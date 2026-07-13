//===----------------------------------------------------------------------===//
//
//  NetworkOrchestrator.swift
//  Swiftlet — Quad-Platform Unified Host Orchestrator
//
//  A high-level, concurrency-safe application lifecycle controller that
//  wraps the SwiftletCore (L3/L4) and SwiftletCoreExpand (L7 MitM/JS)
//  engine stacks behind a simplified two-verb API.  Designed for Swift 6
//  strict concurrency checking with zero isolation warnings.
//
//  Architecture
//  ------------
//  ```
//  ┌──────────────────────────────────────────────────────────────────┐
//  │                     NetworkOrchestrator                           │
//  │                     (@unchecked Sendable)                         │
//  │                                                                   │
//  │  ┌─────────────────────────────────────────────────────────────┐ │
//  │  │  SwiftletCoreExpandEngine                                     │ │
//  │  │  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │ │
//  │  │  │ Swiftlet     │  │ MitM Cert    │  │ JS Script          │  │ │
//  │  │  │ Engine       │  │ Manager      │  │ Executor           │  │ │
//  │  │  │ (L3/L4)      │  │ (L7 TLS)     │  │ (L7 Logic)         │  │ │
//  │  │  └─────────────┘  └──────────────┘  └────────────────────┘  │ │
//  │  └─────────────────────────────────────────────────────────────┘ │
//  │                                                                   │
//  │  ┌─────────────────────────────────────────────────────────────┐ │
//  │  │  PCAPPacketDumper  │  SessionDiagnosticsTracker (actor)      │ │
//  │  │  (circular buffer) │  (live metrics)                         │ │
//  │  └─────────────────────────────────────────────────────────────┘ │
//  └──────────────────────────────────────────────────────────────────┘
//  ```
//
//  Platform Guardrails
//  -------------------
//  iOS / macOS / visionOS : Full engine + Network Extension virtual
//                           interface hook (NWPathMonitor-driven).
//  tvOS                    : Local loopback proxy only; container-
//                           constrained, no system-wide VIF.
//
//  Thread Safety
//  -------------
//  Marked `@unchecked Sendable` following the established pattern in
//  `SwiftletEngine` and `SwiftletCoreExpandEngine`.  Mutable state
//  confined to the serial initialisation and shutdown paths.
//
//===----------------------------------------------------------------------===//

import Foundation
import SwiftletCore
import SwiftletCoreExpand

// MARK: - Orchestrator State

/// High-level lifecycle state exposed to the UI layer.
public enum OrchestratorState: Sendable, Equatable, CustomStringConvertible {
    case idle
    case booting
    case running
    case tearingDown
    case stopped
    case failed(OrchestratorError)

    public var description: String {
        switch self {
        case .idle:          return "Idle"
        case .booting:       return "Booting…"
        case .running:       return "Running"
        case .tearingDown:   return "Tearing Down…"
        case .stopped:       return "Stopped"
        case .failed(let e): return "Failed: \(e.localizedDescription)"
        }
    }

    /// Whether the engine is currently processing a transition.
    public var isTransitioning: Bool {
        switch self {
        case .booting, .tearingDown: return true
        default:                     return false
        }
    }

    /// Whether the engine is ready to accept a boot command.
    public var canBoot: Bool {
        switch self {
        case .idle, .stopped, .failed: return true
        default:                        return false
        }
    }
}

// MARK: - Orchestrator Error

/// Errors surfaced by the orchestrator during boot or teardown.
public enum OrchestratorError: Error, Sendable, Equatable, LocalizedError {
    case engineAlreadyRunning
    case engineNotRunning
    case bootFailed(reason: String)
    case teardownFailed(reason: String)
    case invalidConfiguration(String)
    case pcapNotAvailable

    public var errorDescription: String? {
        switch self {
        case .engineAlreadyRunning:
            return "The proxy engine is already running."
        case .engineNotRunning:
            return "The proxy engine is not running."
        case .bootFailed(let reason):
            return "Boot failed: \(reason)"
        case .teardownFailed(let reason):
            return "Teardown failed: \(reason)"
        case .invalidConfiguration(let reason):
            return "Invalid configuration: \(reason)"
        case .pcapNotAvailable:
            return "PCAP packet dump is not available — engine must be running."
        }
    }
}

// MARK: - Orchestrator Diagnostics Snapshot

/// A point-in-time snapshot of engine diagnostics for UI consumption.
/// All fields are value types — safe to pass across isolation domains.
public struct OrchestratorDiagnostics: Sendable, Equatable {
    /// The current orchestrator state.
    public let state: OrchestratorState

    /// The underlying core engine state.
    public let coreEngineState: String

    /// Number of cached host certificates (MitM).
    public let cachedHostCerts: Int

    /// Number of pre‑loaded JavaScript plugins.
    public let scriptCount: Int

    /// Number of valid (parseable) scripts.
    public let validScriptCount: Int

    /// Idle channels in the outbound connection pool.
    public let poolIdleChannels: Int

    /// Number of active cron schedules.
    public let cronEntryCount: Int

    /// Whether the NWPathMonitor is active.
    public let networkMonitorActive: Bool

    /// Number of network‑changed event scripts registered.
    public let networkChangedScriptCount: Int

    /// Number of MitM domains configured.
    public let mitmDomainCount: Int

    /// Local SOCKS5 listen port (0 if not started).
    public let localSocksPort: UInt16

    /// Local HTTP proxy listen port (0 if not started).
    public let localHttpPort: UInt16

    /// Active sessions tracked by the diagnostics subsystem.
    public let activeSessionCount: Int

    /// Total sessions created since boot.
    public let totalSessionsCreated: UInt64

    /// Total PCAP packets captured.
    public let pcapPacketsCaptured: UInt64

    /// PCAP buffer fill level.
    public let pcapBufferedCount: Int

    /// Timestamp of this snapshot.
    public let capturedAt: Date

    /// Default empty snapshot for initial UI state.
    public static let empty = OrchestratorDiagnostics(
        state: .idle, coreEngineState: "idle",
        cachedHostCerts: 0, scriptCount: 0, validScriptCount: 0,
        poolIdleChannels: 0, cronEntryCount: 0,
        networkMonitorActive: false, networkChangedScriptCount: 0,
        mitmDomainCount: 0, localSocksPort: 0, localHttpPort: 0,
        activeSessionCount: 0, totalSessionsCreated: 0,
        pcapPacketsCaptured: 0, pcapBufferedCount: 0,
        capturedAt: Date()
    )
}

// MARK: - Network Orchestrator

/// The central application‑layer facade for the entire Swiftlet proxy
/// ecosystem.  Owns the L3/L4 core engine, the L7 expand engine,
/// a PCAP packet dumper, and bridges real‑time diagnostics to the
/// SwiftUI presentation layer.
///
/// ## Usage
/// ```swift
/// let orch = NetworkOrchestrator.shared
/// try await orch.bootEngine(withConfigRawText: configString)
/// // ... proxy traffic flows ...
/// try await orch.teardownEngine()
/// ```
///
/// ## From UI
/// ```swift
/// @EnvironmentObject var orchestrator: NetworkOrchestrator
/// let diag = orchestrator.currentDiagnostics
/// let pcap = orchestrator.dumpActiveBuffersToPCAP()
/// ```
public final class NetworkOrchestrator: @unchecked Sendable {

    // MARK: - Shared Instance

    /// The global singleton orchestrator.
    ///
    /// Thread‑safe by construction — all mutable state is accessed
    /// through serialised paths within the owned sub‑components.
    public static let shared = NetworkOrchestrator()

    // MARK: - Owned Components

    /// The L7‑capable expand engine (owns the L3/L4 core engine).
    private let expandEngine: SwiftletCoreExpandEngine

    /// In‑memory circular PCAP packet dumper.
    private let pcapDumper: PCAPPacketDumper

    /// The global session diagnostics tracker (actor in SwiftletCore).
    private let diagnosticsTracker: SessionDiagnosticsTracker

    // MARK: - State

    /// The current orchestrator lifecycle state.
    /// Write‑confined to the serial boot/teardown paths; read via
    /// `currentState` for thread‑safe access.
    private var _state: OrchestratorState = .idle

    /// Lock for `_state` access.
    private let stateLock = NSLock()

    /// Thread‑safe read of the current state.
    public var currentState: OrchestratorState {
        stateLock.withLock { _state }
    }

    /// Thread‑safe write of the current state.
    private func setState(_ newState: OrchestratorState) {
        stateLock.withLock { _state = newState }
    }

    // MARK: - Diagnostic Caching

    /// Cached diagnostics snapshot, updated periodically.
    private var _diagnostics: OrchestratorDiagnostics = .empty
    private let diagnosticsLock = NSLock()

    /// The most recently captured diagnostics snapshot.
    public var currentDiagnostics: OrchestratorDiagnostics {
        diagnosticsLock.withLock { _diagnostics }
    }

    // MARK: - Initialisation

    /// Private initialiser — use `NetworkOrchestrator.shared`.
    private init() {
        self.expandEngine = SwiftletCoreExpandEngine()
        self.pcapDumper = PCAPPacketDumper(maxPackets: 4096)
        self.diagnosticsTracker = SessionDiagnosticsTracker.shared
    }

    // MARK: - Boot Engine

    /// Parses a Surge/Loon‑style configuration string and ignites the
    /// entire proxy stack: configuration parsing, node hydration,
    /// routing engine priming, cron schedule registration,
    /// NWPathMonitor activation, MitM domain matrix setup, and
    /// inbound server binding.
    ///
    /// This is the primary "One‑Click Execution" entry point.
    ///
    /// - Parameter text: Raw `.conf` configuration text (Surge/Loon
    ///   dialect).  Must contain at least one valid `[Proxy]` node
    ///   and optionally `[Rule]`, `[MITM]`, `[Script]`, and `[Host]`
    ///   blocks.
    /// - Throws: `OrchestratorError` if the engine is already running,
    ///   the configuration is invalid, or any subsystem fails to start.
    ///
    /// ## Example
    /// ```swift
    /// let config = """
    /// [Proxy]
    /// MySS = ss, example.com, 8388, aes-128-gcm, myPassword
    /// [Rule]
    /// DOMAIN-SUFFIX, google.com, Proxy
    /// FINAL, DIRECT
    /// """
    /// try await NetworkOrchestrator.shared.bootEngine(withConfigRawText: config)
    /// ```
    public func bootEngine(withConfigRawText text: String) async throws {
        // ── Pre‑flight guard ────────────────────────────────────────
        let state = currentState
        guard state.canBoot else {
            throw OrchestratorError.engineAlreadyRunning
        }

        // ── Validate input ──────────────────────────────────────────
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw OrchestratorError.invalidConfiguration(
                "Configuration text is empty."
            )
        }

        setState(.booting)

        do {
            // ── Enable PCAP capture ─────────────────────────────────
            pcapDumper.isEnabled = true

            // ── Ignite the expand engine ────────────────────────────
            // This single call parses the configuration, hydrates
            // nodes, registers cron tasks, hooks NWPathMonitor,
            // maps mitmDomains, and binds inbound servers.
            try await expandEngine.start(configurationRawText: trimmed)

            // ── Transition to running ───────────────────────────────
            setState(.running)

            // ── Capture initial diagnostics ─────────────────────────
            await refreshDiagnostics()

        } catch let error as OrchestratorError {
            setState(.failed(error))
            pcapDumper.isEnabled = false
            throw error

        } catch {
            let orchError = OrchestratorError.bootFailed(
                reason: error.localizedDescription
            )
            setState(.failed(orchError))
            pcapDumper.isEnabled = false
            throw orchError
        }
    }

    // MARK: - Teardown Engine

    /// Gracefully tears down the entire proxy stack: stops cron
    /// schedulers, unregisters NWPathMonitor callbacks, drains the
    /// outbound connection pool, purges decrypted certificate stores,
    /// closes all listening channels, stops NIO event loops, and
    /// nullifies all internal references for a zero‑leak guarantee.
    ///
    /// After teardown the orchestrator returns to `.stopped` state
    /// and can be re‑booted with a new configuration.
    ///
    /// - Throws: `OrchestratorError` if the engine is not running
    ///   or shutdown fails.
    public func teardownEngine() async throws {
        let state = currentState
        guard state == .running else {
            throw OrchestratorError.engineNotRunning
        }

        setState(.tearingDown)

        do {
            // ── Disable PCAP capture ────────────────────────────────
            pcapDumper.isEnabled = false

            // ── Shut down expand engine ─────────────────────────────
            // This drains the connection pool, purges cert stores,
            // stops cron tasks, cancels NWPathMonitor, stops NIO
            // event loops, and nullifies internal references.
            try await expandEngine.shutdown()

            // ── Transition to stopped ───────────────────────────────
            setState(.stopped)

            // ── Final diagnostics snapshot ──────────────────────────
            await refreshDiagnostics()

        } catch let error as OrchestratorError {
            setState(.failed(error))
            throw error

        } catch {
            let orchError = OrchestratorError.teardownFailed(
                reason: error.localizedDescription
            )
            setState(.failed(orchError))
            throw orchError
        }
    }

    // MARK: - PCAP Export

    /// Exports all buffered raw IP packets as a standards‑compliant
    /// libpcap file suitable for Wireshark analysis.
    ///
    /// - Returns: A `Data` blob containing the 24‑byte global header
    ///   followed by 16‑byte per‑packet record headers and packet data.
    ///   Returns an empty `Data` if the PCAP buffer is empty.
    ///
    /// ## Usage from SwiftUI
    /// ```swift
    /// let pcapData = orchestrator.dumpActiveBuffersToPCAP()
    /// // Present a ShareLink or UIActivityViewController with pcapData
    /// ```
    public func dumpActiveBuffersToPCAP() -> Data {
        pcapDumper.dumpActiveBuffersToPCAP()
    }

    /// Captures a raw IP packet into the PCAP circular buffer.
    ///
    /// Typically called by the TUN stack when `isEnabled` is `true`.
    /// No‑op when capture is disabled.
    ///
    /// - Parameter packetData: Raw IP packet bytes (including IP header).
    public func capturePCAPPacket(_ packetData: Data) {
        pcapDumper.capture(packetData: packetData)
    }

    /// Enables or disables PCAP packet capture.
    public var isPCAPEnabled: Bool {
        get { pcapDumper.isEnabled }
        set { pcapDumper.isEnabled = newValue }
    }

    // MARK: - Diagnostics Refresh

    /// Refreshes the cached diagnostics snapshot from the live engine
    /// and session tracker.
    ///
    /// This is safe to call from any concurrency domain.  The
    /// `currentDiagnostics` property will reflect the latest snapshot.
    @discardableResult
    public func refreshDiagnostics() async -> OrchestratorDiagnostics {
        let expandDiag = await expandEngine.diagnostics()

        let activeCount = await diagnosticsTracker.activeCount
        let totalCreated = await diagnosticsTracker.totalSessionsCreated

        let snapshot = OrchestratorDiagnostics(
            state: currentState,
            coreEngineState: expandDiag.coreState.description,
            cachedHostCerts: expandDiag.cachedHostCerts,
            scriptCount: expandDiag.scriptCount,
            validScriptCount: expandDiag.validScriptCount,
            poolIdleChannels: expandDiag.poolIdleChannels,
            cronEntryCount: expandDiag.cronEntryCount,
            networkMonitorActive: expandDiag.networkMonitorActive,
            networkChangedScriptCount: expandDiag.networkChangedScriptCount,
            mitmDomainCount: expandDiag.mitmDomainCount,
            localSocksPort: expandEngine.localSocksPort,
            localHttpPort: expandEngine.localHttpPort,
            activeSessionCount: activeCount,
            totalSessionsCreated: totalCreated,
            pcapPacketsCaptured: pcapDumper.totalCaptured,
            pcapBufferedCount: pcapDumper.bufferedCount,
            capturedAt: Date()
        )

        diagnosticsLock.withLock { _diagnostics = snapshot }
        return snapshot
    }

    // MARK: - Session Metrics

    /// Returns all currently active session snapshots.
    public func activeSessions() async -> [SessionSnapshot] {
        await diagnosticsTracker.activeSnapshots
    }

    /// Returns the most recent closed session snapshots.
    /// - Parameter count: Maximum number of snapshots to return (default 100).
    public func recentClosedSessions(count: Int = 100) async -> [SessionSnapshot] {
        await diagnosticsTracker.recentClosedSnapshots(count: count)
    }

    // MARK: - Convenience

    /// The Root CA PEM string, for installation as a trusted anchor
    /// on the device.  Returns `nil` if the engine has not been booted
    /// or the Root CA has not been generated.
    public func rootCAPEMString() async -> String? {
        await expandEngine.rootCAPEMString()
    }

    /// A one‑line summary of the current engine state for UI display.
    public var statusSummary: String {
        let diag = currentDiagnostics
        switch diag.state {
        case .idle:
            return "Engine idle — ready to boot"
        case .booting:
            return "Initialising proxy stack…"
        case .running:
            return "Running · SOCKS5:\(diag.localSocksPort) HTTP:\(diag.localHttpPort) · \(diag.activeSessionCount) sessions"
        case .tearingDown:
            return "Draining connections…"
        case .stopped:
            return "Engine stopped"
        case .failed(let error):
            return "Error: \(error.localizedDescription)"
        }
    }
}

// MARK: - Sendable Compliance Verification

// `NetworkOrchestrator` is `@unchecked Sendable` because:
//
// 1. `SwiftletCoreExpandEngine` is `@unchecked Sendable` and manages
//    its own internal synchronisation.
// 2. `PCAPPacketDumper` is `@unchecked Sendable` (serial buffer access).
// 3. `SessionDiagnosticsTracker` is an `actor` (built‑in isolation).
// 4. `_state` and `_diagnostics` are protected by `NSLock`.
//
// Under Swift 6 with `SWIFT_APPROACHABLE_CONCURRENCY = YES`, this
// pattern compiles without warnings because the compiler recognises
// the `@unchecked Sendable` annotation as an explicit opt‑out of
// strict sendable checking for this type.
