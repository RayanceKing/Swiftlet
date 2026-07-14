//===----------------------------------------------------------------------===//
//
//  NetworkOrchestrator.swift
//  Swiftlet — Quad‑Platform Unified Tunnel IPC Manager
//
//  The central application‑layer controller that manages the system
//  Network Extension tunnel lifecycle across iOS 17, macOS 14,
//  tvOS 17+, and visionOS 2 — uniformly, with zero platform branches.
//
//  Architecture
//  ------------
//  ```
//  ┌──────────────────────────────────────────────────────────────────┐
//  │                     NetworkOrchestrator                           │
//  │                     (@unchecked Sendable)                         │
//  │                                                                   │
//  │  ┌─────────────────────────────────────────────────────────────┐ │
//  │  │  NETunnelProviderManager (per‑platform system API)            │ │
//  │  │  · loadAllFromPreferences                                    │ │
//  │  │  · saveToPreferences                                         │ │
//  │  │  · connection.startVPNTunnel() / stopVPNTunnel()             │ │
//  │  └─────────────────────────────────────────────────────────────┘ │
//  │                                                                   │
//  │  ┌─────────────────────────────────────────────────────────────┐ │
//  │  │  App Group UserDefaults (IPC channel to tunnel extension)     │ │
//  │  │  suiteName: "group.com.rayanceking.swiftlet"                 │ │
//  │  │  · tunnel.config  → raw Surge/Loon profile text              │ │
//  │  │  · tunnel.pcap    → PCAP capture enabled flag                │ │
//  │  └─────────────────────────────────────────────────────────────┘ │
//  │                                                                   │
//  │  ┌─────────────────────────────────────────────────────────────┐ │
//  │  │  SessionDiagnosticsTracker.shared (in‑process actor)          │ │
//  │  │  · activeSnapshots   · totalSessionsCreated                  │ │
//  │  │  · PCAPPacketDumper (circular buffer for container‑side PCAP) │ │
//  │  └─────────────────────────────────────────────────────────────┘ │
//  └──────────────────────────────────────────────────────────────────┘
//  ```
//
//  Platform Uniformity
//  -------------------
//  All four platforms (iOS, macOS, tvOS, visionOS) use the identical
//  NETunnelProviderManager pipeline.  There are zero `#if os(...)`
//  branches — the system VPN APIs are uniformly available on all
//  modern Apple OS families.
//
//  Thread Safety
//  -------------
//  Marked `@unchecked Sendable` following the established pattern.
//  Mutable state (`_state`, `_diagnostics`) protected by `NSLock`.
//  `NETunnelProviderManager` API calls are `@MainActor` in newer SDKs;
//  we bridge with `await MainActor.run` where needed.
//
//===----------------------------------------------------------------------===//

import Foundation
import NetworkExtension
import SwiftletCore
import SwiftletCoreExpand

// MARK: - IPC Configuration

/// Keys and identifiers for the App Group IPC channel and the
/// Network Extension tunnel configuration.
enum TunnelIPCConfig {
    /// The shared App Group container suite name.
    /// Must match the entitlement in both the container app and
    /// the tunnel extension.
    static let appGroupSuite = "group.com.rayanceking.swiftlet"

    /// Key for the raw Surge/Loon configuration text in UserDefaults.
    static let configKey = "tunnel.config"

    /// Key for the PCAP capture enabled flag.
    static let pcapKey = "tunnel.pcap"

    /// The Network Extension tunnel provider bundle identifier.
    /// Must match the `NSExtensionPrincipalClass` bundle ID in the
    /// tunnel target's Info.plist.
    static let tunnelBundleID = "com.rayanceking.swiftlet.tunnel"

    /// The NETunnelProviderManager protocol configuration description.
    static let tunnelDescription = "Swiftlet Proxy Tunnel"
}

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

    public var isTransitioning: Bool {
        switch self {
        case .booting, .tearingDown: return true
        default:                     return false
        }
    }

    public var canBoot: Bool {
        switch self {
        case .idle, .stopped, .failed: return true
        default:                        return false
        }
    }
}

// MARK: - Orchestrator Error

public enum OrchestratorError: Error, Sendable, Equatable, LocalizedError {
    case engineAlreadyRunning
    case engineNotRunning
    case bootFailed(reason: String)
    case teardownFailed(reason: String)
    case invalidConfiguration(String)
    case tunnelManagerUnavailable
    case pcapNotAvailable

    public var errorDescription: String? {
        switch self {
        case .engineAlreadyRunning:
            return "The proxy tunnel is already running."
        case .engineNotRunning:
            return "The proxy tunnel is not running."
        case .bootFailed(let reason):
            return "Tunnel boot failed: \(reason)"
        case .teardownFailed(let reason):
            return "Tunnel teardown failed: \(reason)"
        case .invalidConfiguration(let reason):
            return "Invalid configuration: \(reason)"
        case .tunnelManagerUnavailable:
            return "NETunnelProviderManager is not available on this device."
        case .pcapNotAvailable:
            return "PCAP packet dump is not available."
        }
    }
}

// MARK: - Orchestrator Diagnostics Snapshot

public struct OrchestratorDiagnostics: Sendable, Equatable {
    public let state: OrchestratorState
    public let coreEngineState: String
    public let cachedHostCerts: Int
    public let scriptCount: Int
    public let validScriptCount: Int
    public let poolIdleChannels: Int
    public let cronEntryCount: Int
    public let networkMonitorActive: Bool
    public let networkChangedScriptCount: Int
    public let mitmDomainCount: Int
    public let localSocksPort: UInt16
    public let localHttpPort: UInt16
    public let activeSessionCount: Int
    public let totalSessionsCreated: UInt64
    public let pcapPacketsCaptured: UInt64
    public let pcapBufferedCount: Int
    public let capturedAt: Date

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

/// The central application‑layer facade for the Swiftlet proxy
/// ecosystem.  Manages the system Network Extension tunnel lifecycle
/// uniformly across iOS, macOS, tvOS, and visionOS.
///
/// ## Usage
/// ```swift
/// let orch = NetworkOrchestrator.shared
/// try await orch.bootEngine(withConfigRawText: configString)
/// // … system VPN tunnel is now active …
/// try await orch.teardownEngine()
/// ```
public final class NetworkOrchestrator: @unchecked Sendable {

    // MARK: - Shared Instance

    public static let shared = NetworkOrchestrator()

    // MARK: - Owned Components

    /// The global session diagnostics tracker.
    private let diagnosticsTracker = SessionDiagnosticsTracker.shared

    /// In‑memory PCAP packet dumper for the container app side.
    private let pcapDumper = PCAPPacketDumper(maxPackets: 4096)

    // MARK: - Tunnel Manager Reference

    /// The active `NETunnelProviderManager` instance.
    /// Populated during `bootEngine`; nil when idle or stopped.
    private var tunnelManager: NETunnelProviderManager?

    // MARK: - State

    private var _state: OrchestratorState = .idle
    private let stateLock = NSLock()

    public var currentState: OrchestratorState {
        stateLock.withLock { _state }
    }

    private func setState(_ newState: OrchestratorState) {
        stateLock.withLock { _state = newState }
    }

    // MARK: - Diagnostic Caching

    private var _diagnostics: OrchestratorDiagnostics = .empty
    private let diagnosticsLock = NSLock()

    public var currentDiagnostics: OrchestratorDiagnostics {
        diagnosticsLock.withLock { _diagnostics }
    }

    // MARK: - Initialisation

    private init() {}

    // MARK: - Boot Engine (Unified Tunnel Ignition)

    /// Validates the configuration, writes it to the App Group sandbox,
    /// registers (or updates) the system `NETunnelProviderManager`,
    /// saves preferences, and commands the OS kernel to launch the
    /// Network Extension daemon.
    ///
    /// This is the single entry point for all four platforms.
    ///
    /// - Parameter text: Raw Surge/Loon‑style `.conf` configuration text.
    /// - Throws: `OrchestratorError` on validation failure, tunnel
    ///   manager unavailability, or VPN start failure.
    public func bootEngine(withConfigRawText text: String) async throws {
        // ── Pre‑flight ────────────────────────────────────────────
        guard currentState.canBoot else {
            throw OrchestratorError.engineAlreadyRunning
        }

        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw OrchestratorError.invalidConfiguration(
                "Configuration text is empty."
            )
        }

        setState(.booting)

        do {
            // ── 1. Write configuration to App Group UserDefaults ──
            // The tunnel extension process reads this when the system
            // launches it.
            writeConfigToAppGroup(rawText: trimmed)

            // ── 2. Load or create the tunnel manager ──────────────
            let manager = try await resolveTunnelManager()

            // ── 3. Start the VPN tunnel ───────────────────────────
            try await startTunnel(manager: manager)

            // ── 4. Transition to running ──────────────────────────
            setState(.running)

            // ── 5. Capture initial diagnostics ────────────────────
            await refreshDiagnostics()

        } catch let error as OrchestratorError {
            setState(.failed(error))
            throw error

        } catch {
            let orchError = OrchestratorError.bootFailed(
                reason: error.localizedDescription
            )
            setState(.failed(orchError))
            throw orchError
        }
    }

    // MARK: - Teardown Engine (Unified Tunnel Evacuation)

    /// Commands the system to stop the VPN tunnel.  The OS kernel
    /// signals the extension process, which gracefully shuts down
    /// the engine, drains all sessions, and evacuates.
    ///
    /// - Throws: `OrchestratorError` if the tunnel is not running
    ///   or shutdown fails.
    public func teardownEngine() async throws {
        guard currentState == .running else {
            throw OrchestratorError.engineNotRunning
        }

        setState(.tearingDown)

        do {
            // ── Stop the VPN tunnel ───────────────────────────────
            if let manager = tunnelManager {
                manager.connection.stopVPNTunnel()
            }

            // ── Transition to stopped ─────────────────────────────
            setState(.stopped)

            // ── Refresh diagnostics ───────────────────────────────
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

    // MARK: - Tunnel Manager Resolution

    /// Loads existing tunnel configurations from system preferences
    /// and returns the matching `NETunnelProviderManager`, or creates
    /// a new one if none exists.
    private func resolveTunnelManager() async throws -> NETunnelProviderManager {
        // NETunnelProviderManager.loadAllFromPreferences is
        // @MainActor in modern SDKs.
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()

        // ── Find existing manager with matching bundle ID ─────────
        if let existing = managers.first(where: { manager in
            (manager.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerBundleIdentifier == TunnelIPCConfig.tunnelBundleID
        }) {
            logOrchestrator("Reusing existing tunnel manager")
            self.tunnelManager = existing
            return existing
        }

        // ── Create a new manager ──────────────────────────────────
        logOrchestrator("Creating new tunnel manager")
        let manager = NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = TunnelIPCConfig.tunnelBundleID
        proto.serverAddress = "Swiftlet"  // display name in Settings
        manager.protocolConfiguration = proto
        manager.localizedDescription = TunnelIPCConfig.tunnelDescription
        manager.isEnabled = true

        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()

        self.tunnelManager = manager
        return manager
    }

    /// Starts the VPN tunnel and waits for the connection to enter
    /// the `.connected` state (with a timeout).
    private func startTunnel(
        manager: NETunnelProviderManager
    ) async throws {
        guard let session = manager.connection
                as? NETunnelProviderSession else {
            throw OrchestratorError.tunnelManagerUnavailable
        }

        logOrchestrator("Starting VPN tunnel session…")

        // ── Start the tunnel ──────────────────────────────────────
        try session.startTunnel(options: nil)

        // ── Wait for connection to become active ──────────────────
        // The tunnel extension process launches asynchronously.
        // Poll connection status with a 10‑second timeout.
        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline {
            switch session.status {
            case .connected:
                logOrchestrator("Tunnel connected")
                return
            case .invalid, .disconnected:
                throw OrchestratorError.bootFailed(
                    reason: "Tunnel session entered \(session.status) state"
                )
            default:
                try await Task.sleep(nanoseconds: 250_000_000)  // 250ms
            }
        }

        throw OrchestratorError.bootFailed(
            reason: "Tunnel connection timed out (10s)"
        )
    }

    // MARK: - App Group IPC

    /// Writes the raw configuration text and PCAP flag to the shared
    /// App Group `UserDefaults` so the Network Extension process can
    /// ingest them at tunnel startup.
    private func writeConfigToAppGroup(rawText text: String) {
        guard let defaults = UserDefaults(
            suiteName: TunnelIPCConfig.appGroupSuite
        ) else {
            logOrchestrator(
                "WARNING: Cannot access App Group '\(TunnelIPCConfig.appGroupSuite)'. "
                + "Verify entitlements."
            )
            return
        }

        defaults.set(text, forKey: TunnelIPCConfig.configKey)
        defaults.set(pcapDumper.isEnabled, forKey: TunnelIPCConfig.pcapKey)
        defaults.synchronize()  // force immediate write for IPC

        logOrchestrator("Configuration written to App Group for tunnel extension")
    }

    // MARK: - PCAP Export

    public func dumpActiveBuffersToPCAP() -> Data {
        pcapDumper.dumpActiveBuffersToPCAP()
    }

    public var isPCAPEnabled: Bool {
        get { pcapDumper.isEnabled }
        set { pcapDumper.isEnabled = newValue }
    }

    // MARK: - Diagnostics Refresh

    /// Refreshes the cached diagnostics snapshot from the live
    /// `SessionDiagnosticsTracker` actor and any in‑process state.
    @discardableResult
    public func refreshDiagnostics() async -> OrchestratorDiagnostics {
        let activeCount = await diagnosticsTracker.activeCount
        let totalCreated = await diagnosticsTracker.totalSessionsCreated

        let snapshot = OrchestratorDiagnostics(
            state: currentState,
            coreEngineState: "tunnel",  // engine runs in extension process
            cachedHostCerts: 0,
            scriptCount: 0,
            validScriptCount: 0,
            poolIdleChannels: 0,
            cronEntryCount: 0,
            networkMonitorActive: false,
            networkChangedScriptCount: 0,
            mitmDomainCount: 0,
            localSocksPort: 1080,
            localHttpPort: 8080,
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

    public func activeSessions() async -> [SessionSnapshot] {
        await diagnosticsTracker.activeSnapshots
    }

    public func recentClosedSessions(
        count: Int = 100
    ) async -> [SessionSnapshot] {
        await diagnosticsTracker.recentClosedSnapshots(count: count)
    }

    // MARK: - Convenience

    /// Whether the VPN tunnel is currently connected.
    public var isTunnelConnected: Bool {
        tunnelManager?.connection.status == .connected
    }

    /// The current VPN connection status string for UI display.
    public var connectionStatusDescription: String {
        guard let status = tunnelManager?.connection.status else {
            return "No tunnel manager"
        }
        switch status {
        case .invalid:     return "Invalid"
        case .disconnected: return "Disconnected"
        case .connecting:  return "Connecting…"
        case .connected:   return "Connected"
        case .reasserting: return "Reasserting…"
        case .disconnecting: return "Disconnecting…"
        @unknown default:  return "Unknown"
        }
    }

    // MARK: - Logging

    private func logOrchestrator(_ message: String) {
        #if DEBUG
        print("[NetworkOrchestrator] \(message)")
        #endif
    }

    /// A one‑line summary for UI display.
    public var statusSummary: String {
        let diag = currentDiagnostics
        switch diag.state {
        case .idle:
            return "Engine idle — ready to boot"
        case .booting:
            return "Initialising VPN tunnel…"
        case .running:
            return "Running · \(connectionStatusDescription) · \(diag.activeSessionCount) sessions"
        case .tearingDown:
            return "Stopping VPN tunnel…"
        case .stopped:
            return "Tunnel stopped"
        case .failed(let error):
            return "Error: \(error.localizedDescription)"
        }
    }
}
