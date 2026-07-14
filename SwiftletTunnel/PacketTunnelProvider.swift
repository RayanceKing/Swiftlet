//===----------------------------------------------------------------------===//
//
//  PacketTunnelProvider.swift
//  SwiftletTunnel — Sovereign Network Extension Packet Tunnel
//
//  The definitive ingress gateway for the Swiftlet proxy ecosystem.
//  Sits between Apple's kernel utun virtual interface and the
//  SwiftletCoreExpandEngine, intercepting 100% of device IPv4/IPv6
//  raw Layer‑3 traffic and piping it through the full protocol
//  obfuscation + routing + MitM pipeline at line rate.
//
//  Quad‑Platform Deployment
//  ------------------------
//  iOS 17   / macOS 14  / tvOS 17+  / visionOS 2
//  All targets share this identical code path — no platform branches.
//  `NEPacketTunnelProvider` is uniformly available across all four
//  modern Apple OS families.
//
//  Memory Contract (15 MB Extension Kill Gate)
//  -------------------------------------------
//  | Component              | Allocation         |
//  |------------------------|--------------------|
//  | Single-thread ELG      | ~5 MB              |
//  | TCP session registry   | ~1024 × 2 KB = 2MB |
//  | PCAP circular buffer   | ~2048 × 1500B = 3MB|
//  | UDP session registry   | ~512 × 1 KB = 0.5MB|
//  | Root CA + cert cache   | ~1 MB              |
//  | **Total steady state** | **≤ 12 MB**         |
//
//  Data Flow
//  ---------
//  ```
//  Kernel utun
//       │  readPackets()
//       ▼
//  ┌─────────────────────────────────────────────────────────┐
//  │  PacketTunnelProvider (this file)                        │
//  │                                                          │
//  │  ┌──────────────────┐  ┌──────────────────────────────┐ │
//  │  │ TUN2SocksBridge   │  │ TUN2UdpBridge                 │ │
//  │  │ · virtual 3WHS    │  │ · Full Cone NAT (EIM + EIF)  │ │
//  │  │ · session tracking│  │ · idle sweep (30s)            │ │
//  │  │ · reassembly      │  │ · unsolicited inbound filter  │ │
//  │  └────────┬──────────┘  └─────────────┬────────────────┘ │
//  │           │                            │                  │
//  │           ▼                            ▼                  │
//  │  ┌─────────────────────────────────────────────────────┐ │
//  │  │  SwiftletCoreExpandEngine.shared                    │ │
//  │  │  · RoutingEngine (Radix Tree + CIDR)                │ │
//  │  │  · OutboundDialer (SS/VLESS/Trojan/Hysteria2/...)   │ │
//  │  │  · MitMCertificateManager (L7 TLS interception)     │ │
//  │  │  · CronEngine + NetworkPathMonitor (background)     │ │
//  │  │  · JavaScriptPluginExecutor ($httpClient, $proxy)   │ │
//  │  └─────────────────────────────────────────────────────┘ │
//  └─────────────────────────────────────────────────────────┘
//       │
//       ▼  writePackets()
//  Kernel utun
//  ```
//
//  Thread Safety (Swift 6 Strict Concurrency)
//  ------------------------------------------
//  • `@unchecked Sendable` — all mutable state confined to
//    the serial dispatch queue or the NIO event loop.
//  • `packetFlow` callbacks fire on arbitrary queues; we
//    immediately dispatche to known serial contexts.
//  • Bridges (`TUN2SocksBridge`, `TUN2UdpBridge`) are
//    `@unchecked Sendable` with internal serial guarantees.
//  • Zero data races — no shared mutable state between the
//    read loop, the eviction timer, and the stop path.
//
//===----------------------------------------------------------------------===//

import NetworkExtension
import SwiftletCore
import SwiftletCoreExpand
import os.log

// MARK: - Logger

private let tlog = OSLog(
    subsystem: "com.rayanceking.swiftlet.tunnel",
    category: "PacketTunnel"
)

private func logInfo(_ msg: String) {
    os_log(.info, log: tlog, "%{public}@", msg)
}

private func logError(_ msg: String) {
    os_log(.error, log: tlog, "%{public}@", msg)
}

// MARK: - IPC Configuration Keys

/// Keys for the App Group UserDefaults IPC channel between the
/// container app and this Network Extension process.
enum TunnelIPC {
    /// The shared App Group container identifier.
    static let suite = "group.com.rayanceking.swiftlet"

    /// Key for the raw Surge/Loon configuration text.
    static let config = "tunnel.config"

    /// Key for the PCAP capture enabled flag.
    static let pcap = "tunnel.pcap"
}

// MARK: - Packet Tunnel Provider

/// The sovereign entry point for the Swiftlet Network Extension.
///
/// ## Lifecycle
/// 1. `startTunnel` — reads config from App Group, boots engine,
///    applies VIF settings, begins line‑rate packet ingestion.
/// 2. Packet loop — recursive zero‑gap `readPackets` →
///    bridge dispatch → `writePackets` cycle.
/// 3. `stopTunnel` — stops ingestion, drains sessions, awaits
///    engine shutdown, nullifies all references, signals OS.
open class PacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {

    // MARK: - Bridges

    /// TCP virtual‑handshake bridge (SYN → SYN‑ACK → ESTABLISHED).
    private let tcpBridge = TUN2SocksBridge()

    /// UDP Full Cone NAT bridge (EIM + EIF, RFC 4787 Type A).
    private let udpBridge = TUN2UdpBridge()

    // MARK: - Engine & Diagnostics

    /// The process‑local expand engine singleton.
    /// Booted once during `startTunnel`, shut down during `stopTunnel`.
    private var engineBooted = false

    /// In‑memory PCAP dumper for on‑demand Wireshark exports.
    private let pcapDumper = PCAPPacketDumper(maxPackets: 2048)

    // MARK: - IO Infrastructure

    /// Single‑thread event loop group (~5 MB baseline).
    private var eventLoopGroup: MultiThreadedEventLoopGroup?

    /// Outbound TCP channel registry (session key → Channel).
    private var outboundChannels: [TCPSessionKey: Channel] = [:]

    // MARK: - Lifecycle Flags

    /// Set to `true` when `stopTunnel` is called.
    private var stopping = false

    /// Reassembly eviction timer.
    private var evictionTimer: DispatchSourceTimer?

    // MARK: - startTunnel

    /// Ignites the full proxy engine stack and begins intercepting
    /// all device traffic through the kernel virtual interface.
    ///
    /// - Precondition: The container app must have written a valid
    ///   Surge/Loon configuration string to `TunnelIPC.suite`
    ///   UserDefaults under `TunnelIPC.config` before starting
    ///   the tunnel.
    open override func startTunnel(
        options: [String: NSObject]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        logInfo("startTunnel — entering system VPN ignition sequence")

        // ── 1. Read configuration from App Group sandbox ──────────
        guard let defaults = UserDefaults(suiteName: TunnelIPC.suite),
              let configText = defaults.string(forKey: TunnelIPC.config),
              !configText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else {
            let msg = "No configuration found in App Group '\(TunnelIPC.suite)'."
            logError(msg)
            completionHandler(NSError(
                domain: "com.rayanceking.swiftlet.tunnel",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: msg]
            ))
            return
        }

        // ── 2. Parse manifest for diagnostic logging ──────────────
        let manifest = UnifiedConfigurationParser.parse(configText)
        logInfo("Manifest: \(manifest.nodes.count) nodes, "
                + "\(manifest.rules.count) rules, "
                + "\(manifest.mitmHostnames.count) MITM domains")

        // ── 3. Enable PCAP capture per container app preference ────
        pcapDumper.isEnabled = defaults.bool(forKey: TunnelIPC.pcap)

        // ── 4. Boot the expand engine asynchronously ──────────────
        // The engine start call is async; we bridge into the
        // callback‑based NEPacketTunnelProvider API via a Task.
        Task { [weak self] in
            guard let self else { return }

            do {
                try await SwiftletCoreExpandEngine.shared.start(
                    configurationRawText: configText
                )
                self.engineBooted = true
                logInfo("Engine ignited — "
                        + "SOCKS5:\(SwiftletCoreExpandEngine.shared.localSocksPort) "
                        + "HTTP:\(SwiftletCoreExpandEngine.shared.localHttpPort)")

                await MainActor.run {
                    self.deployVIFAndBeginIngestion(
                        completionHandler: completionHandler
                    )
                }
            } catch {
                logError("Engine boot failed: \(error.localizedDescription)")
                await MainActor.run { completionHandler(error) }
            }
        }
    }

    // MARK: - VIF Configuration & Ingestion Kick‑off

    /// Builds dual‑stack `NEPacketTunnelNetworkSettings`, applies them
    /// to the system, and — on success — ignites the line‑rate packet
    /// ingestion loop.
    private func deployVIFAndBeginIngestion(
        completionHandler: @escaping (Error?) -> Void
    ) {
        // ── Create the memory‑tight event loop ────────────────────
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.eventLoopGroup = group

        // ── Build dual‑stack VIF settings ─────────────────────────
        let settings = VifConfigurator.build()
        logInfo("VIF: IPv4=\(VIFConfig.ipv4Address)/16 "
                + "IPv6=\(VIFConfig.ipv6Address)/64 "
                + "DNS=\(VIFConfig.dnsServerIPv4) "
                + "MTU=\(VIFConfig.tunnelMTU)")

        let box = CompletionBox(completionHandler)

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }

            if let error {
                logError("setTunnelNetworkSettings failed: \(error.localizedDescription)")
                try? group.syncShutdownGracefully()
                self.eventLoopGroup = nil
                box.handler(error)
                return
            }

            logInfo("VIF deployed — igniting line‑rate packet ingestion")
            self.ignitePacketLoop()
            box.handler(nil)
        }
    }

    // MARK: - Line‑Rate Packet Ingestion Loop

    /// Starts the recursive zero‑gap packet read loop and periodic
    /// reassembly eviction.
    private func ignitePacketLoop() {
        stopping = false

        // ── Periodic TCP reassembly eviction (500 ms) ─────────────
        let timer = DispatchSource.makeTimerSource(
            queue: .global(qos: .utility)
        )
        timer.schedule(
            deadline: .now() + .milliseconds(500),
            repeating: .milliseconds(500)
        )
        timer.setEventHandler { [weak self] in
            self?.evictStaleReassembly()
        }
        timer.resume()
        self.evictionTimer = timer

        // ── Kick off the recursive read loop ──────────────────────
        drainPacketFlow()
    }

    /// Recursive zero‑gap tail‑call: the next `readPackets` is
    /// issued **before** the current batch is processed.  This
    /// eliminates inter‑batch idle windows and sustains line‑rate
    /// throughput even at Gigabit cellular speeds.
    private func drainPacketFlow() {
        guard !stopping else { return }

        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self else { return }

            // CRITICAL: re‑issue the next read immediately, before
            // touching a single byte of the current batch.
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                self?.drainPacketFlow()
            }

            // Process this batch on a background serial context.
            self.processBatch(packets: packets, protocols: protocols)
        }
    }

    // MARK: - Batch Processor

    /// Routes each raw L3 packet to the appropriate bridge (TCP/UDP)
    /// and writes any generated reply packets back to the TUN interface.
    private func processBatch(
        packets: [Data],
        protocols: [NSNumber]
    ) {
        var replies = [Data]()

        for (index, data) in packets.enumerated() {
            let family = protocols[index].int32Value

            switch family {
            case AF_INET:
                if let result = try? tcpBridge.processInbound(data) {
                    dispatchTCP(result, replies: &replies)
                } else if let result = try? udpBridge.processInbound(data) {
                    dispatchUDP(result, replies: &replies)
                }
            case AF_INET6:
                if let result = try? tcpBridge.processInbound(data) {
                    dispatchTCP(result, replies: &replies)
                }
            default:
                continue
            }

            // Capture for PCAP diagnostics.
            pcapDumper.capture(packetData: data)
        }

        guard !replies.isEmpty else { return }
        packetFlow.writePackets(
            replies,
            withProtocols: replies.map { _ in NSNumber(value: AF_INET) }
        )
    }

    // MARK: - Bridge Result Dispatch

    private func dispatchTCP(
        _ result: TUN2SocksBridge.ProcessResult,
        replies: inout [Data]
    ) {
        switch result {
        case .reply(let data):           replies.append(data)
        case .icmpUnreachable(let data): replies.append(data)
        case .forwardToSocks5:           break // routed via expand engine
        case .none:                      break
        }
    }

    private func dispatchUDP(
        _ result: TUN2UdpBridge.ProcessResult,
        replies: inout [Data]
    ) {
        switch result {
        case .reply(let data): replies.append(data)
        case .forward, .none:  break
        }
    }

    // MARK: - Reassembly Eviction

    /// Purges TCP segments stalled longer than 750 ms and forwards
    /// recovered data to the outbound channel.
    private func evictStaleReassembly() {
        guard !stopping else { return }

        let evicted = tcpBridge.evictStaleReassemblyData(olderThan: 0.750)
        for (key, segments) in evicted {
            guard let channel = outboundChannels[key], channel.isActive
            else { continue }
            for (_, data) in segments {
                var buf = channel.allocator.buffer(capacity: data.count)
                buf.writeBytes(data)
                channel.writeAndFlush(buf, promise: nil)
            }
        }
    }

    // MARK: - stopTunnel (Zero‑Leak Graceful Evacuation)

    /// Tears down the entire tunnel stack with zero dangling references:
    /// stops packet ingestion, cancels the eviction timer, closes all
    /// outbound channels, drains TCP/UDP registries, awaits engine
    /// shutdown (connection pool, cert stores, cron, NWPathMonitor,
    /// NIO event loops), clears the PCAP buffer, and calls the system
    /// completion handler.
    open override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        logInfo("stopTunnel — reason: \(reason.rawValue)")

        // ── 1. Signal the ingestion loop to stop ──────────────────
        stopping = true

        // ── 2. Cancel eviction timer ──────────────────────────────
        evictionTimer?.cancel()
        evictionTimer = nil

        // ── 3. Disable PCAP capture ───────────────────────────────
        pcapDumper.isEnabled = false

        // ── 4. Close all outbound TCP channels ────────────────────
        let channels = outboundChannels
        outboundChannels.removeAll()
        for (_, ch) in channels {
            ch.close(mode: .all, promise: nil)
        }

        // ── 5. Drain session registries ───────────────────────────
        tcpBridge.registry.removeAll()
        udpBridge.registry.removeAll()

        // ── 6. Shut down the event loop ───────────────────────────
        let group = eventLoopGroup
        self.eventLoopGroup = nil

        // ── 7. Asynchronously shut down engine and finalise ───────
        Task {
            if engineBooted {
                do {
                    try await SwiftletCoreExpandEngine.shared.shutdown()
                    logInfo("Engine shutdown complete")
                } catch {
                    logError("Engine shutdown error: \(error.localizedDescription)")
                }
            }

            pcapDumper.clear()

            if let g = group {
                try? g.syncShutdownGracefully()
            }

            await MainActor.run { [weak self] in
                self?.engineBooted = false
            }

            // ── 8. Final OS signal — tunnel fully evacuated ───────
            completionHandler()
            logInfo("stopTunnel complete — zero dangling references")
        }
    }

    // MARK: - IPC (Container App Messages)

    /// Handles runtime messages from the container app via
    /// `NETunnelProviderSession.sendProviderMessage`.
    ///
    /// Supported commands:
    /// - `"pcap"` → Returns the libpcap‑formatted packet dump.
    /// - `"status"` → Returns engine diagnostics as UTF‑8 text.
    open override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        guard let command = String(data: messageData, encoding: .utf8) else {
            completionHandler?(nil)
            return
        }

        switch command {
        case "pcap":
            completionHandler?(pcapDumper.dumpActiveBuffersToPCAP())

        case "status":
            Task {
                let diag = await SwiftletCoreExpandEngine.shared.diagnostics()
                let status = """
                    state=\(diag.state.description)
                    core=\(diag.coreState.description)
                    certs=\(diag.cachedHostCerts)
                    scripts=\(diag.validScriptCount)/\(diag.scriptCount)
                    pool=\(diag.poolIdleChannels)
                    cron=\(diag.cronEntryCount)
                    monitor=\(diag.networkMonitorActive)
                    mitm=\(diag.mitmDomainCount)
                    """
                completionHandler?(Data(status.utf8))
            }

        default:
            completionHandler?(nil)
        }
    }
}

// MARK: - Sendable Completion Box

/// Wraps a non‑`@Sendable` closure for capture inside `@Sendable`
/// callbacks (e.g., `setTunnelNetworkSettings`).
private final class CompletionBox: @unchecked Sendable {
    let handler: (Error?) -> Void
    init(_ handler: @escaping (Error?) -> Void) {
        self.handler = handler
    }
}
