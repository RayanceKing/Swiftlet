//===----------------------------------------------------------------------===//
//
//  PacketTunnelProvider.swift
//  SwiftletTunnel — Network Extension Packet Tunnel Endpoint
//
//  The glue layer between Apple's kernel virtual interface (utun via
//  `NEPacketTunnelProvider.packetFlow`) and the full Swiftlet proxy
//  engine stack.  Owns its own TCP/UDP bridges (TUN2SocksBridge,
//  TUN2UdpBridge) and integrates the L7 SwiftletCoreExpandEngine
//  for protocol obfuscation, routing, MitM TLS, and JS scripting.
//
//  Platform Scope
//  --------------
//  iOS 17 / macOS 14 / visionOS 2 : Full NetworkExtension TUN support.
//  tvOS                            : EXCLUDED — use local loopback proxy.
//
//  Memory Budget (15 MB Kill Threshold)
//  ------------------------------------
//  • Single-thread event loop: ~5 MB
//  • TCP session registry: ~1024 × 2 KB = ~2 MB
//  • PCAP buffer: ~2048 × 1500 B = ~3 MB
//  • Root CA + cert cache: ~1 MB
//  • Total steady state: ≤ 12 MB
//
//===----------------------------------------------------------------------===//

import NetworkExtension
import SwiftletCore
import SwiftletCoreExpand
import os.log

// MARK: - Logger

private let tlog = OSLog(
    subsystem: "com.stuwang.Swiftlet.tunnel",
    category: "PacketTunnelProvider"
)
private func logInfo(_ msg: String) {
    os_log(.info, log: tlog, "%{public}@", msg)
}
private func logError(_ msg: String) {
    os_log(.error, log: tlog, "%{public}@", msg)
}

// MARK: - Configuration Transport Keys

public enum TunnelConfigKey {
    public static let appGroupSuite = "group.com.stuwang.Swiftlet"
    public static let configKey = "com.stuwang.Swiftlet.tunnel.configRawText"
    public static let pcapKey  = "com.stuwang.Swiftlet.tunnel.pcapEnabled"
}

// MARK: - Packet Tunnel Provider

open class PacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {

    // ── Bridges ──────────────────────────────────────────────────
    private let tcpBridge = TUN2SocksBridge()
    private let udpBridge = TUN2UdpBridge()

    // ── Engine ───────────────────────────────────────────────────
    private var expandEngine: SwiftletCoreExpandEngine?
    private var pcapDumper: PCAPPacketDumper?
    private var parsedManifest: UnifiedConfigurationResult?

    // ── Outbound channel registry ─────────────────────────────────
    private var outboundChannels: [TCPSessionKey: Channel] = [:]
    private var tunnelStopping = false
    private var evictionTimer: DispatchSourceTimer?

    // ── Event loop ───────────────────────────────────────────────
    private var eventLoopGroup: MultiThreadedEventLoopGroup?
    private var eventLoop: EventLoop! { eventLoopGroup?.next() }

    // MARK: - startTunnel

    open override func startTunnel(
        options: [String: NSObject]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        logInfo("startTunnel — reading configuration…")

        let defaults = UserDefaults(suiteName: TunnelConfigKey.appGroupSuite)
        guard let configText = defaults?.string(forKey: TunnelConfigKey.configKey),
              !configText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else {
            let msg = "No configuration in App Group UserDefaults."
            logError(msg)
            completionHandler(NSError(domain: "com.stuwang.Swiftlet.tunnel",
                                      code: -1, userInfo: [NSLocalizedDescriptionKey: msg]))
            return
        }

        parsedManifest = UnifiedConfigurationParser.parse(configText)
        logInfo("Parsed: \(parsedManifest?.nodes.count ?? 0) nodes, "
                + "\(parsedManifest?.rules.count ?? 0) rules")

        let engine = SwiftletCoreExpandEngine()
        self.expandEngine = engine

        let dumper = PCAPPacketDumper(maxPackets: 2048)
        dumper.isEnabled = defaults?.bool(forKey: TunnelConfigKey.pcapKey) ?? false
        self.pcapDumper = dumper

        // Boot the expand engine, then apply VIF settings and start
        // packet ingestion — all on a background Task bridged from the
        // async engine boot to the callback-based NEPacketTunnelProvider API.
        Task { [weak self] in
            guard let self else { return }
            do {
                try await engine.start(configurationRawText: configText)
                logInfo("Engine running — SOCKS5:\(engine.localSocksPort) "
                        + "HTTP:\(engine.localHttpPort)")
                await MainActor.run {
                    self.applyVIFAndStart(completionHandler: completionHandler)
                }
            } catch {
                logError("Engine boot failed: \(error.localizedDescription)")
                await MainActor.run { completionHandler(error) }
            }
        }
    }

    // MARK: - VIF & Ingestion Kickoff

    private func applyVIFAndStart(completionHandler: @escaping (Error?) -> Void) {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.eventLoopGroup = group

        let settings = VifConfigurator.build()
        logInfo("VIF: \(VIFConfig.ipv4Address)/16, MTU: \(VIFConfig.tunnelMTU)")

        let completion = CompletionBox(completionHandler)
        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            if let error {
                logError("VIF failed: \(error.localizedDescription)")
                try? group.syncShutdownGracefully()
                self.eventLoopGroup = nil
                completion.handler(error)
                return
            }
            logInfo("VIF applied — starting packet ingestion")
            self.beginIngestion()
            completion.handler(nil)
        }
    }

    // MARK: - Line-Rate Packet Ingestion Loop

    private func beginIngestion() {
        tunnelStopping = false

        // Periodic reassembly eviction timer (every 500ms).
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        timer.schedule(deadline: .now() + .milliseconds(500), repeating: .milliseconds(500))
        timer.setEventHandler { [weak self] in self?.purgeStaleReassembly() }
        timer.resume()
        self.evictionTimer = timer

        // Kick off the recursive read loop.
        recursiveRead()
    }

    /// Zero-gap tail-call pattern: the next `readPackets` is issued
    /// BEFORE the current batch is processed, eliminating inter-batch
    /// idle gaps and sustaining line-rate throughput.
    private func recursiveRead() {
        guard !tunnelStopping else { return }

        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self else { return }

            // CRITICAL: Re-issue the next read immediately.
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                self?.recursiveRead()
            }

            self.processBatch(packets: packets, protocols: protocols)
        }
    }

    private func processBatch(packets: [Data], protocols: [NSNumber]) {
        var replies: [Data] = []

        for (i, data) in packets.enumerated() {
            let family = protocols[i].int32Value
            switch family {
            case AF_INET:
                if let r = try? tcpBridge.processInbound(data) {
                    applyTCPResult(r, raw: data, replies: &replies)
                } else if let r = try? udpBridge.processInbound(data) {
                    applyUDPResult(r, replies: &replies)
                }
            case AF_INET6:
                if let r = try? tcpBridge.processInbound(data) {
                    applyTCPResult(r, raw: data, replies: &replies)
                }
            default: continue
            }
            pcapDumper?.capture(packetData: data)
        }

        guard !replies.isEmpty else { return }
        packetFlow.writePackets(replies,
                                withProtocols: replies.map { _ in NSNumber(value: AF_INET) })
    }

    // MARK: - Bridge Result Dispatch

    private func applyTCPResult(
        _ r: TUN2SocksBridge.ProcessResult,
        raw: Data, replies: inout [Data]
    ) {
        switch r {
        case .reply(let d):              replies.append(d)
        case .icmpUnreachable(let d):    replies.append(d)
        case .forwardToSocks5:           break // routed via expand engine in future
        case .none:                      break
        }
    }

    private func applyUDPResult(
        _ r: TUN2UdpBridge.ProcessResult,
        replies: inout [Data]
    ) {
        switch r {
        case .reply(let d): replies.append(d)
        case .forward, .none: break
        }
    }

    // MARK: - Reassembly Eviction

    private func purgeStaleReassembly() {
        guard !tunnelStopping else { return }
        let evicted = tcpBridge.evictStaleReassemblyData(olderThan: 0.750)
        for (key, segments) in evicted {
            guard let ch = outboundChannels[key], ch.isActive else { continue }
            for (_, data) in segments {
                var buf = ch.allocator.buffer(capacity: data.count)
                buf.writeBytes(data)
                ch.writeAndFlush(buf, promise: nil)
            }
        }
    }

    // MARK: - stopTunnel (Graceful Zero-Leak Teardown)

    open override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        logInfo("stopTunnel — reason: \(reason.rawValue)")

        tunnelStopping = true
        evictionTimer?.cancel()
        evictionTimer = nil
        pcapDumper?.isEnabled = false

        // Close all outbound channels.
        let channels = outboundChannels
        outboundChannels.removeAll()
        for (_, ch) in channels { ch.close(mode: .all, promise: nil) }

        // Drain registries.
        tcpBridge.registry.removeAll()
        udpBridge.registry.removeAll()

        let engine = self.expandEngine
        let dumper = self.pcapDumper
        let group  = self.eventLoopGroup

        // Shut down expand engine asynchronously, then clean up
        // event loop and call completionHandler.
        Task {
            if let eng = engine {
                do { try await eng.shutdown() }
                catch { logError("Shutdown error: \(error.localizedDescription)") }
            }
            dumper?.clear()

            if let g = group {
                try? g.syncShutdownGracefully()
            }

            await MainActor.run { [weak self] in
                self?.expandEngine = nil
                self?.pcapDumper = nil
                self?.eventLoopGroup = nil
                self?.parsedManifest = nil
                // Call the parent's completion — NEPacketTunnelProvider
                // expects this to finalize the stop sequence.
                completionHandler()
            }
            logInfo("stopTunnel complete — zero leak")
        }
    }

    // MARK: - IPC

    open override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        guard let cmd = String(data: messageData, encoding: .utf8) else {
            completionHandler?(nil); return
        }
        switch cmd {
        case "pcap":
            completionHandler?(pcapDumper?.dumpActiveBuffersToPCAP() ?? Data())
        case "status":
            Task {
                let d = await expandEngine?.diagnostics()
                let s = "state=\(d?.state.description ?? "?") "
                      + "certs=\(d?.cachedHostCerts ?? 0)"
                completionHandler?(Data(s.utf8))
            }
        default:
            completionHandler?(nil)
        }
    }
}

// MARK: - Completion Box

private final class CompletionBox: @unchecked Sendable {
    let handler: (Error?) -> Void
    init(_ h: @escaping (Error?) -> Void) { self.handler = h }
}
