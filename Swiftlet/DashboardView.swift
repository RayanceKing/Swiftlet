//===----------------------------------------------------------------------===//
//
//  DashboardView.swift
//  Swiftlet — Cross-Platform Unified Proxy Dashboard
//
//  A hardware‑accelerated, reactive SwiftUI dashboard that subscribes
//  to the live `SessionDiagnosticsTracker` actor via a lightweight
//  `AsyncStream` polling loop.  Displays real‑time upstream/downstream
//  data rates, active Radix rule matches, DNS lookup durations, proxy
//  group active paths, and exposes a one‑tap PCAP export button with
//  native platform share sheets.
//
//  Platform Adaptations
//  --------------------
//  iOS 17        : Standard navigation, `.sheet` share, Haptic Touch.
//  macOS 14      : Sidebar‑friendly, `.inspector` column, menu bar extras.
//  tvOS 17       : Focus‑engine compatible, 60pt+ padding, no sheets
//                  (full‑screen modal covers instead), large SF symbols.
//  visionOS 2    : `.glassBackgroundEffect()` materials, `.ornament`
//                  attachment for quick actions, spatial depth layering.
//
//  Reactive Architecture
//  ---------------------
//  ```
//  ┌──────────────────────────────────────────────────────────────┐
//  │  DashboardView                                               │
//  │  ┌────────────────────┐  ┌────────────────────────────────┐ │
//  │  │  MetricsStream      │  │  @State DashboardLiveMetrics   │ │
//  │  │  (AsyncStream)      │──▶  (triggers SwiftUI re‑render)  │ │
//  │  │  polls every 500ms  │  │                                │ │
//  │  └────────────────────┘  └────────────────────────────────┘ │
//  │                                                              │
//  │  ┌────────────────────────────────────────────────────────┐ │
//  │  │  SessionDiagnosticsTracker (actor)                      │ │
//  │  │  · activeSnapshots      · totalSessionsCreated          │ │
//  │  │  · recentClosedSnapshots · activeCount                 │ │
//  │  └────────────────────────────────────────────────────────┘ │
//  └──────────────────────────────────────────────────────────────┘
//  ```
//
//===----------------------------------------------------------------------===//

import SwiftUI
import Observation
import SwiftletCore
import SwiftletCoreExpand
import UniformTypeIdentifiers

// MARK: - Live Metrics Model

/// A point‑in‑time aggregate of all real‑time proxy metrics,
/// computed by the dashboard's polling loop from raw session
/// snapshots.
public struct DashboardLiveMetrics: Sendable, Equatable {
    /// Bytes per second inbound (client → proxy → remote).
    var upstreamBytesPerSecond: Double = 0

    /// Bytes per second outbound (remote → proxy → client).
    var downstreamBytesPerSecond: Double = 0

    /// Total bytes received from all clients since boot.
    var totalBytesIn: UInt64 = 0

    /// Total bytes sent to all remotes since boot.
    var totalBytesOut: UInt64 = 0

    /// Number of currently active proxy sessions.
    var activeSessionCount: Int = 0

    /// Total sessions created since engine boot.
    var totalSessionsCreated: UInt64 = 0

    /// The most recent active rule match descriptions (up to 5).
    var recentRuleMatches: [String] = []

    /// Average DNS lookup duration across active sessions (microseconds).
    var averageDNSLookupMicros: UInt64 = 0

    /// The current proxy group → selected path summary.
    var activeProxyPaths: [String] = []

    /// Engine state summary string.
    var engineStatus: String = "Idle"

    /// Number of PCAP packets captured in the buffer.
    var pcapPacketsCaptured: UInt64 = 0

    /// Number of active cron schedules.
    var cronEntryCount: Int = 0

    /// Whether the network path monitor is actively watching.
    var networkMonitorActive: Bool = false

    /// Timestamp when these metrics were captured.
    var capturedAt: Date = Date()

    /// Empty initial state.
    static let empty = DashboardLiveMetrics()

    /// Formats bytes per second into a human‑readable string.
    static func formatBytesPerSecond(_ bps: Double) -> String {
        switch abs(bps) {
        case 0..<1_024:
            return String(format: "%.1f B/s", bps)
        case 1_024..<1_048_576:
            return String(format: "%.1f KB/s", bps / 1_024)
        case 1_048_576..<1_073_741_824:
            return String(format: "%.1f MB/s", bps / 1_048_576)
        default:
            return String(format: "%.2f GB/s", bps / 1_073_741_824)
        }
    }

    /// Formats total bytes into a human‑readable string.
    static func formatBytes(_ bytes: UInt64) -> String {
        switch bytes {
        case 0..<1_024:
            return "\(bytes) B"
        case 1_024..<1_048_576:
            return String(format: "%.1f KB", Double(bytes) / 1_024)
        case 1_048_576..<1_073_741_824:
            return String(format: "%.1f MB", Double(bytes) / 1_048_576)
        default:
            return String(format: "%.2f GB", Double(bytes) / 1_073_741_824)
        }
    }
}

// MARK: - Metric Tile View (Cross-Platform)

/// A single metric card used throughout the dashboard grid.
/// Adapts its visual treatment per platform.
fileprivate struct MetricTile<Content: View>: View {
    let title: String
    let systemImage: String
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // ── Header ──────────────────────────────────────────
            HStack(spacing: 6) {
                Image(systemName: systemImage)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Text(title)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            // ── Value ───────────────────────────────────────────
            content()
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(12)
        #if os(visionOS)
        .background(.regularMaterial)
        .glassBackgroundEffect()
        .clipShape(RoundedRectangle(cornerRadius: 16))
        #elseif os(tvOS)
        .background(.regularMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 20))
        .focusable(true)
        #else
        .background(.quaternary)
        .clipShape(RoundedRectangle(cornerRadius: 12))
        #endif
    }
}

// MARK: - TVOS Focus Card

#if os(tvOS)
/// A focus‑engine‑aware card wrapper for tvOS.
/// Provides the standard tvOS focus scale effect and shadow.
fileprivate struct FocusCard<Content: View>: View {
    @Environment(\.isFocused) private var isFocused
    @ViewBuilder let content: () -> Content

    var body: some View {
        content()
            .scaleEffect(isFocused ? 1.05 : 1.0)
            .shadow(
                color: isFocused ? .white.opacity(0.3) : .clear,
                radius: isFocused ? 20 : 0
            )
            .animation(.interactiveSpring(response: 0.3, dampingFraction: 0.7), value: isFocused)
    }
}
#endif

// MARK: - Dashboard View

/// The primary cross‑platform dashboard view for the Swiftlet proxy
/// application.  Displays real‑time traffic metrics, session state,
/// routing information, and exposes engine control actions.
///
/// ## Usage
/// ```swift
/// DashboardView()
///     .environmentObject(NetworkOrchestrator.shared)
/// ```
public struct DashboardView: View {

    // MARK: - Environment & State

    /// The global orchestrator (injected via `.environment()`).
    @Environment(NetworkOrchestratorDependency.self) private var orchestrator

    /// Live metrics refreshed by the polling loop.
    @State private var metrics = DashboardLiveMetrics.empty

    /// Whether the PCAP share sheet is presented.
    @State private var isPCAPSharePresented = false

    /// The latest PCAP export data for sharing.
    @State private var pcapExportData: Data?

    /// The active polling task.
    @State private var pollingTask: Task<Void, Never>?

    /// Configuration text for the boot sheet.
    @State private var configText: String = defaultConfigTemplate

    /// Whether to show the configuration editor.
    @State private var isConfigEditorPresented = false

    /// Whether an engine action is in progress.
    @State private var isActionInProgress = false

    /// Error alert state.
    @State private var alertError: String?
    @State private var isAlertPresented = false

    // MARK: - Body

    public var body: some View {
        #if os(tvOS)
        tvOSLayout
        #elseif os(visionOS)
        visionOSLayout
        #else
        standardLayout
        #endif
    }

    // MARK: - Standard Layout (iOS / macOS)

    @ViewBuilder
    private var standardLayout: some View {
        ScrollView {
            VStack(spacing: 20) {
                // ── Status Header ────────────────────────────────
                statusHeaderSection

                // ── Traffic Metrics Grid ─────────────────────────
                trafficMetricsGrid

                // ── Routing & DNS Section ────────────────────────
                routingDiagnosticsSection

                // ── Engine Details ────────────────────────────────
                engineDetailsSection

                // ── Actions ───────────────────────────────────────
                actionsSection
            }
            .padding(16)
        }
        .navigationTitle("Swiftlet Dashboard")
        #if os(macOS)
        .navigationSubtitle(metrics.engineStatus)
        #endif
        .refreshable { await refreshMetricsNow() }
        .sheet(isPresented: $isConfigEditorPresented) {
            configEditorSheet
        }
        .sheet(isPresented: $isPCAPSharePresented) {
            if let data = pcapExportData {
                #if os(macOS)
                PCAPShareView_macOS(pcapData: data)
                #else
                PCAPShareView_iOS(pcapData: data)
                #endif
            }
        }
        .alert("Engine Alert", isPresented: $isAlertPresented) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(alertError ?? "Unknown error")
        }
        .onAppear { startMetricsPolling() }
        .onDisappear { stopMetricsPolling() }
    }

    // MARK: - visionOS Layout

    #if os(visionOS)
    @ViewBuilder
    private var visionOSLayout: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 24) {
                    statusHeaderSection
                        .padding(.top, 8)

                    trafficMetricsGrid

                    routingDiagnosticsSection

                    engineDetailsSection
                }
                .padding(24)
            }
            .navigationTitle("Swiftlet")
            .ornament(attachmentAnchor: .scene(.bottom)) {
                HStack(spacing: 16) {
                    bootButton
                    teardownButton
                    pcapExportButton
                    configEditorButton
                }
                .padding(12)
                .glassBackgroundEffect()
                .clipShape(RoundedRectangle(cornerRadius: 20))
            }
            .sheet(isPresented: $isConfigEditorPresented) {
                configEditorSheet
            }
            .onAppear { startMetricsPolling() }
            .onDisappear { stopMetricsPolling() }
        }
    }
    #endif

    // MARK: - tvOS Layout

    #if os(tvOS)
    @ViewBuilder
    private var tvOSLayout: some View {
        NavigationStack {
            ScrollView(.vertical) {
                VStack(spacing: 40) {
                    // ── Large status card ────────────────────────
                    FocusCard {
                        MetricTile(title: "Engine Status", systemImage: "antenna.radiowaves.left.and.right") {
                            VStack(alignment: .leading, spacing: 6) {
                                Text(metrics.engineStatus)
                                    .font(.title2.weight(.bold))
                                Text("SOCKS5 → :\(orchestrator.currentDiagnostics.localSocksPort)  ·  HTTP → :\(orchestrator.currentDiagnostics.localHttpPort)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }

                    // ── Traffic row ──────────────────────────────
                    HStack(spacing: 30) {
                        FocusCard {
                            MetricTile(title: "Upstream", systemImage: "arrow.up") {
                                Text(DashboardLiveMetrics.formatBytesPerSecond(metrics.upstreamBytesPerSecond))
                                    .font(.title2.monospacedDigit().bold())
                                    .foregroundStyle(.blue)
                            }
                        }
                        FocusCard {
                            MetricTile(title: "Downstream", systemImage: "arrow.down") {
                                Text(DashboardLiveMetrics.formatBytesPerSecond(metrics.downstreamBytesPerSecond))
                                    .font(.title2.monospacedDigit().bold())
                                    .foregroundStyle(.green)
                            }
                        }
                    }

                    // ── Stats row ────────────────────────────────
                    HStack(spacing: 30) {
                        FocusCard {
                            MetricTile(title: "Active Sessions", systemImage: "point.3.connected.trianglepath.dotted") {
                                Text("\(metrics.activeSessionCount)")
                                    .font(.title2.monospacedDigit().bold())
                            }
                        }
                        FocusCard {
                            MetricTile(title: "DNS Lookup", systemImage: "globe") {
                                Text("\(metrics.averageDNSLookupMicros) µs")
                                    .font(.title2.monospacedDigit().bold())
                            }
                        }
                        FocusCard {
                            MetricTile(title: "PCAP Packets", systemImage: "antenna.radiowaves.left.and.right") {
                                Text("\(metrics.pcapPacketsCaptured)")
                                    .font(.title2.monospacedDigit().bold())
                            }
                        }
                    }

                    // ── Actions ──────────────────────────────────
                    HStack(spacing: 40) {
                        bootButton
                            .disabled(!orchestrator.currentDiagnostics.state.canBoot || isActionInProgress)
                        teardownButton
                            .disabled(orchestrator.currentDiagnostics.state != .running || isActionInProgress)
                        configEditorButtonLarge
                        pcapExportButtonLarge
                    }
                    .padding(.top, 20)
                }
                .padding(60)
            }
            .navigationTitle("Swiftlet")
            .onAppear { startMetricsPolling() }
            .onDisappear { stopMetricsPolling() }
        }
    }
    #endif

    // MARK: - Status Header

    private var statusHeaderSection: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Circle()
                        .fill(statusColor)
                        .frame(width: 10, height: 10)
                    Text(metrics.engineStatus)
                        .font(.headline)
                }
                Text("SOCKS5 :\(orchestrator.currentDiagnostics.localSocksPort)  ·  HTTP :\(orchestrator.currentDiagnostics.localHttpPort)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 4) {
                Text("\(metrics.activeSessionCount) active")
                    .font(.subheadline.monospacedDigit())
                    .foregroundStyle(.secondary)
                Text("\(metrics.totalSessionsCreated) total")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
        }
        .padding(16)
        #if os(visionOS)
        .background(.regularMaterial)
        .glassBackgroundEffect()
        .clipShape(RoundedRectangle(cornerRadius: 16))
        #elseif os(tvOS)
        .background(.regularMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 20))
        #else
        .background(.quaternary)
        .clipShape(RoundedRectangle(cornerRadius: 12))
        #endif
    }

    private var statusColor: Color {
        switch orchestrator.currentDiagnostics.state {
        case .idle, .stopped:    return .gray
        case .booting:           return .orange
        case .running:           return .green
        case .tearingDown:       return .orange
        case .failed:            return .red
        }
    }

    // MARK: - Traffic Metrics Grid

    private var trafficMetricsGrid: some View {
        #if os(tvOS)
        // tvOS uses its own layout (see tvOSLayout)
        EmptyView()
        #else
        LazyVGrid(
            columns: [
                GridItem(.flexible(), spacing: 12),
                GridItem(.flexible(), spacing: 12),
            ],
            spacing: 12
        ) {
            MetricTile(title: "Upstream", systemImage: "arrow.up") {
                Text(DashboardLiveMetrics.formatBytesPerSecond(metrics.upstreamBytesPerSecond))
                    .font(.title3.monospacedDigit().bold())
                    .foregroundStyle(.blue)
                Text("\(DashboardLiveMetrics.formatBytes(metrics.totalBytesIn)) total")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }

            MetricTile(title: "Downstream", systemImage: "arrow.down") {
                Text(DashboardLiveMetrics.formatBytesPerSecond(metrics.downstreamBytesPerSecond))
                    .font(.title3.monospacedDigit().bold())
                    .foregroundStyle(.green)
                Text("\(DashboardLiveMetrics.formatBytes(metrics.totalBytesOut)) total")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }

            MetricTile(title: "Active Sessions", systemImage: "point.3.connected.trianglepath.dotted") {
                Text("\(metrics.activeSessionCount)")
                    .font(.title3.monospacedDigit().bold())
                Text("currently connected")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }

            MetricTile(title: "DNS Lookup", systemImage: "globe") {
                Text("\(metrics.averageDNSLookupMicros) µs")
                    .font(.title3.monospacedDigit().bold())
                Text("average resolution time")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
        }
        #endif
    }

    // MARK: - Routing Diagnostics

    private var routingDiagnosticsSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Routing & Proxy Paths", systemImage: "arrow.triangle.branch")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.secondary)

            if metrics.recentRuleMatches.isEmpty && metrics.activeProxyPaths.isEmpty {
                Text("No active routing data — boot the engine to begin.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .padding(.vertical, 8)
            } else {
                // ── Recent Rule Matches ───────────────────────────
                if !metrics.recentRuleMatches.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Recent Rule Matches")
                            .font(.caption2.weight(.medium))
                            .foregroundStyle(.tertiary)
                        ForEach(metrics.recentRuleMatches, id: \.self) { match in
                            HStack(spacing: 6) {
                                Image(systemName: "checkmark.diamond")
                                    .font(.caption2)
                                    .foregroundStyle(.blue)
                                Text(match)
                                    .font(.caption.monospaced())
                                    .lineLimit(1)
                            }
                        }
                    }
                }

                // ── Active Proxy Paths ────────────────────────────
                if !metrics.activeProxyPaths.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Active Proxy Paths")
                            .font(.caption2.weight(.medium))
                            .foregroundStyle(.tertiary)
                        ForEach(metrics.activeProxyPaths, id: \.self) { path in
                            HStack(spacing: 6) {
                                Image(systemName: "arrow.triangle.swap")
                                    .font(.caption2)
                                    .foregroundStyle(.green)
                                Text(path)
                                    .font(.caption.monospaced())
                                    .lineLimit(1)
                            }
                        }
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        #if os(visionOS)
        .background(.regularMaterial)
        .glassBackgroundEffect()
        .clipShape(RoundedRectangle(cornerRadius: 16))
        #elseif os(tvOS)
        .background(.regularMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 20))
        #else
        .background(.quaternary)
        .clipShape(RoundedRectangle(cornerRadius: 12))
        #endif
    }

    // MARK: - Engine Details

    private var engineDetailsSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Engine Details", systemImage: "gearshape.2")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.secondary)

            let diag = orchestrator.currentDiagnostics

            detailRow(label: "Core State", value: diag.coreEngineState.capitalized)
            detailRow(label: "Idle Pool Channels", value: "\(diag.poolIdleChannels)")
            detailRow(label: "Cron Schedules", value: "\(diag.cronEntryCount) active")
            detailRow(label: "Network Monitor", value: diag.networkMonitorActive ? "Active" : "Inactive")
            detailRow(label: "Cached Host Certs", value: "\(diag.cachedHostCerts)")
            detailRow(label: "Scripts", value: "\(diag.validScriptCount)/\(diag.scriptCount) valid")
            detailRow(label: "MitM Domains", value: "\(diag.mitmDomainCount)")
            detailRow(label: "PCAP Buffer", value: "\(diag.pcapBufferedCount)/4096 packets")
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        #if os(visionOS)
        .background(.regularMaterial)
        .glassBackgroundEffect()
        .clipShape(RoundedRectangle(cornerRadius: 16))
        #elseif os(tvOS)
        .background(.regularMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 20))
        #else
        .background(.quaternary)
        .clipShape(RoundedRectangle(cornerRadius: 12))
        #endif
    }

    private func detailRow(label: String, value: String) -> some View {
        HStack {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .font(.caption.monospaced().weight(.medium))
        }
    }

    // MARK: - Actions Section (iOS / macOS)

    #if os(iOS) || os(macOS)
    private var actionsSection: some View {
        VStack(spacing: 12) {
            // ── Boot / Teardown Row ─────────────────────────────
            HStack(spacing: 12) {
                bootButton
                teardownButton
            }

            // ── PCAP Export ─────────────────────────────────────
            pcapExportButton

            // ── Config Editor ───────────────────────────────────
            configEditorButton
        }
    }
    #endif

    // MARK: - Buttons

    private var bootButton: some View {
        Button {
            isActionInProgress = true
            Task {
                do {
                    try await orchestrator.bootEngine(withConfigRawText: configText)
                } catch {
                    alertError = error.localizedDescription
                    isAlertPresented = true
                }
                isActionInProgress = false
            }
        } label: {
            Label("Boot Engine", systemImage: "play.fill")
                #if os(tvOS)
                .font(.title3.weight(.semibold))
                .padding(.horizontal, 40)
                .padding(.vertical, 20)
                #else
                .frame(maxWidth: .infinity)
                #endif
        }
        .buttonStyle(.borderedProminent)
        .tint(.green)
        .disabled(!orchestrator.currentDiagnostics.state.canBoot || isActionInProgress)
        #if os(tvOS)
        .focusable(true)
        #endif
    }

    private var teardownButton: some View {
        Button {
            isActionInProgress = true
            Task {
                do {
                    try await orchestrator.teardownEngine()
                } catch {
                    alertError = error.localizedDescription
                    isAlertPresented = true
                }
                isActionInProgress = false
            }
        } label: {
            Label("Teardown", systemImage: "stop.fill")
                #if os(tvOS)
                .font(.title3.weight(.semibold))
                .padding(.horizontal, 40)
                .padding(.vertical, 20)
                #else
                .frame(maxWidth: .infinity)
                #endif
        }
        .buttonStyle(.borderedProminent)
        .tint(.red)
        .disabled(orchestrator.currentDiagnostics.state != .running || isActionInProgress)
        #if os(tvOS)
        .focusable(true)
        #endif
    }

    private var pcapExportButton: some View {
        Button {
            let data = orchestrator.dumpActiveBuffersToPCAP()
            guard !data.isEmpty else {
                alertError = "PCAP buffer is empty. Capture must be enabled and traffic must be flowing."
                isAlertPresented = true
                return
            }
            pcapExportData = data
            isPCAPSharePresented = true
        } label: {
            Label("Export PCAP Dump", systemImage: "doc.badge.arrow.up")
                #if os(tvOS)
                .font(.title3.weight(.semibold))
                #else
                .frame(maxWidth: .infinity)
                #endif
        }
        .buttonStyle(.bordered)
        .disabled(orchestrator.currentDiagnostics.state != .running)
        #if os(tvOS)
        .focusable(true)
        #endif
    }

    #if os(tvOS)
    private var pcapExportButtonLarge: some View {
        Button {
            let data = orchestrator.dumpActiveBuffersToPCAP()
            guard !data.isEmpty else {
                alertError = "PCAP buffer is empty."
                isAlertPresented = true
                return
            }
            pcapExportData = data
            isPCAPSharePresented = true
        } label: {
            Label("Export PCAP", systemImage: "doc.badge.arrow.up")
                .font(.title3.weight(.semibold))
                .padding(.horizontal, 40)
                .padding(.vertical, 20)
        }
        .buttonStyle(.bordered)
        .disabled(orchestrator.currentDiagnostics.state != .running)
        .focusable(true)
    }
    #endif

    private var configEditorButton: some View {
        Button {
            isConfigEditorPresented = true
        } label: {
            Label("Edit Configuration", systemImage: "doc.text")
                #if os(tvOS)
                .font(.title3.weight(.semibold))
                #else
                .frame(maxWidth: .infinity)
                #endif
        }
        .buttonStyle(.bordered)
        .tint(.blue)
        #if os(tvOS)
        .focusable(true)
        #endif
    }

    #if os(tvOS)
    private var configEditorButtonLarge: some View {
        Button {
            isConfigEditorPresented = true
        } label: {
            Label("Edit Config", systemImage: "doc.text")
                .font(.title3.weight(.semibold))
                .padding(.horizontal, 40)
                .padding(.vertical, 20)
        }
        .buttonStyle(.bordered)
        .focusable(true)
    }
    #endif

    // MARK: - Config Editor Sheet

    private var configEditorSheet: some View {
        #if os(tvOS)
        NavigationStack {
            VStack(spacing: 40) {
                Text("Configuration Editor")
                    .font(.largeTitle.weight(.bold))
                TextEditor(text: $configText)
                    .font(.body.monospaced())
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .padding(40)
                Button("Done") { isConfigEditorPresented = false }
                    .buttonStyle(.borderedProminent)
            }
            .padding(60)
        }
        #else
        NavigationStack {
            VStack(spacing: 0) {
                TextEditor(text: $configText)
                    .font(.caption.monospaced())
                    #if os(visionOS)
                    .padding(20)
                    #else
                    .padding(12)
                    #endif
            }
            .navigationTitle("Configuration")
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { isConfigEditorPresented = false }
                }
                ToolbarItem(placement: .cancellationAction) {
                    Button("Reset") {
                        configText = Self.defaultConfigTemplate
                    }
                }
            }
        }
        .presentationDetents([.medium, .large])
        #endif
    }

    // MARK: - Metrics Polling

    /// Starts a background `Task` that polls `SessionDiagnosticsTracker`
    /// every 500ms and updates `metrics` on the main actor, triggering
    /// SwiftUI re‑renders.
    private func startMetricsPolling() {
        guard pollingTask == nil else { return }
        pollingTask = Task { @MainActor in
            var previousBytesIn: UInt64 = 0
            var previousBytesOut: UInt64 = 0
            var previousTimestamp: Date = Date()

            for await _ in metricsStream() {
                guard !Task.isCancelled else { break }

                let snapshots = await NetworkOrchestrator.shared.activeSessions()
                let diag = NetworkOrchestrator.shared.currentDiagnostics

                // ── Aggregate traffic ────────────────────────────
                let totalIn  = snapshots.reduce(0) { $0 + $1.bytesIn }
                let totalOut = snapshots.reduce(0) { $0 + $1.bytesOut }
                let now = Date()
                let elapsed = now.timeIntervalSince(previousTimestamp)

                let bpsIn: Double  = elapsed > 0 ? Double(totalIn  &- previousBytesIn) / elapsed : 0
                let bpsOut: Double = elapsed > 0 ? Double(totalOut &- previousBytesOut) / elapsed : 0

                previousBytesIn  = totalIn
                previousBytesOut = totalOut
                previousTimestamp = now

                // ── DNS average ──────────────────────────────────
                let dnsDurations = snapshots.compactMap(\.dnsLookupDurationMicros)
                let avgDNS: UInt64 = dnsDurations.isEmpty ? 0
                    : dnsDurations.reduce(0, +) / UInt64(dnsDurations.count)

                // ── Rule matches ─────────────────────────────────
                let ruleMatches = snapshots
                    .compactMap(\.ruleMatched)
                    .filter { !$0.isEmpty }
                    .prefix(5)
                    .map { $0 }

                // ── Proxy paths (from active sessions via destination) ──
                let paths = snapshots
                    .prefix(5)
                    .map { "\($0.inboundType) → \($0.destinationTarget)" }

                metrics = DashboardLiveMetrics(
                    upstreamBytesPerSecond: bpsIn,
                    downstreamBytesPerSecond: bpsOut,
                    totalBytesIn: totalIn,
                    totalBytesOut: totalOut,
                    activeSessionCount: snapshots.count,
                    totalSessionsCreated: diag.totalSessionsCreated,
                    recentRuleMatches: ruleMatches,
                    averageDNSLookupMicros: avgDNS,
                    activeProxyPaths: paths,
                    engineStatus: diag.state.description,
                    pcapPacketsCaptured: diag.pcapPacketsCaptured,
                    cronEntryCount: diag.cronEntryCount,
                    networkMonitorActive: diag.networkMonitorActive,
                    capturedAt: now
                )
            }
        }
    }

    /// Stops the polling task.
    private func stopMetricsPolling() {
        pollingTask?.cancel()
        pollingTask = nil
    }

    /// Creates an `AsyncStream` that yields on a 500ms interval.
    private func metricsStream() -> AsyncStream<Date> {
        AsyncStream { continuation in
            let task = Task {
                var tick: UInt64 = 0
                while !Task.isCancelled {
                    continuation.yield(Date())
                    tick &+= 1
                    // 500ms interval yields 2 Hz refresh — enough for
                    // real‑time feel without saturating the main thread.
                    try? await Task.sleep(nanoseconds: 500_000_000)
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    /// Force an immediate metrics refresh (used by `.refreshable`).
    private func refreshMetricsNow() async {
        let snapshots = await NetworkOrchestrator.shared.activeSessions()
        let diag = NetworkOrchestrator.shared.currentDiagnostics

        let totalIn  = snapshots.reduce(0) { $0 + $1.bytesIn }
        let totalOut = snapshots.reduce(0) { $0 + $1.bytesOut }
        let dnsDurations = snapshots.compactMap(\.dnsLookupDurationMicros)
        let avgDNS: UInt64 = dnsDurations.isEmpty ? 0
            : dnsDurations.reduce(0, +) / UInt64(dnsDurations.count)

        metrics = DashboardLiveMetrics(
            upstreamBytesPerSecond: metrics.upstreamBytesPerSecond,
            downstreamBytesPerSecond: metrics.downstreamBytesPerSecond,
            totalBytesIn: totalIn,
            totalBytesOut: totalOut,
            activeSessionCount: snapshots.count,
            totalSessionsCreated: diag.totalSessionsCreated,
            recentRuleMatches: snapshots.compactMap(\.ruleMatched).prefix(5).map { $0 },
            averageDNSLookupMicros: avgDNS,
            activeProxyPaths: snapshots.prefix(5).map { "\($0.inboundType) → \($0.destinationTarget)" },
            engineStatus: diag.state.description,
            pcapPacketsCaptured: diag.pcapPacketsCaptured,
            cronEntryCount: diag.cronEntryCount,
            networkMonitorActive: diag.networkMonitorActive,
            capturedAt: Date()
        )
    }

    // MARK: - Default Config Template

    /// A minimal Surge/Loon‑style configuration template for quick
    /// testing and onboarding.
    fileprivate static let defaultConfigTemplate = """
    [General]
    dns-server = 223.5.5.5, 119.29.29.29
    skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local

    [Proxy]
    Direct = direct

    [Rule]
    DOMAIN-SUFFIX, apple.com, DIRECT
    DOMAIN-SUFFIX, icloud.com, DIRECT
    GEOIP, CN, DIRECT
    FINAL, PROXY

    [Host]
    # Static host mappings (optional)
    # example.com = 1.2.3.4

    [MITM]
    # hostname = *.example.com, api.example.org

    [Script]
    # MyScript.js, type=cron, cronexpr=0 8 * * *
    """
}

// MARK: - PCAP Share Sheet (iOS / visionOS)

#if os(iOS) || os(visionOS)
/// A share sheet wrapper for iOS / visionOS that presents the
/// standard system share UI for a `.pcap` file.
fileprivate struct PCAPShareView_iOS: UIViewControllerRepresentable {
    let pcapData: Data

    func makeUIViewController(context: Context) -> UIActivityViewController {
        // Write PCAP data to a temporary file so the share sheet
        // presents it as a proper `.pcap` attachment.
        let tempDir = FileManager.default.temporaryDirectory
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        let filename = "swiftlet-dump-\(formatter.string(from: Date())).pcap"
        let fileURL = tempDir.appendingPathComponent(filename)
        try? pcapData.write(to: fileURL, options: .atomic)

        let controller = UIActivityViewController(
            activityItems: [fileURL],
            applicationActivities: nil
        )
        controller.excludedActivityTypes = [.assignToContact, .addToReadingList]
        return controller
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}
#endif

// MARK: - PCAP Share Sheet (macOS)

#if os(macOS)
/// A Mac‑native PCAP export view using `NSSharingService`.
fileprivate struct PCAPShareView_macOS: View {
    let pcapData: Data
    @State private var tempFileURL: URL?

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "doc.badge.arrow.up")
                .font(.system(size: 48))
                .foregroundStyle(.blue)

            Text("PCAP Export Ready")
                .font(.title2.weight(.semibold))

            Text("\(pcapData.count) bytes · \(pcapData.count / max(1, pcapGlobalHeaderSize)) packets (est.)")
                .font(.caption)
                .foregroundStyle(.secondary)

            HStack(spacing: 12) {
                Button("Save to Disk…") {
                    saveToDisk()
                }
                .buttonStyle(.borderedProminent)

                Button("Copy to Clipboard") {
                    // Write to temp file, copy file path
                    let url = writeTempFile()
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(url.path, forType: .fileURL)
                }
                .buttonStyle(.bordered)
            }
        }
        .padding(40)
        .frame(minWidth: 400, minHeight: 250)
    }

    private func saveToDisk() {
        let url = writeTempFile()
        let savePanel = NSSavePanel()
        savePanel.nameFieldStringValue = url.lastPathComponent
        savePanel.allowedContentTypes = [UTType(filenameExtension: "pcap") ?? .data]
        savePanel.begin { response in
            if response == .OK, let dest = savePanel.url {
                try? FileManager.default.copyItem(at: url, to: dest)
            }
        }
    }

    private func writeTempFile() -> URL {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        let filename = "swiftlet-dump-\(formatter.string(from: Date())).pcap"
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(filename)
        try? pcapData.write(to: url, options: .atomic)
        return url
    }

    // Estimate packet count from global header size constant.
    private let pcapGlobalHeaderSize = 24
}
#endif

// MARK: - PCAP Share Sheet (tvOS)

#if os(tvOS)
/// tvOS does not support `UIActivityViewController`.  Instead we
/// display the PCAP metadata and offer to save it to the app's
/// documents directory (which can be accessed via Finder/iTunes
/// File Sharing on tvOS).
fileprivate struct PCAPShareView_tvOS: View {
    let pcapData: Data
    @Environment(\.dismiss) private var dismiss
    @State private var saved = false
    @State private var saveError: String?

    var body: some View {
        NavigationStack {
            VStack(spacing: 40) {
                Image(systemName: "doc.badge.arrow.up")
                    .font(.system(size: 80))
                    .foregroundStyle(.blue)

                Text("PCAP Export")
                    .font(.largeTitle.weight(.bold))

                Text("\(pcapData.count) bytes captured")
                    .font(.title3)
                    .foregroundStyle(.secondary)

                if saved {
                    Label("Saved to Documents", systemImage: "checkmark.circle.fill")
                        .font(.title3)
                        .foregroundStyle(.green)
                }

                if let error = saveError {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .padding()
                }

                Button {
                    saveToDocuments()
                } label: {
                    Label("Save to Documents", systemImage: "square.and.arrow.down")
                        .font(.title2.weight(.semibold))
                        .padding(.horizontal, 60)
                        .padding(.vertical, 30)
                }
                .buttonStyle(.borderedProminent)
                .disabled(saved)
                .focusable(true)

                Button("Dismiss") { dismiss() }
                    .buttonStyle(.bordered)
                    .focusable(true)
            }
            .padding(60)
        }
    }

    private func saveToDocuments() {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        let filename = "swiftlet-dump-\(formatter.string(from: Date())).pcap"
        let url = docs.appendingPathComponent(filename)
        do {
            try pcapData.write(to: url, options: .atomic)
            saved = true
        } catch {
            saveError = error.localizedDescription
        }
    }
}
#endif

// MARK: - Orchestrator Dependency Wrapper

/// A lightweight `@Observable` wrapper around
/// `NetworkOrchestrator.shared` so that SwiftUI views can use
/// `@Environment` for dependency injection without
/// strongly coupling to the singleton.
///
/// Uses the Swift 6‑native `@Observable` macro (iOS 17+ /
/// macOS 14+ / tvOS 17+ / visionOS 2+) instead of the legacy
/// `ObservableObject` protocol, avoiding global‑actor isolation
/// conflicts under strict concurrency checking.
///
/// This wrapper forwards all calls to the shared orchestrator
/// and publishes state changes that trigger SwiftUI re‑renders.
@MainActor
@Observable
public final class NetworkOrchestratorDependency {
    /// The underlying shared orchestrator.
    private let orchestrator = NetworkOrchestrator.shared

    /// Diagnostics snapshot for SwiftUI bindings.
    public private(set) var diagnostics = OrchestratorDiagnostics.empty

    /// Live metrics for SwiftUI bindings.
    public private(set) var liveMetrics = DashboardLiveMetrics.empty

    /// State for action button enable/disable.
    public private(set) var isActionInProgress = false

    public init() {}

    /// Forwards boot to the shared orchestrator.
    public func bootEngine(withConfigRawText text: String) async throws {
        isActionInProgress = true
        defer { isActionInProgress = false }
        try await orchestrator.bootEngine(withConfigRawText: text)
        await refresh()
    }

    /// Forwards teardown to the shared orchestrator.
    public func teardownEngine() async throws {
        isActionInProgress = true
        defer { isActionInProgress = false }
        try await orchestrator.teardownEngine()
        await refresh()
    }

    /// Exports the PCAP buffer.
    public func dumpActiveBuffersToPCAP() -> Data {
        orchestrator.dumpActiveBuffersToPCAP()
    }

    /// Refreshes diagnostics and published state.
    public func refresh() async {
        diagnostics = await orchestrator.refreshDiagnostics()
    }

    /// Convenience accessors matching the orchestrator API.
    public var currentDiagnostics: OrchestratorDiagnostics {
        diagnostics
    }
}

// MARK: - Preview

#if DEBUG
#Preview("Dashboard — Idle") {
    NavigationStack {
        DashboardView()
            .environment(NetworkOrchestratorDependency())
    }
}

#Preview("Dashboard — macOS") {
    NavigationSplitView {
        DashboardView()
            .environment(NetworkOrchestratorDependency())
    } detail: {
        Text("Select a session")
    }
}
#endif
