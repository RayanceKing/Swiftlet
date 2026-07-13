//
//  ContentView.swift
//  Swiftlet
//
//  Root content view for the Swiftlet quad‑platform proxy dashboard.
//  Hosts the cross‑platform `DashboardView` within an adaptive
//  navigation structure suitable for iOS, macOS, tvOS, and visionOS.
//

import SwiftUI
import SwiftData
import SwiftletCore

/// The root view of the Swiftlet application.
///
/// Wraps `DashboardView` in a platform‑adaptive navigation
/// container:
/// - **macOS**: `NavigationSplitView` with sidebar + detail.
/// - **iOS / visionOS**: `TabView` with Dashboard and History tabs.
/// - **tvOS**: `NavigationStack` with full‑screen focus‑optimized layout.
struct ContentView: View {

    // MARK: - Environment

    @Environment(NetworkOrchestratorDependency.self) private var orchestrator

    // MARK: - State

    /// Active tab selection (iOS / visionOS).
    @State private var selectedTab: AppTab = .dashboard

    // MARK: - Body

    var body: some View {
        #if os(macOS)
        macOSLayout
        #elseif os(tvOS)
        tvOSLayout
        #else
        // iOS / visionOS unified tab layout
        tabLayout
        #endif
    }

    // MARK: - iOS / visionOS Tab Layout

    @ViewBuilder
    private var tabLayout: some View {
        TabView(selection: $selectedTab) {
            NavigationStack {
                DashboardView()
                    .environment(orchestrator)
            }
            .tabItem {
                Label("Dashboard", systemImage: "gauge.with.dots.needle.33percent")
            }
            .tag(AppTab.dashboard)

            NavigationStack {
                SessionHistoryView()
                    .environment(orchestrator)
            }
            .tabItem {
                Label("Sessions", systemImage: "list.bullet.rectangle")
            }
            .tag(AppTab.sessions)

            NavigationStack {
                ConfigurationLibraryView()
            }
            .tabItem {
                Label("Configs", systemImage: "doc.text")
            }
            .tag(AppTab.configs)
        }
    }

    // MARK: - macOS Layout

    #if os(macOS)
    @ViewBuilder
    private var macOSLayout: some View {
        NavigationSplitView {
            // ── Sidebar ────────────────────────────────────────
            List(selection: $selectedTab) {
                Label("Dashboard", systemImage: "gauge.with.dots.needle.33percent")
                    .tag(AppTab.dashboard)
                Label("Sessions", systemImage: "list.bullet.rectangle")
                    .tag(AppTab.sessions)
                Label("Configuration", systemImage: "doc.text")
                    .tag(AppTab.configs)

                Divider()

                // Quick status indicator
                let diag = orchestrator.currentDiagnostics
                HStack {
                    Circle()
                        .fill(statusColor(for: diag.state))
                        .frame(width: 8, height: 8)
                    Text(diag.state.description)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 4)
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 220)
            .listStyle(.sidebar)
        } detail: {
            // ── Detail ─────────────────────────────────────────
            switch selectedTab {
            case .dashboard:
                DashboardView()
                    .environment(orchestrator)
            case .sessions:
                SessionHistoryView()
                    .environment(orchestrator)
            case .configs:
                ConfigurationLibraryView()
            }
        }
    }
    #endif

    // MARK: - tvOS Layout

    #if os(tvOS)
    @ViewBuilder
    private var tvOSLayout: some View {
        TabView {
            DashboardView()
                .environment(orchestrator)
                .tabItem {
                    Label("Dashboard", systemImage: "gauge.with.dots.needle.33percent")
                }
                .tag(AppTab.dashboard)

            SessionHistoryView()
                .environment(orchestrator)
                .tabItem {
                    Label("Sessions", systemImage: "list.bullet.rectangle")
                }
                .tag(AppTab.sessions)
        }
    }
    #endif

    // MARK: - Helpers

    private func statusColor(for state: OrchestratorState) -> Color {
        switch state {
        case .idle, .stopped:    return .gray
        case .booting:           return .orange
        case .running:           return .green
        case .tearingDown:       return .orange
        case .failed:            return .red
        }
    }
}

// MARK: - App Tab Enum

/// Tabs in the main application interface.
fileprivate enum AppTab: String, Hashable, Sendable {
    case dashboard
    case sessions
    case configs
}

// MARK: - Session History View

/// Displays recent proxy session history from the diagnostics
/// tracker — active sessions and recently closed ones.
fileprivate struct SessionHistoryView: View {
    @Environment(NetworkOrchestratorDependency.self) private var orchestrator
    @State private var activeSessions: [SessionSnapshot] = []
    @State private var closedSessions: [SessionSnapshot] = []
    @State private var refreshTask: Task<Void, Never>?

    var body: some View {
        List {
            // ── Active Sessions ─────────────────────────────
            Section {
                if activeSessions.isEmpty {
                    Text("No active sessions")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                } else {
                    ForEach(activeSessions) { session in
                        SessionRow(session: session)
                    }
                }
            } header: {
                Label("Active (\(activeSessions.count))", systemImage: "circle.dotted")
            }

            // ── Recently Closed ─────────────────────────────
            Section {
                if closedSessions.isEmpty {
                    Text("No completed sessions yet")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                } else {
                    ForEach(closedSessions) { session in
                        SessionRow(session: session)
                    }
                }
            } header: {
                Label("Recently Closed (\(closedSessions.count))", systemImage: "checkmark.circle")
            }
        }
        .navigationTitle("Sessions")
        #if os(macOS)
        .navigationSubtitle("\(activeSessions.count) active")
        #endif
        .refreshable { await refreshSessions() }
        .onAppear { startAutoRefresh() }
        .onDisappear { refreshTask?.cancel() }
    }

    private func startAutoRefresh() {
        refreshTask = Task {
            while !Task.isCancelled {
                await refreshSessions()
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }

    private func refreshSessions() async {
        activeSessions = await NetworkOrchestrator.shared.activeSessions()
        closedSessions = await NetworkOrchestrator.shared.recentClosedSessions(count: 50)
    }
}

// MARK: - Session Row

/// A compact session summary row used in the history list.
fileprivate struct SessionRow: View {
    let session: SessionSnapshot

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            // ── Target ─────────────────────────────────────
            HStack {
                Circle()
                    .fill(session.isActive ? Color.green : Color.gray)
                    .frame(width: 6, height: 6)
                Text(session.destinationTarget)
                    .font(.caption.monospaced().weight(.medium))
                    .lineLimit(1)
                Spacer()
                Text(session.inboundType.description)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(.quaternary)
                    .clipShape(Capsule())
            }

            // ── Metadata ──────────────────────────────────
            HStack(spacing: 12) {
                if let dns = session.dnsLookupDurationMicros {
                    Label("\(dns) µs", systemImage: "globe")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
                if let rule = session.ruleMatched {
                    Label(rule, systemImage: "arrow.triangle.branch")
                        .font(.caption2)
                        .foregroundStyle(.blue)
                        .lineLimit(1)
                }
                Label("↓\(DashboardLiveMetrics.formatBytes(session.bytesIn))", systemImage: "arrow.down")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                Label("↑\(DashboardLiveMetrics.formatBytes(session.bytesOut))", systemImage: "arrow.up")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Configuration Library View

/// A placeholder view for managing saved configuration profiles.
fileprivate struct ConfigurationLibraryView: View {
    @Query private var items: [Item]
    @Environment(\.modelContext) private var modelContext

    var body: some View {
        List {
            if items.isEmpty {
                ContentUnavailableView(
                    "No Saved Configurations",
                    systemImage: "doc.text.magnifyingglass",
                    description: Text("Save your proxy configurations for quick access.")
                )
            } else {
                ForEach(items) { item in
                    VStack(alignment: .leading) {
                        Text(item.timestamp, format: Date.FormatStyle(date: .numeric, time: .standard))
                            .font(.caption)
                    }
                }
                .onDelete { offsets in
                    for index in offsets {
                        modelContext.delete(items[index])
                    }
                }
            }
        }
        .navigationTitle("Configurations")
        #if os(iOS)
        .toolbar {
            EditButton()
        }
        #endif
    }
}

// MARK: - Preview

#if DEBUG
#Preview("Content View") {
    ContentView()
        .environment(NetworkOrchestratorDependency())
        .modelContainer(for: Item.self, inMemory: true)
}
#endif
