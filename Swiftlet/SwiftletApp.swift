//
//  SwiftletApp.swift
//  Swiftlet
//
//  Quad‑Platform Unified Proxy Host Application
//
//  Entry point for the Swiftlet proxy management dashboard across
//  iOS 17, macOS 14, tvOS 17, and visionOS 2.  Bootstraps the
//  NetworkOrchestrator dependency, SwiftData persistence, and
//  the cross‑platform DashboardView.
//

import SwiftUI
import SwiftData

@main
struct SwiftletApp: App {

    // MARK: - SwiftData

    /// Persistent storage for configuration profiles and session
    /// history.  In‑memory only during development; switch to
    /// persistent storage for production.
    var sharedModelContainer: ModelContainer = {
        let schema = Schema([
            Item.self,
        ])
        let modelConfiguration = ModelConfiguration(
            schema: schema,
            isStoredInMemoryOnly: false
        )

        do {
            return try ModelContainer(
                for: schema,
                configurations: [modelConfiguration]
            )
        } catch {
            fatalError("Could not create ModelContainer: \(error)")
        }
    }()

    // MARK: - Orchestrator

    /// The `@Observable` dependency wrapper around
    /// `NetworkOrchestrator.shared`.  Injected into the view
    /// hierarchy via `.environment()`.
    @State private var orchestratorDependency = NetworkOrchestratorDependency()

    // MARK: - Body

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(orchestratorDependency)
        }
        .modelContainer(sharedModelContainer)

        // ── macOS: Settings / Preferences window ─────────────────
        #if os(macOS)
        Settings {
            SettingsView()
                .environment(orchestratorDependency)
        }
        #endif
    }
}

// MARK: - macOS Settings View

#if os(macOS)
/// A minimal settings panel for the Swiftlet proxy application.
/// Provides quick access to Root CA export and configuration
/// management from the app menu → Settings… (⌘,).
fileprivate struct SettingsView: View {
    @Environment(NetworkOrchestratorDependency.self) private var orchestrator

    var body: some View {
        TabView {
            // ── General ───────────────────────────────────────
            VStack(alignment: .leading, spacing: 12) {
                Text("Proxy Ports")
                    .font(.headline)

                let diag = orchestrator.currentDiagnostics
                LabeledContent("SOCKS5 Port", value: "\(diag.localSocksPort)")
                LabeledContent("HTTP Proxy Port", value: "\(diag.localHttpPort)")

                Divider()

                Text("Engine Status")
                    .font(.headline)
                LabeledContent("State", value: diag.state.description)

                Spacer()
            }
            .padding()
            .tabItem {
                Label("General", systemImage: "gearshape")
            }

            // ── Security ───────────────────────────────────────
            VStack(alignment: .leading, spacing: 12) {
                Text("Root CA Certificate")
                    .font(.headline)

                Text("Install the Root CA to enable TLS interception for MitM domains.")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Button("Copy Root CA PEM to Clipboard") {
                    Task {
                        if let pem = await NetworkOrchestrator.shared.rootCAPEMString() {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(pem, forType: .string)
                        }
                    }
                }

                Divider()

                let diag = orchestrator.currentDiagnostics
                LabeledContent("Cached Host Certs", value: "\(diag.cachedHostCerts)")
                LabeledContent("MitM Domains", value: "\(diag.mitmDomainCount)")

                Spacer()
            }
            .padding()
            .tabItem {
                Label("Security", systemImage: "lock.shield")
            }
        }
        .frame(width: 400, height: 300)
    }
}
#endif
