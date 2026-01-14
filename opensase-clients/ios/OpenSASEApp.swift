// OpenSASE iOS Client - Swift / SwiftUI
// /src/client/ios/OpenSASE/OpenSASEApp.swift

import SwiftUI
import NetworkExtension

@main
struct OpenSASEApp: App {
    @StateObject private var appState = AppState()
    
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appState)
        }
    }
}

struct ContentView: View {
    @EnvironmentObject var appState: AppState
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 20) {
                    // Status card
                    StatusCard(
                        isConnected: appState.isConnected,
                        gateway: appState.connectedGateway,
                        duration: appState.connectionDuration
                    )
                    
                    // Connect button
                    Button(action: {
                        if appState.isConnected {
                            appState.disconnect()
                        } else {
                            appState.connect()
                        }
                    }) {
                        HStack {
                            Image(systemName: appState.isConnected ? "shield.slash" : "shield.fill")
                            Text(appState.isConnected ? "Disconnect" : "Connect")
                        }
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(appState.isConnected ? Color.red : Color.green)
                        .foregroundColor(.white)
                        .cornerRadius(10)
                    }
                    .padding(.horizontal)
                    
                    // Posture status
                    PostureCard(score: appState.postureScore, violations: appState.postureViolations)
                    
                    // Connection stats
                    if appState.isConnected {
                        StatsCard(stats: appState.connectionStats)
                    }
                    
                    Spacer()
                }
                .padding(.top)
            }
            .navigationTitle("OpenSASE")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    NavigationLink(destination: SettingsView()) {
                        Image(systemName: "gear")
                    }
                }
            }
        }
    }
}

struct StatusCard: View {
    let isConnected: Bool
    let gateway: String
    let duration: String
    
    var body: some View {
        VStack(spacing: 12) {
            HStack {
                Circle()
                    .fill(isConnected ? Color.green : Color.red)
                    .frame(width: 12, height: 12)
                Text(isConnected ? "Protected" : "Not Protected")
                    .font(.headline)
            }
            
            if isConnected {
                VStack(spacing: 4) {
                    HStack {
                        Text("Gateway:")
                        Spacer()
                        Text(gateway)
                    }
                    .font(.caption)
                    
                    HStack {
                        Text("Connected:")
                        Spacer()
                        Text(duration)
                    }
                    .font(.caption)
                }
            }
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(10)
        .padding(.horizontal)
    }
}

struct PostureCard: View {
    let score: Double
    let violations: [String]
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Device Posture")
                    .font(.headline)
                Spacer()
                Text("\(Int(score))%")
                    .font(.title2)
                    .fontWeight(.bold)
                    .foregroundColor(score >= 70 ? .green : .orange)
            }
            
            if !violations.isEmpty {
                Divider()
                ForEach(violations, id: \.self) { violation in
                    HStack {
                        Image(systemName: "exclamationmark.triangle")
                            .foregroundColor(.orange)
                        Text(violation)
                            .font(.caption)
                    }
                }
            }
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(10)
        .padding(.horizontal)
    }
}

struct StatsCard: View {
    let stats: ConnectionStats
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Connection Stats")
                .font(.headline)
            
            Divider()
            
            HStack {
                VStack(alignment: .leading) {
                    Text("Upload")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Text(formatBytes(stats.bytesSent))
                        .font(.callout)
                }
                Spacer()
                VStack(alignment: .trailing) {
                    Text("Download")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Text(formatBytes(stats.bytesReceived))
                        .font(.callout)
                }
            }
            
            HStack {
                Text("Latency:")
                    .font(.caption)
                Spacer()
                Text("\(stats.latencyMs)ms")
                    .font(.callout)
            }
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(10)
        .padding(.horizontal)
    }
    
    private func formatBytes(_ bytes: Int64) -> String {
        let units = ["B", "KB", "MB", "GB"]
        var value = Double(bytes)
        var unitIndex = 0
        
        while value >= 1024 && unitIndex < units.count - 1 {
            value /= 1024
            unitIndex += 1
        }
        
        return String(format: "%.1f %@", value, units[unitIndex])
    }
}

struct SettingsView: View {
    @AppStorage("autoConnect") var autoConnect = false
    @AppStorage("onDemand") var onDemand = true
    
    var body: some View {
        Form {
            Section(header: Text("Connection")) {
                Toggle("Auto-connect", isOn: $autoConnect)
                Toggle("Connect on demand", isOn: $onDemand)
            }
            
            Section(header: Text("Account")) {
                NavigationLink("Manage Account") {
                    AccountView()
                }
            }
            
            Section(header: Text("About")) {
                HStack {
                    Text("Version")
                    Spacer()
                    Text("1.0.0")
                        .foregroundColor(.secondary)
                }
            }
        }
        .navigationTitle("Settings")
    }
}

struct AccountView: View {
    var body: some View {
        List {
            Text("Account details")
        }
        .navigationTitle("Account")
    }
}

class AppState: ObservableObject {
    @Published var isConnected = false
    @Published var statusText = "Disconnected"
    @Published var connectedGateway = ""
    @Published var assignedIP = ""
    @Published var connectionDuration = ""
    @Published var postureScore: Double = 85
    @Published var postureViolations: [String] = []
    @Published var connectionStats = ConnectionStats()
    
    private var tunnelManager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private var timer: Timer?
    private var connectionStart: Date?
    
    init() {
        loadTunnelManager()
        collectPosture()
    }
    
    func connect() {
        guard let manager = tunnelManager else {
            setupTunnelManager()
            return
        }
        
        do {
            try manager.connection.startVPNTunnel()
            statusText = "Connecting..."
        } catch {
            statusText = "Failed: \(error.localizedDescription)"
        }
    }
    
    func disconnect() {
        tunnelManager?.connection.stopVPNTunnel()
        timer?.invalidate()
    }
    
    private func setupTunnelManager() {
        let manager = NETunnelProviderManager()
        
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "io.opensase.client.tunnel"
        proto.serverAddress = "gateway.opensase.io"
        
        manager.protocolConfiguration = proto
        manager.localizedDescription = "OpenSASE"
        manager.isEnabled = true
        
        manager.saveToPreferences { [weak self] error in
            if error == nil {
                self?.tunnelManager = manager
                self?.observeStatus()
                self?.connect()
            }
        }
    }
    
    private func loadTunnelManager() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, _ in
            self?.tunnelManager = managers?.first
            self?.observeStatus()
        }
    }
    
    private func observeStatus() {
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: tunnelManager?.connection,
            queue: .main
        ) { [weak self] _ in
            self?.updateStatus()
        }
    }
    
    private func updateStatus() {
        guard let status = tunnelManager?.connection.status else { return }
        
        switch status {
        case .connected:
            isConnected = true
            statusText = "Connected"
            connectedGateway = "us-west-1"
            assignedIP = "10.0.0.1"
            connectionStart = Date()
            startTimer()
        case .connecting:
            statusText = "Connecting..."
        case .disconnecting:
            statusText = "Disconnecting..."
        case .disconnected:
            isConnected = false
            statusText = "Disconnected"
            timer?.invalidate()
        default:
            statusText = "Unknown"
        }
    }
    
    private func startTimer() {
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            guard let start = self?.connectionStart else { return }
            let elapsed = Int(Date().timeIntervalSince(start))
            let hours = elapsed / 3600
            let minutes = (elapsed % 3600) / 60
            let seconds = elapsed % 60
            self?.connectionDuration = String(format: "%02d:%02d:%02d", hours, minutes, seconds)
        }
    }
    
    private func collectPosture() {
        // iOS posture collection
        var score: Double = 100
        var violations: [String] = []
        
        // Check passcode
        // Check jailbreak
        // Check encryption
        
        postureScore = score
        postureViolations = violations
    }
}

struct ConnectionStats {
    var bytesSent: Int64 = 0
    var bytesReceived: Int64 = 0
    var latencyMs: Int = 25
}

// Network Extension Provider
class PacketTunnelProvider: NEPacketTunnelProvider {
    
    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        // Configure tunnel settings
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "gateway.opensase.io")
        
        // IPv4
        let ipv4 = NEIPv4Settings(addresses: ["10.0.0.1"], subnetMasks: ["255.255.255.255"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4
        
        // DNS
        let dns = NEDNSSettings(servers: ["10.0.0.2"])
        dns.matchDomains = [""]
        settings.dnsSettings = dns
        
        // MTU
        settings.mtu = 1280
        
        setTunnelNetworkSettings(settings) { error in
            if let error = error {
                completionHandler(error)
                return
            }
            
            // Start WireGuard tunnel using Rust core
            completionHandler(nil)
        }
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
    }
    
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        // Handle IPC from main app
        completionHandler?(nil)
    }
}
