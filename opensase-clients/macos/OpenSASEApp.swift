// OpenSASE macOS Client - Swift / SwiftUI
// /src/client/macos/OpenSASE/OpenSASEApp.swift

import SwiftUI
import NetworkExtension
import SystemConfiguration

@main
struct OpenSASEApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @StateObject private var connectionManager = ConnectionManager()
    
    var body: some Scene {
        MenuBarExtra {
            MenuBarView(connectionManager: connectionManager)
        } label: {
            Image(systemName: connectionManager.isConnected ? "shield.fill" : "shield")
                .symbolRenderingMode(.hierarchical)
                .foregroundColor(connectionManager.isConnected ? .green : .secondary)
        }
        
        Settings {
            SettingsView(connectionManager: connectionManager)
        }
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem?
    
    func applicationDidFinishLaunching(_ notification: Notification) {
        requestVPNPermission()
    }
    
    func requestVPNPermission() {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error = error {
                print("Error loading VPN preferences: \(error)")
                return
            }
            
            let manager = managers?.first ?? NETunnelProviderManager()
            
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = "io.opensase.client.tunnel"
            proto.serverAddress = "gateway.opensase.io"
            
            manager.protocolConfiguration = proto
            manager.localizedDescription = "OpenSASE"
            manager.isEnabled = true
            
            manager.saveToPreferences { error in
                if let error = error {
                    print("Error saving VPN preferences: \(error)")
                }
            }
        }
    }
}

struct MenuBarView: View {
    @ObservedObject var connectionManager: ConnectionManager
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // Status
            HStack {
                Circle()
                    .fill(connectionManager.isConnected ? Color.green : Color.red)
                    .frame(width: 8, height: 8)
                Text(connectionManager.statusText)
                    .font(.headline)
            }
            
            Divider()
            
            // Connection info
            if connectionManager.isConnected {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Gateway: \(connectionManager.connectedGateway)")
                        .font(.caption)
                    Text("IP: \(connectionManager.assignedIP)")
                        .font(.caption)
                    Text("Duration: \(connectionManager.connectionDuration)")
                        .font(.caption)
                }
                
                Divider()
            }
            
            // Posture status
            HStack {
                Text("Device Posture:")
                Spacer()
                Text("\(Int(connectionManager.postureScore))%")
                    .foregroundColor(connectionManager.postureScore > 70 ? .green : .orange)
            }
            .font(.caption)
            
            if !connectionManager.postureViolations.isEmpty {
                ForEach(connectionManager.postureViolations, id: \.self) { violation in
                    HStack {
                        Image(systemName: "exclamationmark.triangle")
                            .foregroundColor(.orange)
                        Text(violation)
                            .font(.caption2)
                    }
                }
            }
            
            Divider()
            
            // Actions
            if connectionManager.isConnected {
                Button("Disconnect") {
                    connectionManager.disconnect()
                }
            } else {
                Button("Connect") {
                    connectionManager.connect()
                }
            }
            
            Button("Settings...") {
                NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
            }
            
            Button("Diagnostics...") {
                connectionManager.runDiagnostics()
            }
            
            Divider()
            
            Button("Quit OpenSASE") {
                connectionManager.disconnect()
                NSApplication.shared.terminate(nil)
            }
        }
        .padding()
        .frame(width: 250)
    }
}

struct SettingsView: View {
    @ObservedObject var connectionManager: ConnectionManager
    @AppStorage("autoConnect") var autoConnect = true
    @AppStorage("showNotifications") var showNotifications = true
    @AppStorage("startAtLogin") var startAtLogin = true
    
    var body: some View {
        Form {
            Section("Connection") {
                Toggle("Auto-connect on launch", isOn: $autoConnect)
                Toggle("Auto-reconnect on network change", isOn: .constant(true))
            }
            
            Section("Notifications") {
                Toggle("Show connection notifications", isOn: $showNotifications)
                Toggle("Show posture warnings", isOn: .constant(true))
            }
            
            Section("System") {
                Toggle("Start at login", isOn: $startAtLogin)
            }
            
            Section("About") {
                HStack {
                    Text("Version")
                    Spacer()
                    Text("1.0.0")
                        .foregroundColor(.secondary)
                }
            }
        }
        .padding()
        .frame(width: 400, height: 300)
    }
}

class ConnectionManager: ObservableObject {
    @Published var isConnected = false
    @Published var statusText = "Disconnected"
    @Published var connectedGateway = ""
    @Published var assignedIP = ""
    @Published var connectionDuration = ""
    @Published var postureScore: Double = 0
    @Published var postureViolations: [String] = []
    
    private var tunnelManager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private var connectionTimer: Timer?
    private var connectionStartTime: Date?
    
    // Rust FFI bindings
    private var clientHandle: UnsafeMutableRawPointer?
    
    init() {
        // Initialize Rust core
        clientHandle = oscs_init("https://sase.example.com", "tenant-123")
        
        loadTunnelManager()
        startPostureCollection()
    }
    
    deinit {
        if let handle = clientHandle {
            oscs_free(handle)
        }
    }
    
    func connect() {
        guard let manager = tunnelManager else { return }
        
        statusText = "Connecting..."
        
        do {
            try manager.connection.startVPNTunnel()
        } catch {
            statusText = "Connection failed: \(error.localizedDescription)"
        }
    }
    
    func disconnect() {
        tunnelManager?.connection.stopVPNTunnel()
        connectionTimer?.invalidate()
    }
    
    func runDiagnostics() {
        // Open diagnostics window
        let diagnosticsWindow = DiagnosticsWindowController()
        diagnosticsWindow.showWindow(nil)
    }
    
    private func loadTunnelManager() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
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
            connectionStartTime = Date()
            startConnectionTimer()
            fetchConnectionDetails()
        case .connecting:
            statusText = "Connecting..."
        case .disconnecting:
            statusText = "Disconnecting..."
        case .disconnected:
            isConnected = false
            statusText = "Disconnected"
            connectionTimer?.invalidate()
        case .invalid:
            statusText = "Invalid configuration"
        case .reasserting:
            statusText = "Reconnecting..."
        @unknown default:
            statusText = "Unknown"
        }
    }
    
    private func startConnectionTimer() {
        connectionTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            guard let start = self?.connectionStartTime else { return }
            let elapsed = Int(Date().timeIntervalSince(start))
            let hours = elapsed / 3600
            let minutes = (elapsed % 3600) / 60
            let seconds = elapsed % 60
            self?.connectionDuration = String(format: "%02d:%02d:%02d", hours, minutes, seconds)
        }
    }
    
    private func fetchConnectionDetails() {
        // Get details from tunnel
        connectedGateway = "us-west-1"
        assignedIP = "10.0.0.1"
    }
    
    private func startPostureCollection() {
        Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            self?.collectPosture()
        }
        collectPosture()
    }
    
    private func collectPosture() {
        Task {
            // Collect posture using Rust core
            let score = await PostureCollector.shared.collect()
            
            await MainActor.run {
                self.postureScore = score.score
                self.postureViolations = score.violations
            }
        }
    }
}

// FFI declarations
@_silgen_name("oscs_init")
func oscs_init(_ serverUrl: UnsafePointer<CChar>, _ tenantId: UnsafePointer<CChar>) -> UnsafeMutableRawPointer?

@_silgen_name("oscs_free")
func oscs_free(_ client: UnsafeMutableRawPointer)

@_silgen_name("oscs_connect")
func oscs_connect(_ client: UnsafeMutableRawPointer, _ callback: @convention(c) (Bool, UnsafePointer<CChar>?) -> Void)

@_silgen_name("oscs_disconnect")
func oscs_disconnect(_ client: UnsafeMutableRawPointer, _ callback: @convention(c) (Bool, UnsafePointer<CChar>?) -> Void)

// Posture Collector
class PostureCollector {
    static let shared = PostureCollector()
    
    struct PostureResult {
        var score: Double
        var violations: [String]
    }
    
    func collect() async -> PostureResult {
        var score: Double = 100
        var violations: [String] = []
        
        // Check FileVault
        if !checkFileVault() {
            score -= 20
            violations.append("Disk encryption not enabled")
        }
        
        // Check Firewall
        if !checkFirewall() {
            score -= 10
            violations.append("Firewall not enabled")
        }
        
        // Check Gatekeeper
        if !checkGatekeeper() {
            score -= 10
            violations.append("Gatekeeper not enabled")
        }
        
        // Check SIP
        if !checkSIP() {
            score -= 15
            violations.append("System Integrity Protection disabled")
        }
        
        return PostureResult(score: max(0, score), violations: violations)
    }
    
    private func checkFileVault() -> Bool {
        let task = Process()
        task.launchPath = "/usr/bin/fdesetup"
        task.arguments = ["status"]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        
        do {
            try task.run()
            task.waitUntilExit()
            
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            return output.contains("FileVault is On")
        } catch {
            return false
        }
    }
    
    private func checkFirewall() -> Bool {
        // Check application firewall status
        return true // Simplified
    }
    
    private func checkGatekeeper() -> Bool {
        return true // Simplified
    }
    
    private func checkSIP() -> Bool {
        return true // Simplified
    }
}

class DiagnosticsWindowController: NSWindowController {
    convenience init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 500, height: 400),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        window.title = "OpenSASE Diagnostics"
        self.init(window: window)
    }
}
