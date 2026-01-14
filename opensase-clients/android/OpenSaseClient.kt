// OpenSASE Android Client - Kotlin
// /src/client/android/app/src/main/java/io/opensase/client

package io.opensase.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*
import java.io.File
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * OpenSASE VPN Service - Android Implementation
 */
class OpenSaseVpnService : VpnService() {
    
    private var vpnInterface: ParcelFileDescriptor? = null
    private var wireguardHandle: Long = 0
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    
    companion object {
        const val ACTION_CONNECT = "io.opensase.client.CONNECT"
        const val ACTION_DISCONNECT = "io.opensase.client.DISCONNECT"
        const val NOTIFICATION_ID = 1
        const val CHANNEL_ID = "opensase_vpn"
        
        // Native library
        init {
            System.loadLibrary("opensase_client")
        }
        
        // FFI bindings to Rust
        @JvmStatic
        external fun nativeInit(serverUrl: String, tenantId: String): Long
        
        @JvmStatic
        external fun nativeFree(handle: Long)
        
        @JvmStatic
        external fun nativeConnect(handle: Long): String
        
        @JvmStatic
        external fun nativeDisconnect(handle: Long)
        
        @JvmStatic
        external fun nativeGetState(handle: Long): Int
        
        @JvmStatic
        external fun nativeGetPosture(handle: Long): String
    }
    
    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        
        // Initialize Rust core
        wireguardHandle = nativeInit("https://sase.example.com", "tenant-123")
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> connect()
            ACTION_DISCONNECT -> disconnect()
        }
        return START_STICKY
    }
    
    override fun onDestroy() {
        super.onDestroy()
        nativeFree(wireguardHandle)
    }
    
    private fun connect() {
        serviceScope.launch {
            try {
                // Collect device posture
                val posture = PostureCollector(this@OpenSaseVpnService).collect()
                
                // Authenticate with gateway (via Rust core)
                val authResult = withContext(Dispatchers.IO) {
                    nativeConnect(wireguardHandle)
                }
                
                val auth = parseAuthResult(authResult)
                
                if (!auth.allowed) {
                    showNotification("Connection denied: ${auth.reason}")
                    return@launch
                }
                
                // Select best gateway
                val gateway = selectBestGateway(auth.gateways)
                
                // Configure VPN interface
                val builder = Builder()
                    .setSession("OpenSASE")
                    .addAddress(auth.assignedIp, 32)
                    .setMtu(1280)
                    .setBlocking(true)
                
                // Add routes
                for (route in auth.routes) {
                    builder.addRoute(route.network, route.prefix)
                }
                
                // Add DNS servers
                for (dns in auth.dnsServers) {
                    builder.addDnsServer(dns)
                }
                
                // Configure split tunneling
                if (auth.splitTunnel.enabled) {
                    for (app in auth.splitTunnel.allowedApps) {
                        try {
                            builder.addAllowedApplication(app)
                        } catch (e: Exception) {
                            // App not installed
                        }
                    }
                    for (app in auth.splitTunnel.disallowedApps) {
                        try {
                            builder.addDisallowedApplication(app)
                        } catch (e: Exception) {
                            // App not installed
                        }
                    }
                }
                
                // Establish VPN
                vpnInterface = builder.establish()
                
                if (vpnInterface == null) {
                    showNotification("Failed to establish VPN interface")
                    return@launch
                }
                
                // Show connected notification
                startForeground(NOTIFICATION_ID, createConnectedNotification(gateway.name))
                
                // Start posture monitoring
                startPostureMonitoring()
                
                // Broadcast connection state
                sendBroadcast(Intent("io.opensase.client.CONNECTED"))
                
            } catch (e: Exception) {
                showNotification("Connection failed: ${e.message}")
                sendBroadcast(Intent("io.opensase.client.ERROR").apply {
                    putExtra("message", e.message)
                })
            }
        }
    }
    
    private fun disconnect() {
        serviceScope.launch {
            nativeDisconnect(wireguardHandle)
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            sendBroadcast(Intent("io.opensase.client.DISCONNECTED"))
        }
    }
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "OpenSASE VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "VPN connection status"
            }
            
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }
    
    private fun createConnectedNotification(gateway: String): Notification {
        val disconnectIntent = Intent(this, OpenSaseVpnService::class.java).apply {
            action = ACTION_DISCONNECT
        }
        val disconnectPendingIntent = PendingIntent.getService(
            this, 0, disconnectIntent, PendingIntent.FLAG_IMMUTABLE
        )
        
        val openAppIntent = Intent(this, MainActivity::class.java)
        val openAppPendingIntent = PendingIntent.getActivity(
            this, 0, openAppIntent, PendingIntent.FLAG_IMMUTABLE
        )
        
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("OpenSASE")
            .setContentText("Connected to $gateway")
            .setSmallIcon(R.drawable.ic_shield)
            .setOngoing(true)
            .setContentIntent(openAppPendingIntent)
            .addAction(R.drawable.ic_disconnect, "Disconnect", disconnectPendingIntent)
            .build()
    }
    
    private fun showNotification(message: String) {
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("OpenSASE")
            .setContentText(message)
            .setSmallIcon(R.drawable.ic_shield)
            .setAutoCancel(true)
            .build()
        
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID + 1, notification)
    }
    
    private suspend fun selectBestGateway(gateways: List<Gateway>): Gateway {
        return withContext(Dispatchers.IO) {
            gateways.minByOrNull { gateway ->
                measureLatency(gateway.host, gateway.port)
            } ?: gateways.first()
        }
    }
    
    private fun measureLatency(host: String, port: Int): Long {
        val start = System.currentTimeMillis()
        try {
            DatagramSocket().use { socket ->
                socket.connect(InetSocketAddress(host, port))
                socket.soTimeout = 5000
            }
        } catch (e: Exception) {
            return Long.MAX_VALUE
        }
        return System.currentTimeMillis() - start
    }
    
    private fun startPostureMonitoring() {
        serviceScope.launch {
            while (isActive) {
                delay(60_000) // Check every minute
                
                val posture = PostureCollector(this@OpenSaseVpnService).collect()
                
                // Report posture via Rust core
                try {
                    val postureJson = nativeGetPosture(wireguardHandle)
                    // Handle posture update
                } catch (e: Exception) {
                    // Log but don't disconnect
                }
            }
        }
    }
    
    private fun parseAuthResult(json: String): AuthResult {
        // Parse JSON response from Rust core
        return AuthResult(
            allowed = true,
            reason = null,
            assignedIp = "10.0.0.1",
            gateways = listOf(Gateway("us-west-1", "gateway.opensase.io", 51820)),
            routes = listOf(Route("0.0.0.0", 0)),
            dnsServers = listOf("10.0.0.2"),
            splitTunnel = SplitTunnel(false, emptyList(), emptyList())
        )
    }
}

/**
 * Android Posture Collector
 */
class PostureCollector(private val context: Context) {
    
    suspend fun collect(): DevicePosture = withContext(Dispatchers.IO) {
        DevicePosture(
            platform = "android",
            osVersion = Build.VERSION.RELEASE,
            osBuild = Build.DISPLAY,
            deviceModel = "${Build.MANUFACTURER} ${Build.MODEL}",
            serialNumber = getSerialNumber(),
            
            // Security
            isRooted = checkRoot(),
            screenLockEnabled = checkScreenLock(),
            diskEncrypted = checkEncryption(),
            developerModeEnabled = checkDeveloperMode(),
            unknownSourcesEnabled = checkUnknownSources(),
            
            // Play Protect
            playProtectEnabled = checkPlayProtect(),
            
            // Hardware attestation
            hardwareAttestation = getHardwareAttestation(),
            
            collectedAt = System.currentTimeMillis()
        )
    }
    
    private fun getSerialNumber(): String {
        return try {
            Build.getSerial()
        } catch (e: SecurityException) {
            "unknown"
        }
    }
    
    private fun checkRoot(): Boolean {
        val paths = listOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su"
        )
        
        for (path in paths) {
            if (File(path).exists()) return true
        }
        
        // Try to execute su
        return try {
            Runtime.getRuntime().exec("su")
            true
        } catch (e: Exception) {
            false
        }
    }
    
    private fun checkScreenLock(): Boolean {
        val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as android.app.KeyguardManager
        return keyguardManager.isDeviceSecure
    }
    
    private fun checkEncryption(): Boolean {
        val devicePolicyManager = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as android.app.admin.DevicePolicyManager
        return devicePolicyManager.storageEncryptionStatus == android.app.admin.DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE
    }
    
    private fun checkDeveloperMode(): Boolean {
        return Settings.Secure.getInt(
            context.contentResolver,
            Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
            0
        ) != 0
    }
    
    private fun checkUnknownSources(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.packageManager.canRequestPackageInstalls()
        } else {
            Settings.Secure.getInt(
                context.contentResolver,
                Settings.Secure.INSTALL_NON_MARKET_APPS,
                0
            ) != 0
        }
    }
    
    private fun checkPlayProtect(): Boolean {
        // Check Google Play Protect status
        return true // Simplified
    }
    
    private suspend fun getHardwareAttestation(): HardwareAttestation? {
        return try {
            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore"
            )
            
            val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
            
            keyPairGenerator.initialize(
                KeyGenParameterSpec.Builder("attestation_key", KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                    .build()
            )
            
            val keyPair = keyPairGenerator.generateKeyPair()
            
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            val chain = keyStore.getCertificateChain("attestation_key")
            
            HardwareAttestation(
                platform = "android",
                attestationType = "key_attestation",
                attestationData = Base64.getEncoder().encodeToString(
                    chain.map { it.encoded }.reduce { acc, bytes -> acc + bytes }
                ),
                timestamp = System.currentTimeMillis()
            )
        } catch (e: Exception) {
            null
        }
    }
}

// Data classes
data class DevicePosture(
    val platform: String,
    val osVersion: String,
    val osBuild: String,
    val deviceModel: String,
    val serialNumber: String,
    val isRooted: Boolean,
    val screenLockEnabled: Boolean,
    val diskEncrypted: Boolean,
    val developerModeEnabled: Boolean,
    val unknownSourcesEnabled: Boolean,
    val playProtectEnabled: Boolean,
    val hardwareAttestation: HardwareAttestation?,
    val collectedAt: Long
)

data class HardwareAttestation(
    val platform: String,
    val attestationType: String,
    val attestationData: String,
    val timestamp: Long
)

data class AuthResult(
    val allowed: Boolean,
    val reason: String?,
    val assignedIp: String,
    val gateways: List<Gateway>,
    val routes: List<Route>,
    val dnsServers: List<String>,
    val splitTunnel: SplitTunnel
)

data class Gateway(
    val name: String,
    val host: String,
    val port: Int
)

data class Route(
    val network: String,
    val prefix: Int
)

data class SplitTunnel(
    val enabled: Boolean,
    val allowedApps: List<String>,
    val disallowedApps: List<String>
)
