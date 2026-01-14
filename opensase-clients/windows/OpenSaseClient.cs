// OpenSASE Windows Client - C# / WPF
// /src/client/windows/OpenSaseClient/MainWindow.xaml.cs

using System;
using System.Windows;
using System.Windows.Controls;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Runtime.InteropServices;

namespace OpenSase.Client.Windows
{
    /// <summary>
    /// Main window for OpenSASE Windows client
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly OpenSaseService _service;
        private readonly NotifyIcon _trayIcon;
        
        // P/Invoke to Rust core library
        [DllImport("opensase_client.dll")]
        private static extern IntPtr oscs_init(string serverUrl, string tenantId);
        
        [DllImport("opensase_client.dll")]
        private static extern void oscs_free(IntPtr client);
        
        [DllImport("opensase_client.dll")]
        private static extern void oscs_connect(IntPtr client, ConnectCallback callback);
        
        [DllImport("opensase_client.dll")]
        private static extern void oscs_disconnect(IntPtr client, ConnectCallback callback);
        
        [DllImport("opensase_client.dll")]
        private static extern int oscs_get_state(IntPtr client);
        
        [DllImport("opensase_client.dll")]
        private static extern IntPtr oscs_get_status_json(IntPtr client);
        
        private delegate void ConnectCallback(bool success, IntPtr error);
        
        private IntPtr _clientHandle;
        
        public MainWindow()
        {
            InitializeComponent();
            
            // Initialize Rust core
            _clientHandle = oscs_init("https://sase.example.com", "tenant-123");
            
            _service = new OpenSaseService(_clientHandle);
            _service.StatusChanged += OnStatusChanged;
            _service.PostureChanged += OnPostureChanged;
            
            InitializeTrayIcon();
            
            // Start minimized to tray
            this.WindowState = WindowState.Minimized;
            this.ShowInTaskbar = false;
        }
        
        private void InitializeTrayIcon()
        {
            _trayIcon = new NotifyIcon
            {
                Icon = Properties.Resources.TrayIconDisconnected,
                Visible = true,
                Text = "OpenSASE - Disconnected"
            };
            
            _trayIcon.DoubleClick += (s, e) => ShowWindow();
            
            var contextMenu = new ContextMenuStrip();
            contextMenu.Items.Add("Connect", null, async (s, e) => await Connect());
            contextMenu.Items.Add("Disconnect", null, async (s, e) => await Disconnect());
            contextMenu.Items.Add("-");
            contextMenu.Items.Add("Settings", null, (s, e) => ShowSettings());
            contextMenu.Items.Add("Diagnostics", null, (s, e) => ShowDiagnostics());
            contextMenu.Items.Add("-");
            contextMenu.Items.Add("Exit", null, (s, e) => ExitApplication());
            
            _trayIcon.ContextMenuStrip = contextMenu;
        }
        
        private async Task Connect()
        {
            try
            {
                StatusText.Text = "Connecting...";
                ConnectButton.IsEnabled = false;
                
                var result = await _service.ConnectAsync();
                
                if (result.Success)
                {
                    StatusText.Text = $"Connected to {result.Gateway}";
                    _trayIcon.Icon = Properties.Resources.TrayIconConnected;
                    _trayIcon.Text = $"OpenSASE - Connected ({result.Gateway})";
                    
                    UpdateConnectionDetails(result);
                }
                else
                {
                    StatusText.Text = $"Connection failed: {result.Error}";
                    System.Windows.MessageBox.Show(result.Error, "Connection Failed", 
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            catch (Exception ex)
            {
                StatusText.Text = "Connection failed";
                System.Windows.MessageBox.Show(ex.Message, "Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                ConnectButton.IsEnabled = true;
            }
        }
        
        private async Task Disconnect()
        {
            await _service.DisconnectAsync();
            StatusText.Text = "Disconnected";
            _trayIcon.Icon = Properties.Resources.TrayIconDisconnected;
            _trayIcon.Text = "OpenSASE - Disconnected";
        }
        
        private void OnStatusChanged(object sender, ConnectionStatusEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                switch (e.Status)
                {
                    case ConnectionStatus.Connected:
                        _trayIcon.Icon = Properties.Resources.TrayIconConnected;
                        StatusIndicator.Fill = System.Windows.Media.Brushes.Green;
                        break;
                    case ConnectionStatus.Connecting:
                        _trayIcon.Icon = Properties.Resources.TrayIconConnecting;
                        StatusIndicator.Fill = System.Windows.Media.Brushes.Yellow;
                        break;
                    case ConnectionStatus.Disconnected:
                        _trayIcon.Icon = Properties.Resources.TrayIconDisconnected;
                        StatusIndicator.Fill = System.Windows.Media.Brushes.Red;
                        break;
                }
            });
        }
        
        private void OnPostureChanged(object sender, PostureEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                PostureScore.Text = $"{e.Posture.Score:F0}%";
                
                if (e.Posture.Violations.Count > 0)
                {
                    PostureWarning.Visibility = Visibility.Visible;
                    PostureWarning.Text = string.Join("\n", e.Posture.Violations);
                }
                else
                {
                    PostureWarning.Visibility = Visibility.Collapsed;
                }
            });
        }
        
        private void ShowWindow()
        {
            this.Show();
            this.WindowState = WindowState.Normal;
            this.ShowInTaskbar = true;
            this.Activate();
        }
        
        private void ShowSettings()
        {
            var settingsWindow = new SettingsWindow();
            settingsWindow.ShowDialog();
        }
        
        private void ShowDiagnostics()
        {
            var diagWindow = new DiagnosticsWindow(_service);
            diagWindow.ShowDialog();
        }
        
        private void UpdateConnectionDetails(ConnectionResult result)
        {
            GatewayLabel.Text = result.Gateway;
            IpAddressLabel.Text = result.AssignedIp;
            ConnectedSinceLabel.Text = result.ConnectedAt.ToString("g");
        }
        
        private void ExitApplication()
        {
            _service.Disconnect();
            oscs_free(_clientHandle);
            _trayIcon.Dispose();
            System.Windows.Application.Current.Shutdown();
        }
        
        protected override void OnClosed(EventArgs e)
        {
            base.OnClosed(e);
            oscs_free(_clientHandle);
            _trayIcon?.Dispose();
        }
    }
    
    public class OpenSaseService
    {
        private readonly IntPtr _clientHandle;
        
        public event EventHandler<ConnectionStatusEventArgs> StatusChanged;
        public event EventHandler<PostureEventArgs> PostureChanged;
        
        public ConnectionStatus Status { get; private set; }
        
        public OpenSaseService(IntPtr clientHandle)
        {
            _clientHandle = clientHandle;
            Status = ConnectionStatus.Disconnected;
        }
        
        public Task<ConnectionResult> ConnectAsync()
        {
            var tcs = new TaskCompletionSource<ConnectionResult>();
            
            oscs_connect(_clientHandle, (success, error) =>
            {
                if (success)
                {
                    Status = ConnectionStatus.Connected;
                    tcs.SetResult(new ConnectionResult 
                    { 
                        Success = true,
                        Gateway = "us-west-1",
                        AssignedIp = "10.0.0.1",
                        ConnectedAt = DateTime.Now
                    });
                }
                else
                {
                    var errorMsg = Marshal.PtrToStringAnsi(error);
                    tcs.SetResult(new ConnectionResult { Success = false, Error = errorMsg });
                }
            });
            
            return tcs.Task;
        }
        
        public Task DisconnectAsync()
        {
            var tcs = new TaskCompletionSource<bool>();
            
            oscs_disconnect(_clientHandle, (success, error) =>
            {
                Status = ConnectionStatus.Disconnected;
                tcs.SetResult(true);
            });
            
            return tcs.Task;
        }
        
        public void Disconnect()
        {
            DisconnectAsync().Wait();
        }
        
        [DllImport("opensase_client.dll")]
        private static extern void oscs_connect(IntPtr client, ConnectCallback callback);
        
        [DllImport("opensase_client.dll")]
        private static extern void oscs_disconnect(IntPtr client, ConnectCallback callback);
        
        private delegate void ConnectCallback(bool success, IntPtr error);
    }
    
    public enum ConnectionStatus
    {
        Disconnected,
        Connecting,
        Connected,
        Reconnecting,
        Error
    }
    
    public class ConnectionResult
    {
        public bool Success { get; set; }
        public string Gateway { get; set; }
        public string AssignedIp { get; set; }
        public DateTime ConnectedAt { get; set; }
        public string Error { get; set; }
    }
    
    public class ConnectionStatusEventArgs : EventArgs
    {
        public ConnectionStatus Status { get; set; }
    }
    
    public class PostureEventArgs : EventArgs
    {
        public DevicePosture Posture { get; set; }
    }
    
    public class DevicePosture
    {
        public double Score { get; set; }
        public List<string> Violations { get; set; } = new();
    }
}
