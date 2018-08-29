
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
using System.Web.Script.Serialization;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Forms;
using System.Windows.Input;
using System.Windows.Media;
using YamlDotNet.Serialization;

namespace titun_windows_gui
{
    public partial class MainWindow : Window, INotifyPropertyChanged
    {
        #region Property changed boilerplate.
        public event PropertyChangedEventHandler PropertyChanged;
        private void NotifyPropertyChanged([CallerMemberName] String propertyName = "")
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
        #endregion

        private Status status;
        public Status Status
        {
            get => status;
            set
            {
                status = value;
                NotifyPropertyChanged();
                NotifyPropertyChanged("StatusTabEnabled");
            }
        }
        public bool StatusTabEnabled { get => Status != null; }

        private BufferBlock<string> outputBuffer = new BufferBlock<string>();
        private async Task ReceiveAndDisplayOutput()
        {
            while (true)
            {
                var x = await outputBuffer.ReceiveAsync();
                if (!x.EndsWith("\n"))
                {
                    x += '\n';
                }
                var run = new Run(x);
                if (x.Contains("Exception"))
                {
                    run.Background = Brushes.LightYellow;
                }
                LogsTextBlock.Inlines.Add(run);
            }
        }

        public MainWindow()
        {
            InitializeComponent();
            DataContext = this;
            SetUpTrayIcon();

            var _task = ReceiveAndDisplayOutput();

            // Setup Ctrl-Q shortcut to exit.
            var exitCommand = new RoutedCommand();
            exitCommand.InputGestures.Add(new KeyGesture(Key.Q, ModifierKeys.Control));
            CommandBindings.Add(new CommandBinding(exitCommand, MenuItemExit_Click));
        }

        private void ClearLogButtonClick(object sender, RoutedEventArgs e)
        {
            LogsTextBlock.Text = string.Empty;
        }

        private void SaveLogButtonClick(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.SaveFileDialog()
            {
                DefaultExt = "txt"
            };
            if (dialog.ShowDialog() == true)
            {
                var log = LogsTextBlock.Text;
                try
                {
                    File.WriteAllText(dialog.FileName, log, new UTF8Encoding(false));
                }
                catch (Exception ex)
                {
                    System.Windows.MessageBox.Show(ex.Message, "Failed to save log");
                }
            }
        }

        private void CalculatePubkeyButtonClick(object sender, RoutedEventArgs e)
        {
            new CalcPublicKey()
            {
                Owner = this
            }.Show();
        }

        public class KeyPair
        {
            public string Key { get; set; }
            public string PublicKey { get; set; }
        }

        private async void GenerateKeyButtonClick(object sender, RoutedEventArgs e)
        {
            try
            {
                string key = await GenerateKey();
                string pubkey = await CalculatePublicKey(key);

                var keyPairDialog = new KeyPairWindow
                {
                    Owner = this,
                    DataContext = new KeyPair()
                    {
                        Key = key,
                        PublicKey = pubkey
                    }
                };
                keyPairDialog.Show();
            }
            catch (Exception ex)
            {
                System.Windows.MessageBox.Show(ex.Message);
            }
        }

        public static async Task<string> GenerateKey()
        {
            var info = new ProcessStartInfo(titunPath, "genkey")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using (var p = Process.Start(info))
            {
                return (await p.StandardOutput.ReadToEndAsync()).TrimEnd('\n');
            }
        }

        public static async Task<String> GetTiTunVersion()
        {
            var info1 = new ProcessStartInfo(titunPath, "--version")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using (var p = Process.Start(info1))
            {
                return (await p.StandardOutput.ReadToEndAsync()).TrimEnd();
            }
        }

        public static async Task<string> CalculatePublicKey(string key)
        {
            var info1 = new ProcessStartInfo(titunPath, "pubkey")
            {
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using (var p = Process.Start(info1))
            {
                await p.StandardInput.WriteAsync(key);
                p.StandardInput.Close();
                var stdoutTask = p.StandardOutput.ReadToEndAsync();
                var stderrTask = p.StandardError.ReadToEndAsync();

                Task.WaitAll(stdoutTask, stderrTask);

                if (stderrTask.Result.Length > 0)
                {
                    throw new Exception(stderrTask.Result);
                }
                return stdoutTask.Result.TrimEnd('\n');
            }
        }

        private void ReallyExit()
        {
            reallyExit = true;
            if (titunProcess == null)
            {
                Close();
            }
            else
            {
                titunProcess.Kill();
            }
        }

        private void MenuItemExit_Click(object sender, RoutedEventArgs e)
        {
            ReallyExit();
        }

        private void MenuItemAbout_Click(object sender, RoutedEventArgs e)
        {
            new AboutWindow()
            {
                Owner = this
            }.ShowDialog();
        }

        #region Tray icon.
        private NotifyIcon notifyIcon = new NotifyIcon();
        private bool reallyExit = false;

        private void SetUpTrayIcon()
        {
            // Minimize to tray.
            var menu = notifyIcon.ContextMenu = new ContextMenu();
            menu.MenuItems.Add("Exit", (s, e) =>
            {
                ReallyExit();
            });
            notifyIcon.Icon = Properties.Resources.Icon;
            notifyIcon.Visible = true;
            notifyIcon.Click += (s, e) =>
            {
                Show();
                WindowState = WindowState.Normal;
            };
        }

        protected override void OnClosing(CancelEventArgs e)
        {
            if (reallyExit)
            {
                base.OnClosing(e);
                return;
            }
            Hide();
            e.Cancel = true;
        }

        protected override void OnClosed(EventArgs e)
        {
            base.OnClosed(e);
            notifyIcon.Dispose();
        }
        #endregion

        #region Process lifecycle.
        private static string titunPath = AppDomain.CurrentDomain.BaseDirectory + "\\titun.exe";

        private Process titunProcess;

        private void OnButtonRunOrStopClicked(object sender, RoutedEventArgs e)
        {
            if (titunProcess != null)
            {
                titunProcess.Kill();
                return;
            }

            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Filter = "Yaml files (*.yaml;*.yml)|*.yaml;*.yml|All files (*.*)|*.*"
            };

            if (dialog.ShowDialog() == true)
            {
                var fileName = dialog.FileName;
                try
                {
                    var configStr = File.ReadAllText(fileName, Encoding.UTF8);

                    Run(configStr);
                }
                catch (Exception ex)
                {
                    System.Windows.MessageBox.Show(ex.Message, "Cannot read config file");
                }
            }
        }
        
        private NetworkConfigManager networkConfigManager = new NetworkConfigManager();

        private async void Run(string config)
        {
            RunOrStopButton.IsEnabled = false;
            Config configObj;
            try
            {
                var de = new DeserializerBuilder().IgnoreUnmatchedProperties().Build();
                configObj = de.Deserialize<Config>(config);

                var context = new ValidationContext(configObj);
                Validator.ValidateObject(configObj, context, true);

                if (configObj.auto_config && configObj.network.next_hop == null)
                {
                    throw new Exception("network.next_hop must be specified unless auto_config is false");
                }
            }
            catch (ValidationException ex)
            {
                outputBuffer.Post("Failed to validate config:\n" + ex.ValidationResult);
                RunOrStopButton.IsEnabled = true;
                return;
            }
            catch (Exception ex)
            {
                outputBuffer.Post("Failed to parse config: " + ex.ToString());
                RunOrStopButton.IsEnabled = true;
                return;
            }

            var info = new ProcessStartInfo(titunPath, $"tun \"--dev={configObj.dev_name}\" --network {configObj.network.address}/{configObj.network.prefix} --exit-stdin-eof")
            {
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                UseShellExecute = false
            };
            info.EnvironmentVariables.Add("RUST_LOG", "warn");
            var p = titunProcess = new Process()
            {
                StartInfo = info,
                EnableRaisingEvents = true
            };
            var exitSeamophore = new SemaphoreSlim(0);
            p.Exited += (s, e) =>
            {
                exitSeamophore.Release(5);
            };
            try
            {
                p.Start();
            }
            catch (Exception e)
            {
                outputBuffer.Post("Failed to start tiun: " + e.Message);
                RunOrStopButton.IsEnabled = true;
                titunProcess = null;
                return;
            }

            // Spawn but do not wait.
            var task = ReadStream(titunProcess.StandardError.BaseStream);
            task = ReadStream(titunProcess.StandardOutput.BaseStream);

            await WriteConfig(configObj);

            var getStatusCancellationTokenSource = new CancellationTokenSource();
            task = GetStatus(getStatusCancellationTokenSource.Token, configObj.dev_name);

            var haveRunAutoConfigure = false;
            IEnumerable<string> routes = null;

            if (configObj.auto_config)
            {
                if (Task.WaitAny(new Task[] { exitSeamophore.WaitAsync() }, 500) == -1)
                {
                    // Have not exited.
                    haveRunAutoConfigure = true;
                    outputBuffer.Post("Auto config network.");
                    await Task.Run(delegate
                    {
                        networkConfigManager.AutomaticConfig(configObj, outputBuffer, out routes);
                    });
                }
            }

            RunOrStopButton.IsEnabled = true;
            RunOrStopButton.Content = "Stop";
            await exitSeamophore.WaitAsync();
            RunOrStopButton.IsEnabled = false;
            outputBuffer.Post("TiTun process exited.");
            getStatusCancellationTokenSource?.Cancel();
            Status = null;
            if (haveRunAutoConfigure)
            {
                outputBuffer.Post("Undo network config");
                await Task.Run(() => networkConfigManager.UndoAutomaticConfig(configObj, routes, outputBuffer));
            }
            titunProcess.Close();
            titunProcess = null;

            RunOrStopButton.IsEnabled = true;
            RunOrStopButton.Content = "Run";

            if (reallyExit)
            {
                await Task.Delay(1000);
                Close();
            }
        }

        private async Task ReadStream(Stream stream)
        {
            using (var reader = new StreamReader(stream, new UTF8Encoding(false)))
            {
                while (true)
                {
                    var line = await reader.ReadLineAsync();
                    if (line == null)
                    {
                        return;
                    }
                    outputBuffer.Post(line);
                }
            }
        }

        private static string Base64ToHex(string s)
        {
            var data = Convert.FromBase64String(s);
            return BitConverter.ToString(data).Replace("-", string.Empty);
        }

        private async Task WriteConfig(Config config)
        {
            using (var conn = new NamedPipeClientStream($"wireguard\\{config.dev_name}.sock"))
            {
                await conn.ConnectAsync();
                // var writer = new StringWriter();
                var writer = new StreamWriter(conn, new UTF8Encoding(false), 128, true)
                {
                    NewLine = "\n"
                };
                await writer.WriteLineAsync("set=1");
                await writer.WriteLineAsync($"private_key={Base64ToHex(config.key)}");
                if (config.listen_port != null)
                {
                    await writer.WriteLineAsync($"listen_port={config.listen_port}");
                }

                foreach (var p in config.peers)
                {
                    await writer.WriteLineAsync($"public_key={Base64ToHex(p.public_key)}");
                    if (p.endpoint != null)
                    {
                        await writer.WriteLineAsync($"endpoint={p.endpoint}");
                    }
                    foreach (var a in p.allowed_ips)
                    {
                        await writer.WriteLineAsync($"allowed_ip={a}");
                    }
                }
                await writer.WriteLineAsync();
                await writer.FlushAsync();
                
                await new StreamReader(conn, new UTF8Encoding(false)).ReadToEndAsync();
            }
        }

        private async Task GetStatus(CancellationToken token, string deviceName)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    using (var conn = new NamedPipeClientStream($"wireguard\\{deviceName}.sock"))
                    {
                        await conn.ConnectAsync(token);
                        using (var writer = new StreamWriter(conn, new UTF8Encoding(false), 128, true))
                        {
                            await writer.WriteAsync("get=1\n\n");
                            await writer.FlushAsync();
                        }
                        Status = await StatusParser.Parse(conn);
                    }
                }
                catch (TaskCanceledException)
                {
                    break;
                }
                catch (Exception e)
                {
                    Console.WriteLine("Failed to get status:", e.Message);
                }
                await Task.Delay(500, token);
            }
        }
        #endregion
    }
}
