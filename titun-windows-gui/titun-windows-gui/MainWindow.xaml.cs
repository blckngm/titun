
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Forms;
using System.Windows.Input;
using System.Windows.Media;
using Nett;

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
            }
        }

        private string interfaceName;
        public string InterfaceName
        {
            get => interfaceName;
            set
            {
                interfaceName = value;
                NotifyPropertyChanged();
            }
        }

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

        private static async Task<string> CheckAndTransformConfig(string configFilePath)
        {
            var info = new ProcessStartInfo(titunPath, "check --print " + configFilePath)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using (var p = Process.Start(info))
            {
                var stdoutTask = p.StandardOutput.ReadToEndAsync();
                var stderrTask = p.StandardError.ReadToEndAsync();

                await Task.WhenAll(stdoutTask, stderrTask);

                if (stderrTask.Result.Length > 0)
                {
                    throw new Exception(stderrTask.Result);
                }
                return stdoutTask.Result;
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
                titunProcess.StandardInput.Close();
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

        private async void OnButtonRunOrStopClicked(object sender, RoutedEventArgs e)
        {
            if (titunProcess != null)
            {
                titunProcess.StandardInput.Close();
                RunOrStopButton.IsEnabled = false;
                return;
            }

            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Filter = "Interface config file (*.toml;*.conf)|*.toml;*.conf|All files (*.*)|*.*"
            };

            if (dialog.ShowDialog() == true)
            {
                var fileName = dialog.FileName;
                try
                {
                    var configToml = await CheckAndTransformConfig(fileName);

                    Run(configToml, fileName);
                }
                catch (Exception ex)
                {
                    System.Windows.MessageBox.Show(ex.Message, "Cannot read config file");
                }
            }
        }
        
        private NetworkConfigManager networkConfigManager = new NetworkConfigManager();

        private async void Run(string config, string configFilePath)
        {
            RunOrStopButton.IsEnabled = false;
            Config configObj;
            try
            {
                configObj = Toml.ReadString<Config>(config);

                var context = new ValidationContext(configObj);
                Validator.ValidateObject(configObj, context, true);
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

            var info = new ProcessStartInfo(titunPath, "-c " + configFilePath + " --exit-stdin-eof")
            {
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                UseShellExecute = false
            };
            info.EnvironmentVariables.Add("RUST_LOG", "titun=debug");
            info.EnvironmentVariables.Add("RUST_BACKTRACE", "1");
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

            var getStatusCancellationTokenSource = new CancellationTokenSource();
            var interfaceName = Path.GetFileNameWithoutExtension(configFilePath);
            task = GetStatus(getStatusCancellationTokenSource.Token, interfaceName);

            var haveRunAutoConfigure = false;
            IEnumerable<string> routes = null;

            if (configObj.Interface.Address != null)
            {
                if (Task.WaitAny(new Task[] { exitSeamophore.WaitAsync() }, 500) == -1)
                {
                    // Have not exited.
                    haveRunAutoConfigure = true;
                    outputBuffer.Post("Auto config network.");
                    await Task.Run(delegate
                    {
                        networkConfigManager.AutomaticConfig(interfaceName, configObj, outputBuffer, out routes);
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
            StatusPanel.Visibility = Visibility.Hidden;
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
        
        private async Task GetStatus(CancellationToken token, string interfaceName)
        {
            InterfaceName = interfaceName;
            while (!token.IsCancellationRequested)
            {
                try
                {
                    using (var conn = new NamedPipeClientStream($"wireguard\\{interfaceName}.sock"))
                    {
                        await conn.ConnectAsync(token);
                        using (var writer = new StreamWriter(conn, new UTF8Encoding(false), 128, true))
                        {
                            await writer.WriteAsync("get=1\n\n");
                            await writer.FlushAsync();
                        }
                        Status = await StatusParser.Parse(conn);
                        StatusPanel.Visibility = Visibility.Visible;
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
