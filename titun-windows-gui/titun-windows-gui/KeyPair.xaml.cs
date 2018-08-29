using System.Windows;

namespace titun_windows_gui
{
    /// <summary>
    /// KeyPair.xaml 的交互逻辑
    /// </summary>
    public partial class KeyPairWindow : Window
    {
        public KeyPairWindow()
        {
            InitializeComponent();
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
