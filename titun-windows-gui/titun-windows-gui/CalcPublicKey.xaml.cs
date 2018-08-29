using System;
using System.Windows;

namespace titun_windows_gui
{
    /// <summary>
    /// CalcPublicKey.xaml 的交互逻辑
    /// </summary>
    public partial class CalcPublicKey : Window
    {
        public CalcPublicKey()
        {
            InitializeComponent();
        }

        private async void CalculateButton_Click(object sender, RoutedEventArgs e)
        {
            var k = KeyTextBox.Text;
            try
            {
                var pubkey = await MainWindow.CalculatePublicKey(k);
                PublicKeyTextBox.Text = pubkey;
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Failed to Calculate Public Key");
            }
        }
    }
}
