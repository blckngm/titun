using titun_windows_gui;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Net;

namespace titun_windows_gui.Tests
{
    [TestClass()]
    public class NetworkConfigManagerTests
    {
        [TestMethod()]
        public void IsInNetworkTest()
        {
            var a = IPAddress.Parse("192.168.33.7");
            var n = IPAddress.Parse("192.168.33.0");
            var prefix = 24U;
            Assert.IsTrue(NetworkConfigManager.IsInNetwork(a, n, prefix));

            var n1 = IPAddress.Parse("192.168.34.0");
            Assert.IsFalse(NetworkConfigManager.IsInNetwork(a, n1, prefix));
        }

        [TestMethod()]
        public void IsSubNetworkTest()
        {
            var n = IPAddress.Parse("192.168.33.0");
            var n1 = IPAddress.Parse("192.168.0.0");
            Assert.IsTrue(NetworkConfigManager.IsSubNetwork(n, 24, n1, 16));

            var n2 = IPAddress.Parse("192.167.0.0");
            Assert.IsFalse(NetworkConfigManager.IsSubNetwork(n, 24, n2, 16));

            var n3 = IPAddress.Parse("192.168.33.9");
            Assert.IsTrue(NetworkConfigManager.IsSubNetwork(n3, 30, n, 24));
            Assert.IsFalse(NetworkConfigManager.IsSubNetwork(n, 24, n3, 30));
        }
    }
}
