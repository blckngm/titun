using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Management.Automation;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading.Tasks.Dataflow;

namespace titun_windows_gui
{
    public class PSException : Exception
    {
        public Collection<ErrorRecord> Errs { get; private set; }

        public PSException()
        {
        }

        public PSException(Collection<ErrorRecord> errs)
        {
            Errs = errs;
        }

        public override string Message { get => string.Join(",", Errs); }
    }

    class PSCommand
    {
        private static PowerShell ps = PowerShell.Create();
        private string command;
        private Dictionary<string, object> parameters = new Dictionary<string, object>();

        private PSCommand()
        {
        }

        public static PSCommand Create(string command)
        {
            return new PSCommand()
            {
                command = command
            };
        }

        public PSCommand P(string name, object value)
        {
            parameters.Add(name, value);
            return this;
        }

        public static Collection<PSObject> InvokeScript(string script)
        {
            using (var ps = PowerShell.Create())
            {
                ps.AddScript(script);
                var result = ps.Invoke();
                var errs = ps.Streams.Error.ReadAll();
                ps.Streams.Error.Clear();
                if (errs.Count > 0)
                {
                    throw new PSException(errs);
                }
                return result;
            }
        }

        public Collection<PSObject> Invoke()
        {
            lock (ps)
            {
                ps.Commands.Clear();
                ps.AddCommand(command);
                foreach (var entry in parameters)
                {
                    ps.AddParameter("-" + entry.Key, entry.Value);
                }
                var result = ps.Invoke();
                var errs = ps.Streams.Error.ReadAll();
                ps.Streams.Error.Clear();
                if (errs.Count > 0)
                {
                    throw new PSException(errs);
                }
                return result;
            }
        }
    }

    public class NetworkConfigManager
    {
        public class BasicConfig
        {
#pragma warning disable IDE1006 // 命名样式
            public string address { get; set; }
            public uint prefix { get; set; }
            public uint? mtu { get; set; }
            public uint? metric { get; set; }
#pragma warning restore IDE1006 // 命名样式
        }

        /// <summary>
        /// Find network interface index by interface alias.
        /// </summary>
        public uint? FindInterfaceIndexByAlias(string alias)
        {
            var r = PSCommand.Create("Get-NetIpInterface")
                .P("InterfaceAlias", alias)
                .Invoke();
            if (r.Count == 0)
            {
                return null;
            }
            return Convert.ToUInt32(r[0].Members["InterfaceIndex"].Value);
        }

        /// <summary>
        /// Basic configuration of an interface.
        /// </summary>
        /// <param name="index"></param>
        /// <param name="config"></param>
        public void SetBasic(uint index, BasicConfig config)
        {
            var command = PSCommand.Create("Set-NetIpInterface")
                .P("InterfaceIndex", index);

            if (config.mtu != null)
            {
                command.P("NlMtuBytes", config.mtu);
            }

            if (config.metric != null)
            {
                command.P("InterfaceMetric", config.metric);
                command.P("AutomaticMetric", "Disabled");
            }
            else
            {
                command.P("AutomaticMetric", "Enabled");
            }
            command.Invoke();

            PSCommand.Create("Remove-NetIPAddress")
                .P("InterfaceIndex", index)
                .P("Confirm", false)
                .Invoke();
            PSCommand.Create("New-NetIPAddress")
                .P("InterfaceIndex", index)
                .P("IpAddress", config.address)
                .P("PrefixLength", config.prefix)
                .Invoke();
        }

        /// <summary>
        /// Fixate a route. Add a most specific route same as the original.
        /// </summary>
        /// <param name="destination"></param>
        public void FixateRoute(string destination)
        {
            var r = PSCommand.Create("Find-NetRoute")
                .P("RemoteIPAddress", destination)
                .Invoke();
            if (r.Count < 2)
            {
                throw new Exception($"Failed to find route to {destination}");
            }
            var index = Convert.ToUInt32(r[0].Members["InterfaceIndex"].Value);
            var nextHop = Convert.ToString(r[1].Members["NextHop"].Value).Trim();
            AddRoute(index, destination, nextHop);
        }

        private string AddPrefix(string address)
        {
            uint prefix;
            {
                var a = IPAddress.Parse(address).AddressFamily;
                if (a == AddressFamily.InterNetwork)
                {
                    prefix = 32;
                }
                else if (a == AddressFamily.InterNetworkV6)
                {
                    prefix = 128;
                }
                else
                {
                    throw new Exception($"Unexpected address family {a}");
                }
            }
            return $"{address}/{prefix}";
        }

        public void AddRoute(uint interfaceIndex, string destination, string nextHop)
        {
            string destinationWithPrefix;
            if (!destination.Contains("/"))
            {
                destinationWithPrefix = AddPrefix(destination);
            }
            else
            {
                destinationWithPrefix = destination;
            }
            var c = PSCommand.Create("New-NetRoute")
                .P("InterfaceIndex", interfaceIndex)
                .P("DestinationPrefix", destinationWithPrefix)
                .P("PolicyStore", "ActiveStore")
                .P("NextHop", nextHop);
            c.Invoke();
        }

        public void RemoveRoute(string destination)
        {
            string destinationWithPrefix;
            if (!destination.Contains("/"))
            {
                destinationWithPrefix = AddPrefix(destination);
            }
            else
            {
                destinationWithPrefix = destination;
            }
            PSCommand.Create("Remove-NetRoute")
            .P("DestinationPrefix", destinationWithPrefix)
            .P("Confirm", false)
            .Invoke();
        }

        public void SetDns(uint interfaceIndex, IEnumerable<string> dnsServers)
        {
            PSCommand.Create("Set-DnsClientServerAddress")
                .P("InterfaceIndex", interfaceIndex)
                .P("ServerAddress", dnsServers.ToArray<string>())
                .Invoke();
        }

        /// <summary>
        ///  Add windows firewall rules to block all DNS servers other than those of this interface.
        /// </summary>
        /// <param name="ourInterfaceIndex"></param>
        public void BlockOtherDNS(uint ourInterfaceIndex)
        {
            // Find their DNS Servers.
            var results = PSCommand.Create("Get-DNSClientServerAddress").Invoke();
            var addressesToBlock = new HashSet<string>();
            foreach (var r in results)
            {
                var ii = Convert.ToUInt32(r.Members["InterfaceIndex"].Value);
                var ads = r.Members["ServerAddresses"].Value as string[];
                if (ii != ourInterfaceIndex)
                {
                    foreach (var a in ads)
                    {
                        addressesToBlock.Add(a);
                    }
                }
            }
            foreach (var a in addressesToBlock)
            {
                BlockDNS(a);
            }
        }

        private void BlockDNS(string a)
        {
            PSCommand.Create("New-NetFirewallRule")
                .P("Group", "TiTunDNSBlock")
                .P("DisplayName", "Block DNS Server " + a + " UDP")
                .P("Direction", "Outbound")
                .P("Action", "Block")
                .P("RemoteAddress", a)
                .P("RemotePort", 53)
                .P("Protocol", "UDP")
                .Invoke();
            PSCommand.Create("New-NetFirewallRule")
                .P("Group", "TiTunDNSBlock")
                .P("DisplayName", "Block DNS Server " + a + " TCP")
                .P("Direction", "Outbound")
                .P("Action", "Block")
                .P("RemoteAddress", a)
                .P("RemotePort", 53)
                .P("Protocol", "TCP")
                .Invoke();
        }

        public void UnBlockDNS()
        {
            PSCommand.InvokeScript("Get-NetFirewallRule -Group TiTunDNSBlock | Remove-NetFirewallRule");
        }

        private static UInt32 IPv4ToUInt32(IPAddress a)
        {
            // XXX: Big endian hosts.
            return BitConverter.ToUInt32(a.GetAddressBytes().Reverse().ToArray(), 0);
        }

        public static bool IsInNetwork(IPAddress a, IPAddress network, uint prefix)
        {
            if (a.AddressFamily != network.AddressFamily)
            {
                return false;
            }
            if (a.AddressFamily == AddressFamily.InterNetwork)
            {
                // Ipv4.
                var aU32 = IPv4ToUInt32(a);
                var networkU32 = IPv4ToUInt32(network);
                var mask = prefix == 0 ? 0 : (~0U) << (int)(32 - prefix);
                return (aU32 & mask) == (networkU32 & mask);
            }
            // TODO: IPv6.
            return false;
        }

        /// <summary>
        /// Check whether network/prefix is a subset of network1/prefix1.
        /// </summary>
        public static bool IsSubNetwork(IPAddress network, uint prefix, IPAddress network1, uint prefix1)
        {
            if (network.AddressFamily != network1.AddressFamily)
            {
                return false;
            }
            if (network.AddressFamily == AddressFamily.InterNetwork)
            {
                // Ipv4.
                var networkU32 = IPv4ToUInt32(network);
                var network1U32 = IPv4ToUInt32(network1);
                var mask = prefix == 0 ? 0 : (~0U) << (int)(32 - prefix);
                var mask1 = prefix1 == 0 ? 0 : (~0U) << (int)(32 - prefix1);
                networkU32 &= mask;
                network1U32 &= mask1;
                return network1U32 == (networkU32 & mask1);
            }
            // TODO: IPv6.
            return false;
        }

        [MethodImpl(MethodImplOptions.Synchronized)]
        public void AutomaticConfig(Config config, BufferBlock<string> output, out IEnumerable<string> routesAdded)
        {
            var routes = new List<string>();
            void Try(string description, Action op)
            {
                output.Post(description);
                try
                {
                    op();
                    output.Post("OK.");
                }
                catch (Exception e)
                {
                    output.Post(e.ToString().Trim());
                }
            }
            uint index;
            try
            {
                index = FindInterfaceIndexByAlias(config.Interface.Name) ?? throw new Exception($"Failed to find interface {config.Interface.Name}");
            }
            catch (Exception e)
            {
                output.Post(e.Message);
                routesAdded = routes;
                return;
            }
            output.Post($"Interface index is {index}");
            Try("Set address, prefix, MTU and metric.", () =>
            {
                SetBasic(index, new BasicConfig
                {
                    address = config.Network.Address,
                    prefix = config.Network.PrefixLen,
                    mtu = config.Network.Mtu,
                    metric = config.Network.Metric
                });
            });
            // Fixate routes.
            foreach (var p in config.Peer)
            {
                if (p.Endpoint != null)
                {
                    // Fixate route if endpoint is in allowed ips.
                    var d = p.Endpoint.Split(':')[0];
                    var shouldFixate = false;
                    foreach(var r0 in p.AllowedIPs)
                    {
                        string r;
                        if (!r0.Contains('/'))
                        {
                            r = AddPrefix(r0);
                        }
                        else
                        {
                            r = r0;
                        }
                        var rr = r.Split('/');
                        var network = IPAddress.Parse(rr[0]);
                        var prefix = uint.Parse(rr[1]);
                        if (IsInNetwork(IPAddress.Parse(d), network, prefix))
                        {
                            shouldFixate = true;
                            break;
                        }
                    }
                    if (shouldFixate)
                    {
                        Try($"Fixate route to {d}.", delegate
                        {
                            FixateRoute(d);
                            routes.Add(d);
                        });
                    }
                }
            }
            // Other routes.
            foreach (var p in config.Peer)
            {
                foreach (var r in p.AllowedIPs)
                {
                    var rr = r.Split('/');
                    var network = IPAddress.Parse(rr[0]);
                    // XXX: IPv6.
                    var prefix = rr.Count() > 1 ? uint.Parse(rr[1]) : 32;
                    // Add route if it is not in interface network address/prefix.
                    if (!IsSubNetwork(network, prefix, IPAddress.Parse(config.Network.Address), config.Network.PrefixLen))
                    {
                        Try($"Add route {r}", () =>
                        {
                            AddRoute(index, r, config.Network.NextHop);
                            routes.Add(r);
                        });
                    }
                }
            }
            Try($"Set DNS servers.", () => SetDns(index, config.Network.Dns));
            if (config.Network.PreventDnsLeak)
            {
                Try($"Block other DNS servers", () => BlockOtherDNS(index));
            }
            output.Post("Done.");
            routesAdded = routes;
        }

        [MethodImpl(MethodImplOptions.Synchronized)]
        public void UndoAutomaticConfig(Config config, IEnumerable<string> routes, BufferBlock<string> output)
        {
            void Try(string description, Action op)
            {
                output.Post(description);
                try
                {
                    op();
                    output.Post("OK.");
                }
                catch (Exception e)
                {
                    output.Post(e.ToString().Trim());
                }
            }
            uint index;
            try
            {
                index = FindInterfaceIndexByAlias(config.Interface.Name) ?? throw new Exception($"Failed to find interface {config.Interface}");
            }
            catch (Exception e)
            {
                output.Post(e.Message);
                return;
            }
            // Unblock DNS.
            if (config.Network.PreventDnsLeak)
            {
                Try("Unblock DNS", () => UnBlockDNS());
            }
            // Remove routes.
            output.Post("Remove Routes.");
            foreach(var r in routes)
            {
                Try($"Remove route {r}", () => RemoveRoute(r));
            }
            output.Post("Done.");
        }
    }
}
