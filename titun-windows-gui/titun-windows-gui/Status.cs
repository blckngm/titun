using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using System.Windows;

namespace titun_windows_gui
{
#pragma warning disable IDE1006
    public class Status
    {
        public string public_key { get; set; }
        public ushort listen_port { get; set; }
        public List<PeerStatus> peers { get; set; } = new List<PeerStatus>();
    }

    public class PeerStatus
    {
        public string public_key { get; set; }
        public string endpoint { get; set; }
        public bool preshared_key { get; set; }
        public ulong? last_handshake_time { get; set; }
        public ulong? rx_bytes { get; set; }
        public ulong? tx_bytes { get; set; }
        public ushort? persistent_keepalive_interval { get; set; }
        public List<string> allowed_ips { get; set; } = new List<string>();

        public string public_key_shown
        {
            get => public_key;
        }

        public Visibility preshared_key_visibility
        {
            get => preshared_key ? Visibility.Visible : Visibility.Collapsed;
        }

        public Visibility persistent_keepalive_visibility
        {
            get => persistent_keepalive_interval != null && persistent_keepalive_interval > 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        public string persistent_keepalive_interval_shown
        {
            get => "every " + HumanTime(TimeSpan.FromSeconds((double)persistent_keepalive_interval));
        }

        public string transfer_shown
        {
            get => SizeSuffix(rx_bytes ?? 0) + " received, " + SizeSuffix(tx_bytes ?? 0) + " sent";
        }

        public Visibility last_handshake_visibility
        {
            get => last_handshake_time != null ? Visibility.Visible : Visibility.Collapsed;
        }

        public string last_handshake_shown
        {
            get
            {
                if (last_handshake_time != null)
                {
                    var t = DateTimeOffset.FromUnixTimeSeconds((long)last_handshake_time);
                    var timeToNow = DateTimeOffset.Now.Subtract(t);
                    if (timeToNow.TotalSeconds >= 1)
                    {
                        return HumanTime(timeToNow) + " ago";
                    }
                    else
                    {
                        return "just now";
                    }
                }
                else
                {
                    return "";
                }
            }
        }

        private static string HumanTime(TimeSpan timeSpan)
        {
            var results = new List<string>();
            var hours = (int)timeSpan.TotalHours;
            if (hours > 0)
            {
                if (hours > 1)
                {
                    results.Add(hours + " hours");
                }
                else
                {
                    results.Add(hours + " hour");
                }
            }
            if (timeSpan.Minutes > 0)
            {
                if (timeSpan.Minutes > 1)
                {
                    results.Add(timeSpan.Minutes + " minutes");
                }
                else
                {
                    results.Add(timeSpan.Minutes + " minute");
                }
            }
            if (timeSpan.Seconds > 0)
            {
                if (timeSpan.Seconds > 1)
                {
                    results.Add(timeSpan.Seconds + " seconds");
                }
                else
                {
                    results.Add(timeSpan.Seconds + " second");
                }
            }

            return String.Join(", ", results);
        }

        public string allowed_ips_shown
        {
            get => string.Join(", ", allowed_ips);
        }

        static readonly string[] SizeSuffixes =
                   { "B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB" };
        static string SizeSuffix(ulong value, int decimalPlaces = 1)
        {
            if (decimalPlaces < 0) { throw new ArgumentOutOfRangeException("decimalPlaces"); }
            if (value == 0) { return string.Format("{0:n" + decimalPlaces + "} bytes", 0); }

            // mag is 0 for bytes, 1 for KB, 2, for MB, etc.
            int mag = (int)Math.Log(value, 1024);

            // 1L << (mag * 10) == 2 ^ (10 * mag) 
            // [i.e. the number of bytes in the unit corresponding to mag]
            decimal adjustedSize = (decimal)value / (1L << (mag * 10));

            // make adjustment when the value is large enough that
            // it would round up to 1000 or more
            if (Math.Round(adjustedSize, decimalPlaces) >= 1000)
            {
                mag += 1;
                adjustedSize /= 1024;
            }

            return string.Format("{0:n" + decimalPlaces + "} {1}",
                adjustedSize,
                SizeSuffixes[mag]);
        }
    }

    public class LookAheadReader : IDisposable
    {
        private StreamReader reader;
        private string lookAhead;

        public LookAheadReader(Stream s)
        {
            reader = new StreamReader(s);
        }

        public void Dispose()
        {
            reader.Dispose();
        }

        public async Task<string> Next()
        {
            if (lookAhead != null)
            {
                var result = lookAhead;
                lookAhead = null;
                return result;
            }
            return await reader.ReadLineAsync();
        }

        public void PutBack(string line)
        {
            if (lookAhead != null)
            {
                throw new Exception("lookAhead is not null");
            }
            lookAhead = line;
        }
    }

    public class StatusParser
    {
        private static string CachedPrivateKey = null;
        private static string CachedPublicKey = null;

        private static async Task<string> GetOrCalculatePublicKey(string private_key) {
            if(CachedPrivateKey == private_key)
            {
                return CachedPublicKey;
            }
            CachedPrivateKey = null;
            CachedPublicKey = await MainWindow.CalculatePublicKey(private_key);
            CachedPrivateKey = private_key;
            return CachedPublicKey;
        }

        public static async Task<Status> Parse(Stream stream)
        {
            var status = new Status();
            using (var reader = new LookAheadReader(stream))
            {
                while (true)
                {
                    var line = await reader.Next();
                    if (line == null || line == "")
                    {
                        break;
                    }
                    var parts = line.Split('=');
                    var k = parts[0];
                    var v = parts[1].Trim();
                    switch (k)
                    {
                        case "private_key":
                            status.public_key = await GetOrCalculatePublicKey(Convert.ToBase64String(DecodeHex(v)));
                            continue;
                        case "listen_port":
                            status.listen_port = ushort.Parse(v);
                            continue;
                        case "public_key":
                            reader.PutBack(line);
                            var peer = await ParsePeer(reader);
                            status.peers.Add(peer);
                            continue;
                        case "errno":
                            goto end;
                        default:
                            throw new Exception($"Unrecognized key {k}");
                    }
                }
            }
            end:
            return status;
        }

        private static byte[] DecodeHex(string hex)
        {
            byte[] raw = new byte[hex.Length / 2];
            for (int i = 0; i < raw.Length; i++)
            {
                raw[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return raw;
        }

        private async static Task<PeerStatus> ParsePeer(LookAheadReader reader)
        {
            var peer = new PeerStatus();
            while (true)
            {
                var line = await reader.Next();
                if (line == null || line == "")
                {
                    break;
                }
                if (peer.public_key != null && line.StartsWith("public_key"))
                {
                    reader.PutBack(line);
                    break;
                }
                var parts = line.Split('=');
                var k = parts[0];
                var v = parts[1].Trim();
                switch (k)
                {
                    case "public_key":
                        peer.public_key = Convert.ToBase64String(DecodeHex(v));
                        continue;
                    case "endpoint":
                        peer.endpoint = v;
                        continue;
                    case "preshared_key":
                        peer.preshared_key = true;
                        continue;
                    case "allowed_ip":
                        peer.allowed_ips.Add(v);
                        continue;
                    case "rx_bytes":
                        peer.rx_bytes = ulong.Parse(v);
                        continue;
                    case "tx_bytes":
                        peer.tx_bytes = ulong.Parse(v);
                        continue;
                    case "persistent_keepalive_interval":
                        peer.persistent_keepalive_interval = ushort.Parse(v);
                        continue;
                    case "last_handshake_time_sec":
                        peer.last_handshake_time = ulong.Parse(v);
                        continue;
                    case "last_handshake_time_nsec":
                        // We do not use this.
                        continue;
                    default:
                        reader.PutBack(line);
                        goto end;
                }
            }
            end:
            return peer;
        }
    }
#pragma warning restore IDE1006
}