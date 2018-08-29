using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

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

        public string has_psk
        {
            get => preshared_key ? "yes" : "no";
        }

        public string persistent_keepalive_interval_shown
        {
            get => persistent_keepalive_interval != null && persistent_keepalive_interval > 0 ? "Every " + persistent_keepalive_interval.ToString() + " secs" : "no";
        }

        public string rx_bytes_shown
        {
            get => SizeSuffix(rx_bytes ?? 0);
        }

        public string tx_bytes_shown
        {
            get => SizeSuffix(tx_bytes ?? 0);
        }

        public string last_handshake_shown
        {
            get
            {
                if (last_handshake_time != null)
                {
                    return FromUnixTime((long)last_handshake_time).ToLocalTime().ToString();
                }
                else
                {
                    return "";
                }
            }
        }

        public string allowed_ips_shown
        {
            get => string.Join(", ", allowed_ips);
        }

        public static DateTime FromUnixTime(long unixTime)
        {
            return epoch.AddSeconds(unixTime);
        }
        private static readonly DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        static readonly string[] SizeSuffixes =
                   { "bytes", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB" };
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
                            status.public_key = await MainWindow.CalculatePublicKey(Convert.ToBase64String(DecodeHex(v)));
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