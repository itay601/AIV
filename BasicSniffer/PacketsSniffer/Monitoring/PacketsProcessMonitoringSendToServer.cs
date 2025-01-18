using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using PacketDotNet;
using System.Threading;
using SharpPcap;
using PacketsSniffer.Core.Database.Packets;
using PacketsSniffer.Core.Detection;
using PacketsSniffer.Monitoring.PacketAnalyzer;
using ZstdSharp.Unsafe;
using System.Text.Json.Serialization;
using Newtonsoft.Json;

namespace PacketsSniffer.Monitoring
{
    public class PacketProcessor : IDisposable
    {
        private static List<string> _capturedPackets = new List<string>();
        private readonly HttpClient _httpClient;
        private readonly string _apiEndpoint;
        
        private const int BATCH_SIZE = 1;
        private ILiveDevice _device;
        private CancellationTokenSource _cancellationTokenSource;
        private readonly object _bufferLock = new object();

        public PacketProcessor(string apiEndpoint = "http://localhost:5000/v1/api/packets/packets-service")
        {
            _httpClient = new HttpClient();
            _apiEndpoint = apiEndpoint;
            _cancellationTokenSource = new CancellationTokenSource();
        }

        private ILiveDevice InitializeSniffDevice()
        {
            var devices = CaptureDeviceList.Instance;
            if (devices.Count < 1)
            {
                throw new Exception("No devices found. Make sure you have the necessary permissions.");
            }
            int deviceIndex = 4; // You might want to make this configurable
            return devices[deviceIndex];
        }

        public async Task StartMonitoring(int intervalSeconds = 60)
        {
            try
            {
                _device = InitializeSniffDevice();
                _device.Open(DeviceModes.Promiscuous);
                // Temporary counter for packets
                int currentPacketCount = 0;
                // Event handler for snapshot
                PacketArrivalEventHandler snapshotHandler = (sender, e) =>
                {
                    if (currentPacketCount < BATCH_SIZE)
                    {
                        PacketArrivalEventHandler(sender ,e);
                        currentPacketCount++;
                    }
                    else
                    {
                        _device.StopCapture();
                    }
                };
                // Start capturing packets
                _device.OnPacketArrival += snapshotHandler;
                _device.StartCapture();

                Console.WriteLine($"Starting capture on {_device.Description}...");
                //await FlushPackets();
                while (!_cancellationTokenSource.Token.IsCancellationRequested)
                {
                    await Task.Delay(TimeSpan.FromSeconds(intervalSeconds), _cancellationTokenSource.Token);
                    await FlushPackets();
                }
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("Monitoring cancelled.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in monitoring: {ex.Message}");
                throw;
            }
        }

        public async Task StopMonitoring()
        {
            _cancellationTokenSource.Cancel();
            if (_device != null)
            {
                _device.StopCapture();
                _device.Close();
            }
            await FlushPackets();
        }

        private void PacketArrivalEventHandler(object sender, PacketCapture e)
        {
            try
            {
                var rawPacket = e.GetPacket();
                if (rawPacket == null) return;

                var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                if (packet == null) return;

                var packetData = CreatePacketData(packet, rawPacket);

                // Serialize the dictionary to JSON
                string json = JsonConvert.SerializeObject(packetData, Formatting.Indented);

                // Send 'json' to the backend
                // Example: backend.Send(json);

                // If you still need to store the text representation
                _capturedPackets.Add(json);

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing packet: {ex.Message}");
            }
        }

        private async Task FlushPackets()
        {
            if (_capturedPackets.Any())
            {
                await SendPacketsToBackend(_capturedPackets);
                _capturedPackets.Clear();
            }
        }
        /// <summary>
        /// TODO
        /// </summary>
        /// <param name="packets"></param>
        /// <returns></returns>
        private async Task SendPacketsToBackend(List<String> packets)
        {
            //Console.WriteLine(packets);
            Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(packets));
            try
            {
                var json = System.Text.Json.JsonSerializer.Serialize(packets);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync(_apiEndpoint, content);

                if (!response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"Failed to send packets: {response.StatusCode}");
                    // Implement retry logic here if needed
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending packets to backend: {ex.Message}");
            }
        }
        
        private Dictionary<string, object> CreatePacketData(Packet packet, RawCapture rawPacket)
        {
            var packetData = new Dictionary<string, object>();

            // Layer 2 - Ethernet
            var ethernetPacket = packet.Extract<EthernetPacket>();
            if (ethernetPacket != null)
            {
                packetData["Ethernet"] = new
                {
                    SourceHardwareAddress = ethernetPacket.SourceHardwareAddress.ToString(),
                    DestinationHardwareAddress = ethernetPacket.DestinationHardwareAddress.ToString(),
                    Type = ethernetPacket.Type.ToString()
                };
            }

            // Layer 3 - Network
            packetData["Layer3"] = new Dictionary<string, object>();
            var ipPacket = packet.Extract<IPPacket>();
            if (ipPacket != null)
            {
                (packetData["Layer3"] as Dictionary<string, object>)["IPPacket"] = new
                {
                    SourceAddress = ipPacket.SourceAddress.ToString(),
                    DestinationAddress = ipPacket.DestinationAddress.ToString(),
                    Protocol = ipPacket.Protocol.ToString(),
                    TimeToLive = ipPacket.TimeToLive
                };
            }

            // Layer 4 - Transport
            packetData["Layer4"] = new Dictionary<string, object>();
            var tcpPacket = packet.Extract<TcpPacket>();
            if (tcpPacket != null)
            {
                (packetData["Layer4"] as Dictionary<string, object>)["TCP"] = new
                {
                    SourcePort = tcpPacket.SourcePort,
                    DestinationPort = tcpPacket.DestinationPort,
                    Flags = PacketSniffer.GetTcpFlagDescription(tcpPacket),
                    SequenceNumber = tcpPacket.SequenceNumber,
                    AcknowledgmentNumber = tcpPacket.AcknowledgmentNumber
                };

                // Layer 5 - Session
                (packetData["Layer4"] as Dictionary<string, object>)["Session"] = new
                {
                    Information = "Session information derived from TCP flags and sequence numbers",
                    TCPState = tcpPacket.Synchronize ? "Connection establishment" : "Data transfer"
                };

                // Vulnerabilities
                if (PacketSniffer.DetectSSH(tcpPacket))
                {
                    (packetData["Layer4"] as Dictionary<string, object>)["PotentialSSHConnection"] = true;
                }

                var dnsAnalyzer = new DNSThreatPacketsAnalyzer();
                dnsAnalyzer.DNSAnalyzePacket(tcpPacket);

                if (tcpPacket.DestinationPort == 80 || tcpPacket.SourcePort == 443)
                {
                    var httpAnalyzer = new HttpPacketAnalyzer();
                    httpAnalyzer.AnalyzePacketHTTP(tcpPacket);
                }
            }

            var udpPacket = packet.Extract<UdpPacket>();
            if (udpPacket != null)
            {
                (packetData["Layer4"] as Dictionary<string, object>)["UDP"] = new
                {
                    SourcePort = udpPacket.SourcePort,
                    DestinationPort = udpPacket.DestinationPort
                };

                var dnsAnalyzer = new DNSThreatPacketsAnalyzer();
                dnsAnalyzer.DNSAnalyzePacket(udpPacket);
            }

            var icmpPacket = packet.Extract<IcmpV4Packet>();
            if (icmpPacket != null)
            {
                (packetData["Layer4"] as Dictionary<string, object>)["ICMP"] = new
                {
                    Type = icmpPacket.GetType().Name,
                    Code = icmpPacket.TypeCode.ToString()
                };
            }

            // DHCP Packet Detailed Analysis
            var dhcpPacket = packet.Extract<DhcpV4Packet>();
            if (dhcpPacket != null)
            {
                packetData["DHCP"] = new
                {
                    Operation = dhcpPacket.Operation.ToString(),
                    ClientIPAddress = dhcpPacket.ClientAddress.ToString(),
                    YourIPAddress = dhcpPacket.YourAddress.ToString(),
                    ServerIPAddress = dhcpPacket.ServerAddress.ToString(),
                    GatewayIPAddress = dhcpPacket.GatewayAddress.ToString(),
                    MessageType = dhcpPacket.MessageType.ToString(),
                    TransactionID = dhcpPacket.TransactionId.ToString("X8"),
                    Options = dhcpPacket.GetOptions().Select(option => new
                    {
                        OptionType = option.OptionType.ToString(),
                        Data = option.Data.ToString()
                    }).ToList()
                };
            }

            // Payload Analysis
            var payloadPacket = packet.Extract<IPv4Packet>();
            if (payloadPacket != null)
            {
                packetData["Payload"] = new
                {
                    Length = payloadPacket.Bytes.Length,
                    Hex = BitConverter.ToString(payloadPacket.Bytes).Replace("-", " "),
                    ASCII = System.Text.Encoding.ASCII.GetString(payloadPacket.Bytes.Where(b => b >= 32 && b < 127).ToArray())
                };
            }

            // General Packet Metadata
            packetData["Metadata"] = new
            {
                PacketTimestamp = rawPacket.Timeval.Date.ToString(),
                PacketLength = rawPacket.Data.Length
            };

            return packetData;
        }


        private static string GetDhcpOptions(DhcpV4Packet dhcpPacket)
        {
            if (dhcpPacket == null) return string.Empty;

            var options = dhcpPacket.GetOptions()
                .Select(o => $"{o.OptionType}: {BitConverter.ToString(o.Data)}");
            return string.Join("; ", options);
        }

        private static string GetAsciiPayload(byte[] bytes)
        {
            if (bytes == null) return string.Empty;

            return new string(bytes
                .Where(b => b >= 32 && b < 127)
                .Select(b => (char)b)
                .ToArray());
        }


        private static string GetTcpFlagDescription(TcpPacket tcpPacket)
        {
            if (tcpPacket == null) return string.Empty;

            var flags = new List<string>();
            if (tcpPacket.Synchronize) flags.Add("SYN");
            if (tcpPacket.Acknowledgment) flags.Add("ACK");
            if (tcpPacket.Push) flags.Add("PSH");
            if (tcpPacket.Finished) flags.Add("FIN");
            if (tcpPacket.Reset) flags.Add("RST");
            if (tcpPacket.Urgent) flags.Add("URG");

            return string.Join(", ", flags);
        }

        public void Dispose()
        {
            _cancellationTokenSource?.Cancel();
            _device?.Close();
            _httpClient?.Dispose();
            _cancellationTokenSource?.Dispose();
        }
    }
}