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

        public PacketProcessor(string apiEndpoint = "http://localhost:5000/api/packets")
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
            Console.WriteLine(JsonSerializer.Serialize(packets));
            try
            {
                var json = JsonSerializer.Serialize(packets);
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
        private StringBuilder CreatePacketData(Packet packet, RawCapture rawPacket)
        {
            var packetInfo = new StringBuilder();
            var ethernetPacket = packet.Extract<EthernetPacket>();
            if (ethernetPacket != null)
            {
                packetInfo.AppendLine($"Ethernet: {ethernetPacket.SourceHardwareAddress} -> {ethernetPacket.DestinationHardwareAddress}");
                packetInfo.AppendLine($"Ethernet Type: {ethernetPacket.Type}");
            }

            packetInfo.AppendLine($"\nLayer 3 - Network:");
            // IP Packet Analysis
            var ipPacket = packet.Extract<IPPacket>();
            if (ipPacket != null)
            {
                packetInfo.AppendLine($"IP Packet: {ipPacket.SourceAddress} -> {ipPacket.DestinationAddress}");
                packetInfo.AppendLine($"IP Protocol: {ipPacket.Protocol}");
                if (ipPacket is IPv4Packet ipv4)
                {
                    packetInfo.AppendLine($"IP/IPv4Packet : Time to Live: {ipPacket.TimeToLive}");
                }
            }

            packetInfo.AppendLine($"\nLayer 4 - Transport:");
            // TCP Packet Detailed Analysis
            var tcpPacket = packet.Extract<TcpPacket>();
            if (tcpPacket != null)
            {
                packetInfo.AppendLine($"TCP Packet: {tcpPacket.SourcePort} -> {tcpPacket.DestinationPort}");
                // TCP Flags Analysis
                packetInfo.AppendLine($"TCP Flags: {PacketSniffer.GetTcpFlagDescription(tcpPacket)}");
                packetInfo.AppendLine($"Sequence Number: {tcpPacket.SequenceNumber}");
                packetInfo.AppendLine($"Acknowledgement Number: {tcpPacket.AcknowledgmentNumber}");
                //layer 5  Detailes
                packetInfo.AppendLine($"\nLayer 5 - Session:");
                packetInfo.AppendLine("* Session information derived from TCP flags and sequence numbers");
                packetInfo.AppendLine($"* TCP State: {(tcpPacket.Synchronize ? "Connection establishment" : "Data transfer")}");




                // check all posibles Vulanrbilities
                // SSH Detection
                bool isPossibleSSH = PacketSniffer.DetectSSH(tcpPacket);
                if (isPossibleSSH)
                {
                    packetInfo.AppendLine("POTENTIAL SSH CONNECTION DETECTED!");
                }


                var analyzer = new DNSThreatPacketsAnalyzer();
                analyzer.DNSAnalyzePacket(tcpPacket);
                if (tcpPacket.DestinationPort == 80 || tcpPacket.SourcePort == 443)
                {
                    var httpPacket = new HttpPacketAnalyzer();
                    httpPacket.AnalyzePacketHTTP(tcpPacket);
                }
            }

            // UDP Packet Analysis
            var udpPacket = packet.Extract<UdpPacket>();
            if (udpPacket != null)
            {
                packetInfo.AppendLine($"UDP Packet: {udpPacket.SourcePort} -> {udpPacket.DestinationPort}");
                // Initialize analyzer
                var analyzer = new DNSThreatPacketsAnalyzer();
                analyzer.DNSAnalyzePacket(udpPacket);
            }

            // ICMP Packet Analysis
            var icmpPacket = packet.Extract<IcmpV4Packet>();
            if (icmpPacket != null)
            {
                packetInfo.AppendLine($"ICMP Packet Type: {icmpPacket.GetType()}");
                packetInfo.AppendLine($"ICMP Code: {icmpPacket.TypeCode}");
            }
            // DHCP Packet Detailed Analysis
            var dhcpPacket = packet.Extract<DhcpV4Packet>();
            if (dhcpPacket != null)
            {
                packetInfo.AppendLine($"DHCP Packet Details:");
                packetInfo.AppendLine($"Operation: {dhcpPacket.Operation}");
                packetInfo.AppendLine($"Client IP Address: {dhcpPacket.ClientAddress}");
                packetInfo.AppendLine($"Your IP Address: {dhcpPacket.YourAddress}");
                packetInfo.AppendLine($"Server IP Address: {dhcpPacket.ServerAddress}");
                packetInfo.AppendLine($"Gateway IP Address: {dhcpPacket.GatewayAddress}");
                packetInfo.AppendLine($"DHCP Message Type: {dhcpPacket.MessageType}");
                packetInfo.AppendLine($"Transaction ID: {dhcpPacket.TransactionId:X8}");

                // Optional: Detailed DHCP Options
                foreach (var option in dhcpPacket.GetOptions())
                {
                    packetInfo.AppendLine($"Option {option.OptionType}: {option.Data}");
                }
            }

            // Payload Analysis
            var payloadPacket = packet.Extract<IPv4Packet>();
            if (payloadPacket != null)
            {
                string payloadHex = BitConverter.ToString(payloadPacket.Bytes).Replace("-", " ");
                string payloadAscii = System.Text.Encoding.ASCII.GetString(
                    payloadPacket.Bytes.Where(b => b >= 32 && b < 127).ToArray()
                );

                packetInfo.AppendLine($"Payload Length: {payloadPacket.Bytes.Length} bytes");
                packetInfo.AppendLine($"Payload (Hex): {payloadHex}");
                packetInfo.AppendLine($"Payload (ASCII): {payloadAscii}");
            }

            // General Packet Metadata
            packetInfo.AppendLine($"Packet Timestamp: {rawPacket.Timeval.Date}");
            packetInfo.AppendLine($"Packet Length: {rawPacket.Data.Length} bytes");
            packetInfo.AppendLine("---");

            // Output and Store
            Console.WriteLine(packetInfo.ToString());
            _capturedPackets.Add(packetInfo.ToString());
            return packetInfo;
            
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