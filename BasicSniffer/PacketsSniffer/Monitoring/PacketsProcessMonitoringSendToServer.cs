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
using System.Net.Mail;
using Quartz;

namespace PacketsSniffer.Monitoring
{
    public class PacketProcessor : IDisposable , IJob
    {
        private static List<Packetss> _capturedPackets = new List<Packetss>();
        private readonly HttpClient _httpClient;
        private readonly string _apiEndpoint;
        private volatile bool _isMonitoring = false;

        private const int BATCH_SIZE = 1;
        private ILiveDevice _device;
        private CancellationTokenSource _cancellationTokenSource;
       

        public PacketProcessor(string apiEndpoint = "http://localhost:5000/packets/packets-service")
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

        //private possicle.....
        public async Task StartMonitoring(int intervalSeconds = 60)
        {
            try
            {
                _isMonitoring = true;
                _device = InitializeSniffDevice();
                _device.Open(DeviceModes.Promiscuous);
                

                Console.WriteLine($"Starting capture on {_device.Description}...");
                //await FlushPackets();
                while (_isMonitoring == true)
                {
                    // Temporary counter for packets
                    int currentPacketCount = 0;
                    // Event handler for snapshot
                    PacketArrivalEventHandler snapshotHandler = (sender, e) =>
                    {
                        if (currentPacketCount < BATCH_SIZE)
                        {
                            PacketArrivalEventHandler(sender, e);
                            currentPacketCount++;
                        }
                        else
                        {
                            _device.StopCapture();
                        }
                    };
                    // Start capturing packets
                    _device.OnPacketArrival += snapshotHandler;
              
                    // Start capturing packets
                    _device.StartCapture();

                    // Wait for the interval to elapse
                    await Task.Delay(TimeSpan.FromSeconds(intervalSeconds), _cancellationTokenSource.Token);

                    // Flush packets or perform your additional logic here
                    await FlushPackets();
                    _device.StopCapture();
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
            finally
            {
                _device.OnPacketArrival -= PacketArrivalEventHandler;
                _device.StopCapture();
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
        }

        private void PacketArrivalEventHandler(object sender, PacketCapture e)
        {
            try
            {
                var rawPacket = e.GetPacket();
                if (rawPacket == null) return;

                var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                if (packet == null) return;

                var packetData = CreatePacket(packet, rawPacket);

                Console.WriteLine($"PacketArrival: {packetData}");
                packetData.DisplayPacket();
                // If you still need to store the text representation
                _capturedPackets.Add(packetData);

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
        private async Task SendPacketsToBackend(List<Packetss> packets)
        {
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
                else
                {
                    Console.WriteLine("sc: 200");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending packets to backend: {ex.Message}");
            }
        }
        private Packetss CreatePacket(Packet packet, RawCapture rawPacket)
        {
            var packetss = new Packetss();

            // Layer 2 - Ethernet
            var ethernetPacket = packet.Extract<EthernetPacket>();
            if (ethernetPacket != null)
            {
                packetss.Layer2_DataLink_SourceMAC = ethernetPacket.SourceHardwareAddress.ToString();
                packetss.Layer2_DataLink_DestinationMAC = ethernetPacket.DestinationHardwareAddress.ToString();
                packetss.Layer2_DataLink_EthernetType = ethernetPacket.Type.ToString();
            }

            // Layer 3 - Network
            var ipPacket = packet.Extract<IPPacket>();
            if (ipPacket != null)
            {
                packetss.Layer3_Network_SourceIP = ipPacket.SourceAddress.ToString();
                packetss.Layer3_Network_DestinationIP = ipPacket.DestinationAddress.ToString();
                packetss.Layer3_Network_Protocol = ipPacket.Protocol.ToString();
                packetss.Layer3_Network_TimeToLive = ipPacket.TimeToLive;
            }

            // Layer 4 - Transport (TCP)
            var tcpPacket = packet.Extract<TcpPacket>();
            if (tcpPacket != null)
            {
                packetss.Layer4_Transport_SourcePort = tcpPacket.SourcePort;
                packetss.Layer4_Transport_DestinationPort = tcpPacket.DestinationPort;
                packetss.Layer4_Transport_TCPFlags = PacketSniffer.GetTcpFlagDescription(tcpPacket);
                packetss.Layer4_Transport_SequenceNumber = tcpPacket.SequenceNumber;
                packetss.Layer4_Transport_AcknowledgementNumber = tcpPacket.AcknowledgmentNumber;

                // Layer 5 - Session
                packetss.Layer5_Session_TCPState = tcpPacket.Synchronize ? "Connection establishment" : "Data transfer";
            }

            // Layer 4 - Transport (UDP)
            var udpPacket = packet.Extract<UdpPacket>();
            if (udpPacket != null)
            {
                packetss.Layer4_Transport_UDP_SourcePort = udpPacket.SourcePort;
                packetss.Layer4_Transport_UDP_DestinationPort = udpPacket.DestinationPort;
            }
            // Vulnerabilities
            if (PacketSniffer.DetectSSH(tcpPacket))
            {
                packetss.SSHdetected = true;
            }

            var dnsAnalyzer = new DNSThreatPacketsAnalyzer();
            dnsAnalyzer.DNSAnalyzePacket(tcpPacket);

            if (tcpPacket.DestinationPort == 80 || tcpPacket.SourcePort == 443)
            {
                var httpAnalyzer = new HttpPacketAnalyzer();
                httpAnalyzer.AnalyzePacketHTTP(tcpPacket);
            }


            // ICMP
            var icmpPacket = packet.Extract<IcmpV4Packet>();
            if (icmpPacket != null)
            {
                packetss.Layer3_ICMP_TypeCode = icmpPacket.TypeCode.ToString();
            }

            // DHCP
            var dhcpPacket = packet.Extract<DhcpV4Packet>();
            if (dhcpPacket != null)
            {
                packetss.Layer3_DHCP_Operation = (int)dhcpPacket.Operation;
                packetss.Layer3_DHCP_ClientAddress = dhcpPacket.ClientAddress.ToString();
                packetss.Layer3_DHCP_YourAddress = dhcpPacket.YourAddress.ToString();
                packetss.Layer3_DHCP_ServerAddress = dhcpPacket.ServerAddress.ToString();
                packetss.Layer3_DHCP_GatewayAddress = dhcpPacket.GatewayAddress.ToString();
                packetss.Layer3_DHCP_MessageType = dhcpPacket.MessageType.ToString();
                packetss.Layer3_DHCP_TransactionId = dhcpPacket.TransactionId.ToString("X8");
                packetss.Layer3_DHCP_Options = string.Join(", ", dhcpPacket.GetOptions().Select(option =>
                    $"{option.OptionType}: {option.Data}"));
            }

            // Payload Analysis
            var payloadPacket = packet.Extract<IPv4Packet>();
            if (payloadPacket != null)
            {
                packetss.Payload_Length = payloadPacket.Bytes.Length.ToString();
                packetss.Payload_Hex = BitConverter.ToString(payloadPacket.Bytes).Replace("-", " ");
                packetss.Payload_ASCII = System.Text.Encoding.ASCII.GetString(
                    payloadPacket.Bytes.Where(b => b >= 32 && b < 127).ToArray());
            }

            // Metadata
            packetss.Packet_Timestamp = rawPacket.Timeval.Date.ToString();
            packetss.Packet_Length = rawPacket.Data.Length.ToString();

            return packetss;
        }

        /// <summary>
        /// make use or delete
        /// </summary>
        /// <param ></param>
        /// <returns></returns>
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



        ////////////////////////////
        public Task Execute(IJobExecutionContext context)
        {
            StartMonitoring();
            Console.WriteLine("Task executed at: " + DateTime.Now);
            return Task.CompletedTask;
        }
    }
}