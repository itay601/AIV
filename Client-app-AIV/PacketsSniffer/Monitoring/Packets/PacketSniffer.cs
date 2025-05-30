﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpPcap;
using PacketDotNet;
using PacketsSniffer.Core.Detection;
using DnsClient;
using System.Net;
using Org.BouncyCastle.Bcpg;
using PacketsSniffer.Monitoring.PacketAnalyzer;
namespace PacketsSniffer
{
    class PacketSniffer
    {
        // List to store captured packets
        private static List<string> capturedPackets = new List<string>();
        public static ILiveDevice SniffInstance()
        {
            // List all network interfaces
            var devices = CaptureDeviceList.Instance; //getting devices for sniffing

            if (devices.Count < 1)
            {
                Console.WriteLine("No devices found. Make sure you have the necessary permissions.");
                return null;
            }

            // Print available devices
            Console.WriteLine("Available Network Interfaces:");
            for (int i = 0; i < devices.Count; i++)
            {
                Console.WriteLine($"{i}. {devices[i].Description}");
            }

            // Select a device to sniff
            Console.Write("Enter the number of the interface to sniff: ");
            int deviceIndex = int.Parse(Console.ReadLine());
            return devices[deviceIndex];
        }

        public static void LiveCaptureOption()
        {
            LiveCapture();
        }
        private static void LiveCapture()
        {
            //choose sniff instance
            var device = SniffInstance();

            // Open the device
            device.Open(DeviceModes.Promiscuous);

            // Start capturing packets
            device.OnPacketArrival += PacketArrivalEventHandler;

            Console.WriteLine($"Starting capture on {device.Description}...");
            device.StartCapture();

            Console.WriteLine("Press any key to stop...");
            Console.ReadKey();

            // Stop the capture
            device.StopCapture();
            Console.ReadLine();
            device.Close();
        }
        public static void SnapshotCaptureOption()
        {
            SnapshotCapture();
        }
        private static void SnapshotCapture()
        {
            // choose sniff instance
            var device = SniffInstance();

            // Open the device
            device.Open(DeviceModes.Promiscuous);

            // Clear previous packets
            capturedPackets.Clear();

            Console.Write("Enter number of packets to capture: ");
            int packetCount = int.Parse(Console.ReadLine());

            // Temporary counter for packets
            int currentPacketCount = 0;

            // Event handler for snapshot
            PacketArrivalEventHandler snapshotHandler = (sender, e) =>
            {
                if (currentPacketCount < packetCount)
                {
                    ProcessPacket(e);
                    currentPacketCount++;
                }
                else
                {
                    device.StopCapture();
                }
            };
            // Start capturing packets
            device.OnPacketArrival += snapshotHandler;

            Console.WriteLine($"Capturing {packetCount} packets on {device.Description}...");
            device.StartCapture();

            // Wait for capture to complete
            while (currentPacketCount < packetCount)
            {
                System.Threading.Thread.Sleep(100);
            }

            // Display captured packets
            Console.WriteLine("\nCaptured Packets Snapshot:");
            foreach (var packet in capturedPackets)
            {
                Console.WriteLine(packet);
            }

            // Close the device
            device.Close();
        }
        private static void PacketArrivalEventHandler(object sender, PacketCapture e)
        {
            ProcessPacket(e);
        }
        private static void ProcessPacket(PacketCapture e)
        {
            try
            {
                var rawPacket = e.GetPacket();
                if (rawPacket == null) return;

                var packet = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                if (packet == null) return;

                var packetInfo = new StringBuilder();
                packetInfo.AppendLine($"-------------------------------------------------------");
                packetInfo.AppendLine($"\nLayer 2 - Data Link:");
                // Ethernet Frame Details
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
                    packetInfo.AppendLine($"TCP Flags: {GetTcpFlagDescription(tcpPacket)}");
                    packetInfo.AppendLine($"Sequence Number: {tcpPacket.SequenceNumber}");
                    packetInfo.AppendLine($"Acknowledgement Number: {tcpPacket.AcknowledgmentNumber}");
                    //layer 5  Detailes
                    packetInfo.AppendLine($"\nLayer 5 - Session:");
                    packetInfo.AppendLine("* Session information derived from TCP flags and sequence numbers");
                    packetInfo.AppendLine($"* TCP State: {(tcpPacket.Synchronize ? "Connection establishment" : "Data transfer")}");
                    
                    
                    

                    // check all posibles Vulanrbilities
                    // SSH Detection
                    bool isPossibleSSH = DetectSSH(tcpPacket);
                    if (isPossibleSSH)
                    {
                        packetInfo.AppendLine("POTENTIAL SSH CONNECTION DETECTED!");
                    }

                    
                    var analyzer = new DNSThreatPacketsAnalyzer();
                    //analyzer.DNSAnalyzePacket(tcpPacket);
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
                    //analyzer.DNSAnalyzePacket(udpPacket);
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
                capturedPackets.Add(packetInfo.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing packet: {ex.Message}");
            }
        }

        // Helper method to detect potential SSH connections
        public static bool DetectSSH(TcpPacket tcpPacket)
        {
            // SSH typically uses port 22
            bool isSSHPort = tcpPacket.SourcePort == 22 || tcpPacket.DestinationPort == 22;

            // Check for SSH protocol signature
            bool hasSSHSignature = false;
            try
            {
                var payloadBytes = tcpPacket.PayloadData;
                if (payloadBytes != null && payloadBytes.Length > 4)
                {
                    // SSH protocol typically starts with "SSH-"
                    string payloadStart = System.Text.Encoding.ASCII.GetString(payloadBytes.Take(4).ToArray());
                    hasSSHSignature = payloadStart.StartsWith("SSH-");
                }
            }
            catch { }

            return isSSHPort || hasSSHSignature;
        }

        // Helper method to describe TCP flags
        public static string GetTcpFlagDescription(TcpPacket tcpPacket)
        {
            var flags = new List<string>();

            if (tcpPacket.Synchronize) flags.Add("SYN");
            if (tcpPacket.Acknowledgment) flags.Add("ACK");
            if (tcpPacket.Finished) flags.Add("FIN");
            if (tcpPacket.Reset) flags.Add("RST");
            if (tcpPacket.Push) flags.Add("PSH");
            if (tcpPacket.Urgent) flags.Add("URG");

            return string.Join(", ", flags);
        }
    }
}