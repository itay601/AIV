using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpPcap;
using PacketDotNet;

namespace PacketsSniffer
{
    class PacketSniffer
    {
        // List to store captured packets
        private static List<string> capturedPackets = new List<string>();

        static void Main(string[] args)
        {
            Console.WriteLine("Packet Sniffer Menu:");
            Console.WriteLine("1. Live Packet Capture");
            Console.WriteLine("2. Packet Snapshot");
            Console.Write("Choose an option (1/2): ");
            string choice = Console.ReadLine();

            switch (choice)
            {
                case "1":
                    LiveCapture();
                    break;
                case "2":
                    SnapshotCapture();
                    break;
                default:
                    Console.WriteLine("Invalid option selected.");
                    return;
            }
        }

        static void LiveCapture()
        {
            // List all network interfaces
            var devices = CaptureDeviceList.Instance;
            if (devices.Count < 1)
            {
                Console.WriteLine("No devices found. Make sure you have the necessary permissions.");
                return;
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
            var device = devices[deviceIndex];

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
            device.Close();
        }

        static void SnapshotCapture()
        {
            // List all network interfaces
            var devices = CaptureDeviceList.Instance;
            if (devices.Count < 1)
            {
                Console.WriteLine("No devices found. Make sure you have the necessary permissions.");
                return;
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
            var device = devices[deviceIndex];

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

                var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                if (packet == null) return;

                // Create a detailed packet description
                StringBuilder packetInfo = new StringBuilder();

                // IP Packet
                var ipPacket = packet.Extract<IPPacket>();
                if (ipPacket != null)
                {
                    packetInfo.AppendLine($"IP Packet: {ipPacket.SourceAddress} -> {ipPacket.DestinationAddress}");
                }

                // TCP Packet
                var tcpPacket = packet.Extract<TcpPacket>();
                if (tcpPacket != null)
                {
                    packetInfo.AppendLine($"TCP Packet: Source Port {tcpPacket.SourcePort}, Destination Port {tcpPacket.DestinationPort}");
                }

                // UDP Packet
                var udpPacket = packet.Extract<UdpPacket>();
                if (udpPacket != null)
                {
                    packetInfo.AppendLine($"UDP Packet: Source Port {udpPacket.SourcePort}, Destination Port {udpPacket.DestinationPort}");
                }

                // Add additional packet details
                packetInfo.AppendLine($"Packet Timestamp: {rawPacket.Timeval.Date}");
                packetInfo.AppendLine($"Packet Length: {rawPacket.Data.Length} bytes");
                packetInfo.AppendLine("---");

                // For live capture, print immediately
                Console.WriteLine(packetInfo.ToString());

                // Store packet for snapshot
                capturedPackets.Add(packetInfo.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing packet: {ex.Message}");
            }
        }
    }
}