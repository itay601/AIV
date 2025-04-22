using System;
using System.Collections.Generic;
using System.Linq;
using System.Reactive.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using PacketDotNet;
using PacketsSniffer.Core.Database.Packets;
using Quartz;
using Quartz.Impl;


namespace PacketsSniffer.Monitoring
{
    public static class PacketExtensions
    {
        public static DnsPacket Extract<T>(this Packet packet) where T : DnsPacket
        {
            var udpPacket = packet.Extract<UdpPacket>();
            if (udpPacket != null && (udpPacket.DestinationPort == 53 || udpPacket.SourcePort == 53))
            {
                return new DnsPacket(udpPacket.PayloadData);
            }
            return null;
        }
        public static async Task MonitoringPackets()
        {
            var processor = new PacketProcessor();

            Observable.Interval(TimeSpan.FromSeconds(10)).Take(1).Subscribe(async x => await processor.StartMonitoring(60));
            // To stop monitoring
            //await processor.StopMonitoring();
        }
        // DNS Query Analysis
        public static (string DomainName, string RecordType) ParseDnsPacket(byte[] packetData)
        {
            try
            {
                if (packetData == null || packetData.Length < 12)
                    return (null, null);

                // DNS Header is 12 bytes
                // Byte 2-3: Flags
                // Byte 4-5: Question Count
                int questionCount = (packetData[4] << 8) | packetData[5];

                if (questionCount == 0)
                    return (null, null);

                // Start parsing domain name after DNS header
                int offset = 12;
                string domainName = ParseDomainName(packetData, ref offset);

                // Parse Record Type (2 bytes after domain name)
                if (offset + 2 < packetData.Length)
                {
                    int recordType = (packetData[offset] << 8) | packetData[offset + 1];
                    string recordTypeString = ConvertRecordTypeToString(recordType);

                    return (domainName, recordTypeString);
                }

                return (domainName, null);
            }
            catch
            {
                return (null, null);
            }
        }

        private static string ParseDomainName(byte[] packetData, ref int offset)
        {
            var domainParts = new List<string>();

            while (offset < packetData.Length)
            {
                int length = packetData[offset];

                // End of domain name
                if (length == 0)
                    break;

                // Check for pointer (compression)
                if ((length & 0xC0) == 0xC0)
                {
                    // Pointer to another location in the packet
                    int pointerOffset = ((length & 0x3F) << 8) | packetData[offset + 1];
                    string compressedPart = ParseDomainName(packetData, ref pointerOffset);
                    domainParts.Add(compressedPart);
                    offset += 2;
                    break;
                }

                offset++;
                string part = Encoding.ASCII.GetString(packetData, offset, length);
                domainParts.Add(part);
                offset += length;
            }

            offset++; // Skip the zero-length terminator
            return string.Join(".", domainParts);
        }

        private static string ConvertRecordTypeToString(int recordType)
        {
            switch (recordType)
            {
                case 1: return "A";       // IPv4 address
                case 2: return "NS";      // Name Server
                case 5: return "CNAME";   // Canonical Name
                case 15: return "MX";     // Mail Exchange
                case 28: return "AAAA";   // IPv6 address
                default: return recordType.ToString();
            }
        }


        // HTTP/HTTPS Packet Analysis
        public static (string UserAgent, string RequestPath, string HttpMethod) AnalyzeHttpPacket(byte[] payloadData)
        {
            try
            {
                // Convert payload to string
                string httpPayload = Encoding.UTF8.GetString(payloadData);

                // Simple HTTP header parsing
                var lines = httpPayload.Split(new[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                if (lines.Length == 0) return (null, null, null);

                // Parse first line (request line)
                var requestParts = lines[0].Split(' ');
                if (requestParts.Length < 3) return (null, null, null);

                string method = requestParts[0];
                string path = requestParts[1];

                // Find User-Agent in headers
                string userAgent = lines
                    .FirstOrDefault(line => line.StartsWith("User-Agent:", StringComparison.OrdinalIgnoreCase))
                    ?.Split(new[] { ": " }, StringSplitOptions.None)[1];

                return (
                    UserAgent: userAgent,
                    RequestPath: path,
                    HttpMethod: method
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine($"HTTP Packet Analysis Error: {ex.Message}");
                return (null, null, null);
            }
        }
        public static (string userAgent, string path, string method) AnalyzeHttpPacketDetails(byte[] payload)
        {
            string userAgent = "";
            string path = "";
            string method = "";

            try
            {
                // Convert payload to string
                string httpContent = System.Text.Encoding.ASCII.GetString(payload);

                // Split into lines
                string[] lines = httpContent.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);

                // Get request line (first line)
                if (lines.Length > 0)
                {
                    string[] requestParts = lines[0].Split(' ');
                    if (requestParts.Length >= 2)
                    {
                        method = requestParts[0];  // GET, POST, etc.
                        path = requestParts[1];    // /login.php, etc.
                    }
                }

                // Look for User-Agent header
                foreach (string line in lines)
                {
                    if (line.StartsWith("User-Agent:", StringComparison.OrdinalIgnoreCase))
                    {
                        userAgent = line.Substring("User-Agent:".Length).Trim();
                        break;
                    }
                }
            }
            catch (Exception)
            {
                // Handle any parsing errors gracefully
                userAgent = "";
                path = "";
                method = "";
            }

            return (userAgent, path, method);
        }
    }
}
