using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Net;
using PacketDotNet;
using SharpPcap;
using System.Collections.Generic;
using System.Text;
using PacketsSniffer.Core.Database.SamplesSignitures;

namespace PacketsSniffer.Core.Detection
{


    public class DnsPacket
    {
        public List<DNSQuery> Queries { get; set; }

        public DnsPacket(byte[] data)
        {
            Queries = new List<DNSQuery>();
            ParseDNSPacket(data);
        }

        private void ParseDNSPacket(byte[] data)
        {
            if (data.Length < 12) return;

            int position = 12; // Skip DNS header
            while (position < data.Length)
            {
                var domain = ParseDomainName(data, ref position);
                if (string.IsNullOrEmpty(domain)) break;

                if (position + 4 <= data.Length)
                {
                    ushort type = (ushort)((data[position] << 8) | data[position + 1]);
                    Queries.Add(new DNSQuery { Domain = domain, Type = type });
                }
                position += 4; // Skip type and class
            }
        }

        private string ParseDomainName(byte[] data, ref int position)
        {
            StringBuilder domain = new StringBuilder();
            int length;

            while (position < data.Length && (length = data[position++]) > 0)
            {
                if (length > 63) return string.Empty; // Invalid length

                for (int i = 0; i < length && position < data.Length; i++)
                {
                    domain.Append((char)data[position++]);
                }
                domain.Append('.');
            }

            return domain.ToString().TrimEnd('.');
        }

    }
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
    }

    // Add these helper methods to ThreatAnalyzer class
    public class ThreatPacketsAnalyzer
    {
        private List<string> knownMaliciousDomains;

        private class StringIComparer : IEqualityComparer<string>
        {
            public bool Equals(string x, string y)
            {
                return string.Equals(x, y, StringComparison.OrdinalIgnoreCase);
            }

            public int GetHashCode(string obj)
            {
                return obj?.ToLower().GetHashCode() ?? 0;
            }
        }
        

        private void CheckUserAgent(string payload)
        {
            string[] suspiciousPatterns = {
                "curl", "wget", "python-requests", "nikto", "sqlmap"
            };

            foreach (var pattern in suspiciousPatterns)
            {
                if (payload.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    RaiseAlert($"Suspicious User-Agent detected: {pattern}");
                    break;
                }
            }
        }

        private void RaiseAlert(string v)
        {
            throw new NotImplementedException();
        }

        private void InitializeMaliciousDomains()
        {
            string[] domains = {
                "malicious-domain.com",
                "evil-domain.net",
                "malware-site.com",
                "exploit-server.net",
                "c2-domain.com"
            };

            foreach (var domain in domains)
            {
                knownMaliciousDomains.Add(domain.ToLowerInvariant());
            }
        }

        private void EmitMetrics(string metricName, double value)
        {
            Console.WriteLine($"[METRIC] {DateTime.Now}: {metricName}={value}");
        }


        public void AnalyzePacket(Packet packet)
        {
            try
            {
                // Check for DNS queries
                var dnsPacket = packet.Extract<DnsPacket>();
                if (dnsPacket != null)
                {
                    foreach (var query in dnsPacket.Queries)
                    {
                        if (knownMaliciousDomains.Contains(query.Domain.ToLowerInvariant()))
                        {
                            RaiseAlert($"Suspicious DNS query detected: {query.Domain}");
                            EmitMetrics("suspicious_dns_queries", 1);
                        }
                    }
                }

                // Extract TCP/UDP packet
                var tcpPacket = packet.Extract<TcpPacket>();
                var udpPacket = packet.Extract<UdpPacket>();

                if (tcpPacket != null)
                {
                    // Check payload for suspicious patterns
                    string payload = Encoding.ASCII.GetString(tcpPacket.PayloadData);
                    CheckUserAgent(payload);
                    EmitMetrics("tcp_packets_analyzed", 1);
                }
                else if (udpPacket != null)
                {
                    EmitMetrics("udp_packets_analyzed", 1);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error analyzing packet: {ex.Message}");
                EmitMetrics("packet_analysis_errors", 1);
            }
        }
    } 
}