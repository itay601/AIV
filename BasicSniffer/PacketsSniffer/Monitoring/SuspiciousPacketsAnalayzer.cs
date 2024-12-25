using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Net;
using PacketDotNet;
using SharpPcap;
using System.Collections.Generic;
using System.Text;
using PacketsSniffer.Core.Database.SamplesSignitures;
using PacketsSniffer.Monitoring;


namespace PacketsSniffer.Core.Detection
{
    // Add these helper methods to ThreatAnalyzer class
    public class ThreatPacketsAnalyzer
    {
        private Dictionary<string, Queue<DateTime>> domainRequests = new Dictionary<string, Queue<DateTime>>();
        private Dictionary<string, HashSet<string>> fastFluxDomains = new Dictionary<string, HashSet<string>>();
        private List<string> knownMaliciousDomains;
        private const int MAX_DOMAIN_LENGTH = 253;

        //Nested Class -->
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
                    this.InitializeMaliciousDomains();
                    foreach (var query in dnsPacket.Queries)
                    {
                        // Check request volume (DNS tunneling)
                        CheckRequestVolume(query.Domain);

                        // Check for extremely long domain names
                        if (query.Domain.Length > MAX_DOMAIN_LENGTH)
                        {
                            RaiseAlert($"Extremely long domain detected: {query.Domain}");
                        }
                        // Check for unusual record types
                        // Convert and check for unusual record types
                        foreach (var answer in dnsPacket.Queries)
                        {
                            // Convert and check for unusual record types
                            var recordType = query.RecordType;
                            if (IsUnusualRecordType(recordType))
                            {
                                RaiseAlert($"Unusual DNS record type detected: {recordType} for {query.Domain}");
                            }
                        }

                        // Check known malicious domains
                        if (knownMaliciousDomains.Contains(query.Domain.ToLowerInvariant()))
                        {
                            RaiseAlert($"Suspicious DNS query detected: {query.Domain}");
                            EmitMetrics("suspicious_dns_queries", 1);
                        }
                    }

                    //// Check for fast-flux DNS if there are answers
                    //if (dnsPacket.Answers != null && dnsPacket.Answers.Any())
                    //{
                    //    CheckFastFlux(dnsPacket.Answers);
                    //}
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
        public enum DnsRecordType
        {
            A = 1,
            NS = 2,
            CNAME = 5,
            SOA = 6,
            PTR = 12,
            HINFO = 13,
            MX = 15,
            TXT = 16,
            RP = 17,
            AFSDB = 18,
            AAAA = 28,
            NULL = 10,
            SRV = 33,
            DNAME = 39
        }
        public static bool IsUnusualRecordType(DnsRecordType recordType)
        {
            switch (recordType)
            {
                // Unusual record types
                case DnsRecordType.NULL:
                case DnsRecordType.HINFO:
                case DnsRecordType.RP:
                case DnsRecordType.AFSDB:
                    return true;

                // Normal record types
                case DnsRecordType.A:
                case DnsRecordType.NS:
                case DnsRecordType.CNAME:
                case DnsRecordType.SOA:
                case DnsRecordType.PTR:
                case DnsRecordType.MX:
                case DnsRecordType.TXT:
                case DnsRecordType.AAAA:
                case DnsRecordType.SRV:
                case DnsRecordType.DNAME:
                    return false;

                // Default case for any undefined or unexpected types
                default:
                    return false;
            }
        }

        private void CheckRequestVolume(string domain)
        {
            var now = DateTime.UtcNow;
            if (!domainRequests.ContainsKey(domain))
            {
                domainRequests[domain] = new Queue<DateTime>();
            }

            domainRequests[domain].Enqueue(now);

            // Remove requests older than 1 minute
            while (domainRequests[domain].Count > 0 &&
                   (now - domainRequests[domain].Peek()).TotalSeconds > 60)
            {
                domainRequests[domain].Dequeue();
            }

            if (domainRequests[domain].Count > 1000) // Threshold for tunneling detection
            {
                RaiseAlert($"Possible DNS tunneling detected: {domain}");
            }
        }
       

        ///// <summary>
        ///// Checks for fast-flux domains in the provided DNS answers.
        ///// </summary>
        ///// <param name="answers">The DNS answers to check.</param>
        //private void CheckFastFlux(DnsAnswerCollection answers)
        //{
        //    // Iterate over each answer in the collection
        //    foreach (var answer in answers)
        //    {
        //        // Only consider A and AAAA record types
        //        if (answer.RecordType != DnsRecordType.A && answer.RecordType != DnsRecordType.AAAA)
        //        {
        //            continue;
        //        }

        //        // Extract the domain from the answer and convert to lowercase
        //        var domain = answer.Domain.ToLowerInvariant();

        //        // Add the domain to the fast-flux domains dictionary if it doesn't exist
        //        if (!fastFluxDomains.TryGetValue(domain, out var addresses))
        //        {
        //            fastFluxDomains[domain] = addresses = new HashSet<string>();
        //        }

        //        // Add the answer's address to the set of addresses for the domain
        //        addresses.Add(answer.Address.ToString());

        //        // Check if the number of addresses for the domain exceeds the threshold
        //        if (addresses.Count > 5)
        //        {
        //            // Raise an alert if the threshold is exceeded
        //            RaiseAlert($"Possible fast-flux detected: {domain}");
        //        }
        //    }
        //}
    } 
}