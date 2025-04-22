using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PacketsSniffer.Core.Database.SamplesSignitures;
using static PacketsSniffer.Core.Detection.DNSThreatPacketsAnalyzer;
using PacketsSniffer.Monitoring;
using PacketsSniffer.Core.Detection;

namespace PacketsSniffer.Monitoring
{
    public class DnsPacket
    {
        public List<DNSQuery> Queries { get; set; }

        public DnsPacket(byte[] data)
        {
            Queries = new List<DNSQuery>();
            ParseDNSPacket(data);
        }

        private static void ParseDNSPacket(byte[] data)
        {
            try
            {
                int index = 12; // Skip DNS header (12 bytes)

                // Extract the query domain name
                string domainName = ParseDomainName(data, ref index);

                // Extract the query type (2 bytes)
                int queryType = (data[index] << 8) | data[index + 1];
                index += 2;

                // Extract the query class (2 bytes, usually IN for Internet)
                int queryClass = (data[index] << 8) | data[index + 1];
                index += 2;

                Console.WriteLine($"Query: {domainName}, Type: {queryType}, Class: {queryClass}");

                // Check record type
                var recordType = (DnsRecordType)queryType;
                if (DNSThreatPacketsAnalyzer.IsUnusualRecordType(recordType))
                {
                    Console.WriteLine($"Unusual DNS record type detected: {recordType}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error parsing DNS packet: " + ex.Message);
            }
        }
        private static string ParseDomainName(byte[] data, ref int position)
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
}
