using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PacketsSniffer.Core.Detection;

namespace PacketsSniffer.Core.Database.SamplesSignitures
{
    public class FluxCheckResult
    {
        public int UniqueIPs { get; set; }
        public int TotalQueries { get; set; }
        public Dictionary<string, int> IpFrequency { get; set; }
        public string Error { get; set; }
    }
    public class DNSQuery
    {
        public string Domain { get; set; }
        public ushort Type { get; set; }
        public DNSThreatPacketsAnalyzer.DnsRecordType RecordType { get; internal set; }
    }
 

}
