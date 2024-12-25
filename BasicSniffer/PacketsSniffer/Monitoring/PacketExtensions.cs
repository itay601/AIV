using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PacketDotNet;

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
    }
}
