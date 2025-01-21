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

            // Create an instance
            var processor = new PacketProcessor();

            // Start monitoring with 60-second intervals
            ///await processor.StartMonitoring(60);

            Observable.Interval(TimeSpan.FromSeconds(20)).Subscribe(async x =>await processor.StartMonitoring(20));

            // To stop monitoring
            //await processor.StopMonitoring();

        }
    }
}
