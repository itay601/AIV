using System;
using System.Collections.Generic;
using System.Linq;
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
            await processor.StartMonitoring(60);

            await Task.Delay(TimeSpan.FromSeconds(60));

            // To stop monitoring
            //await processor.StopMonitoring();

        }




        //public static void MonitorSchesuler()
        //{
        //    // Configure the scheduler factory
        //    StdSchedulerFactory factory = new StdSchedulerFactory();
        //    IScheduler scheduler = factory.GetScheduler().Result;

        //    // Define the job and tie it to a class
        //    IJobDetail job = JobBuilder.Create<PacketProcessor>()
        //        .WithIdentity("myJob", "group1")
        //        .Build();

        //    // Trigger the job to run every 60 seconds
        //    ITrigger trigger = TriggerBuilder.Create()
        //        .WithIdentity("myTrigger", "group1")
        //        .StartNow()
        //        .WithSimpleSchedule(x => x
        //            .WithIntervalInSeconds(60)
        //            .RepeatForever())
        //        .Build();

        //    // Tell quartz to schedule the job using the trigger
        //    scheduler.ScheduleJob(job, trigger).Wait();

        //    // Start the scheduler
        //    scheduler.Start().Wait();

        //    Console.WriteLine("Press Enter to exit.");
        //    Console.ReadLine();

        //    // Shutdown the scheduler
        //    //scheduler.Shutdown().Wait();
        //}
    }
}
