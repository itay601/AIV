using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketsSniffer
{
    class ConsoleTerminal
    {
        /// <summary>
        /// Options of the console
        /// </summary>
        /// 
        //public static void AllOptionsConsole()
        //{

        //}


        public static void SnifferConsole()
        {
            Console.WriteLine("Packet Sniffer Menu:");
            Console.WriteLine("1. Live Packet Capture");
            Console.WriteLine("2. Packet Snapshot");
            Console.Write("Choose an option (1/2): ");
            string choice = Console.ReadLine();

            switch (choice)
            {
                case "1":
                    PacketSniffer.LiveCaptureOption();
                    break;
                case "2":
                    PacketSniffer.SnapshotCaptureOption();
                    break;
                default:
                    Console.WriteLine("Invalid option selected.");
                    return;
            }
        }
    }
}
