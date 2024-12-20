using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PacketsSniffer.Core.Detection;


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
        public static void MalwareDetector()
        {
            string connectionString = "your_sql_connection_string_here";
            var detector = new FileDetection(connectionString);

            // Check a single file
            string filePath = "C:\\MyProjects\\a.dll";
            if (detector.CheckFile(filePath))
            {
                Console.WriteLine("Malware detected!");
            }
            else
            {
                Console.WriteLine("File is clean.");
            }

            // Check all files on the computer
            detector.CheckAllFiles();
        }


        public static void SnifferConsole()
        {
            string choice = "-1";
            while (choice != "ëxit")
            {
                Console.WriteLine("Packet Sniffer Menu:");
                Console.WriteLine("1. Live Packet Capture");
                Console.WriteLine("2. Packet Snapshot");
                Console.Write("Choose an option (1/2): ");
                choice = Console.ReadLine();

                switch (choice)
                {
                    case "1":
                        PacketSniffer.LiveCaptureOption();
                        break;
                    case "2":
                        PacketSniffer.SnapshotCaptureOption();
                        break;
                    case "exit":
                        return;
                    default:
                        Console.WriteLine("Invalid option selected.");
                        return;
                }
                Ex02.ConsoleUtils.Screen.Clear();
            }
        }
    }
}
