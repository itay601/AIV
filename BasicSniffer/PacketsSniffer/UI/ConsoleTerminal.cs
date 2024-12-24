using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using MySql.Data.MySqlClient;
using PacketsSniffer.Core.Detection;
using PacketsSniffer.UI;


namespace PacketsSniffer
{
    class ConsoleTerminal
    {
        /// <summary>
        /// Options of the console
        /// </summary>
        /// Mallware detector Section 
       
        public static void MalwareDetectorSingleFile()
        {   
            var detector = new FileDetection();
            //enter file location
            string fileLocation = null;
            while (fileLocation != null) 
            {
                Console.WriteLine("Enter file location");
                fileLocation = Console.ReadLine();
            }
            string filePath = "C:\\MyProjects\\a.exe";
            if (detector.CheckFile(filePath))
            {
                Console.WriteLine("Malware detected!");
            }
            else
            {
                Console.WriteLine("File is clean.");
            }

            // Check all files on the computer
            //detector.CheckAllFiles();
        }
        public static void MalwareDetectorAllFiles()
        {
            var detector = new FileDetection();
            detector.CheckAllFiles();
        }
        public static void MalwareDetectorConsole() 
        {
            string choice = "-1";
            while (choice != "exit")
            {
                Console.WriteLine("Malware Detector Menu:");
                Console.WriteLine("1. Single file");
                Console.WriteLine("2. All Files");
                Console.Write("Choose an option (1/2): ");
                choice = Console.ReadLine();
                switch (choice)
                {
                    case "1":
                        MalwareDetectorSingleFile();
                        break;
                    case "2":
                        MalwareDetectorAllFiles();
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

        /// <summary>
        /// Packets Sniffer Section
        /// </summary>
        public static void SnifferConsole()
        {
            string choice = "-1";
            while (choice != "exit")
            {
                Console.WriteLine("Packet Sniffer Menu:");
                Console.WriteLine("1. Live Packet Capture");
                Console.WriteLine("2. Packet Snapshot");
                Console.WriteLine("3. Background Packets Analysis");
                Console.Write("Choose an option (1/2/3): ");
                choice = Console.ReadLine();

                switch (choice)
                {
                    case "1":
                        PacketSniffer.LiveCaptureOption();
                        break;
                    case "2":
                        PacketSniffer.SnapshotCaptureOption();
                        break;
                    case "3":
                        BackgroundMonitoringConsole.DisplayPacketBackgroundCheck();
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
