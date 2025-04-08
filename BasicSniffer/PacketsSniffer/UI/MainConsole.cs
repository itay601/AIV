using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using PacketsSniffer.Core.Detection;
using PacketsSniffer.Core.Models;
using PacketsSniffer.Core.Scanners;
using PacketsSniffer.Core.Utilities;
using PacketsSniffer.Monitoring;
using PacketsSniffer.Monitoring.Processes;

namespace PacketsSniffer.UI
{
    internal class MainConsole
    {
        public static async void MainConsoleDisplay()
        {

            // Start monitoring in background
            //_ =  Task.Run(async () => await PacketExtensions.MonitoringPackets());
            // uncomment when finished analyzed aall exe/dll by ember dataset
            _ =  Task.Run(async () => await ProcessExtentions.MonitoringProcesses());


            //var filePath = $@"C:\MyProjects\Packet-Sniffer\BasicSniffer\PacketsSniffer\bin\Debug\PacketsSniffer.exe";
            //var filepath = $@"C:\WINDOWS\System32\DriverStore\FileRepository\asussci2.inf_amd64_f57c48cf404ebc46\AsusAppService\AsusAppService.exe";
            //var fileDetection = new FileDetectionEMBERSchema();
            //Console.WriteLine(PEChecker.IsValidPEFile(filepath));
            //try
            //{
            //    var result = fileDetection.AnalyzeFileForPEFile(filepath);

            //    // Convert Dictionary to JSON
            //    var options = new JsonSerializerOptions
            //    {
            //        WriteIndented = true // For pretty-printed JSON
            //    };

            //    string json = JsonSerializer.Serialize(result, options);
            //    Console.WriteLine(json);

            //}
            //catch (Exception ex)
            //{
            //    Console.WriteLine($"Error: {ex.Message}");
            //}
            

            //need to be work on special imports like "KERNEL32.dll" 
            //PEUtility.ExtractPeImports($@"C:\MyProjects\Packet-Sniffer\BasicSniffer\PacketsSniffer\bin\Debug\PacketsSniffer.exe");


            string choice = "-1";
            while (choice != "exit")
            {
                Console.WriteLine("AntiVirus Menu:");
                Console.WriteLine("1. Packets Sniffer");
                Console.WriteLine("2. Mallware detection");
                Console.WriteLine("Choose an option (1/2): ");
                Console.WriteLine("-----------------------");
                choice = Console.ReadLine();

                switch (choice)
                {
                    case "1":
                        ConsoleTerminal.SnifferConsole();
                        break;
                    case "2":
                        ConsoleTerminal.MalwareDetectorConsole();
                        break;
                    case "3":
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
