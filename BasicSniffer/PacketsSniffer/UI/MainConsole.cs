using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PacketsSniffer.Core.Detection;
using PacketsSniffer.Core.Scanners;
using PacketsSniffer.Monitoring;
using PacketsSniffer.Monitoring.Processes;

namespace PacketsSniffer.UI
{
    internal class MainConsole
    {
        public static async void MainConsoleDisplay()
        {

            // Start monitoring in background
            // The _ discard operator tells the compiler we intentionally aren't awaiting the task
            //_ =  Task.Run(async () => await PacketExtensions.MonitoringPackets());
            _ =  Task.Run(async () => await ProcessExtentions.MonitoringProcesses());
            //await ProcessExtentions.MonitoringProcesses();

            //Decompiler.AnalyzeAssembly(@"C:\MyProjects\Packet-Sniffer\BasicSniffer\PacketsSniffer\bin\Debug\PacketsSniffer.exe");


            string choice = "-1";
            while (choice != "exit")
            {
                Console.WriteLine("AntiVirus Menu:");
                Console.WriteLine("1. Packets Sniffer");
                Console.WriteLine("2. Mallware detection");
                Console.Write("Choose an option (1/2): ");
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
