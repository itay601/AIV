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
using Ex02.ConsoleUtils;
using System.Reflection;


namespace PacketsSniffer.UI
{
    internal class MainConsole
    {
        public static async void MainConsoleDisplay()
        { 
            // Start monitoring in background
            _ = Task.Run(async () => await PacketExtensions.MonitoringPackets());
            _ = Task.Run(async () => await ProcessExtentions.MonitoringProcesses());


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
