using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PacketsSniffer.Core.Detection;

namespace PacketsSniffer.UI
{
    internal class MainConsole
    {
        public static void MainConsoleDisplay()
        {
            string choice = "-1";
            while (choice != "exit")
            {
                Console.WriteLine("Packet Sniffer Menu:");
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
