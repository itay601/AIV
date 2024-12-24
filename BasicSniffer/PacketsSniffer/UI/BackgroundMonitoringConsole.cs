using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PacketDotNet;
using PacketsSniffer.Core.Detection;
using SharpPcap;

namespace PacketsSniffer.UI
{
    class BackgroundMonitoringConsole
    {
       public static void DisplayPacketBackgroundCheck()
        {
            PacketSniffer.StartDisplayAnalayes();
        }
    }
}
