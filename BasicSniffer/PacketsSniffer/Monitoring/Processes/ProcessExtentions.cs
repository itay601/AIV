using System;
using System.Collections.Generic;
using System.Linq;
using System.Reactive.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketsSniffer.Monitoring.Processes
{
    class ProcessExtentions
    {
        public static async Task MonitoringProcesses()
        {
            var processor = new ProcessesMonitoring();

            processor.StartMonitoring();

            //Observable.Interval(TimeSpan.FromSeconds(3600)).Subscribe(async x => await processor.StartMonitoring());
        }
    }
}
