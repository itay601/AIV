using System;
using System.Diagnostics;
using System.Security.Principal;
using System.Management;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Security.Cryptography;

namespace PacketsSniffer.Monitoring
{
    public class ProcessesMonitoring : IDisposable
    {
        private readonly HashSet<string> knownMaliciousHashes = new HashSet<string>();
        private readonly Dictionary<string, HashSet<string>> suspiciousBehaviors = new Dictionary<string, HashSet<string>>();
        private bool isAdministrator;
        private ManagementEventWatcher processWatcher;
        private readonly object lockObject = new object();

        public ProcessesMonitoring()
        {
            CheckAdministratorPrivileges();
            InitializeSuspiciousBehaviors();
        }

        private void CheckAdministratorPrivileges()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                isAdministrator = principal.IsInRole(WindowsBuiltInRole.Administrator);

                if (!isAdministrator)
                {
                    Console.WriteLine("WARNING: Application is not running with administrator privileges!");
                    Console.WriteLine("Some monitoring features may be limited.");
                }
            }
        }

        private void InitializeSuspiciousBehaviors()
        {
            // Define suspicious process characteristics
            suspiciousBehaviors["system_access"] = new HashSet<string>
            {
                @"windows\system32\drivers",
                @"windows\system32\config",
                "registry.exe"
            };

            suspiciousBehaviors["network_behavior"] = new HashSet<string>
            {
                "netsh.exe",
                "nc.exe",
                "nmap.exe"
            };

            suspiciousBehaviors["crypto_mining"] = new HashSet<string>
            {
                "xmrig",
                "minergate",
                "cgminer"
            };
        }

        public void StartMonitoring()
        {
            try
            {
                if (processWatcher != null)
                {
                    Console.WriteLine("Monitoring is already active.");
                    return;
                }

                var scope = new ManagementScope("\\\\.\\root\\cimv2");
                var query = new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace");

                processWatcher = new ManagementEventWatcher(scope, query);
                processWatcher.EventArrived += ProcessStarted;
                processWatcher.Start();

                Console.WriteLine("Process monitoring started successfully.");
                Console.WriteLine("Monitoring for suspicious activities...");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error starting monitoring: {ex.Message}");
                if (!isAdministrator)
                {
                    Console.WriteLine("Please restart the application with administrator privileges.");
                }
                throw;
            }
        }

        private void ProcessStarted(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var processInfo = (ManagementBaseObject)e.NewEvent;
                int processId = Convert.ToInt32(processInfo["ProcessID"]);
                string processName = Convert.ToString(processInfo["ProcessName"]);
                string processPath = Convert.ToString(processInfo["ExecutablePath"]);

                if (string.IsNullOrEmpty(processPath))
                    return;

                var process = Process.GetProcessById(processId);
                AnalyzeProcess(process, processPath);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error analyzing process: {ex.Message}");
            }
        }

        private void AnalyzeProcess(Process process, string processPath)
        {
            try
            {
                // Check file hash
                string fileHash = CalculateFileHash(processPath);
                if (knownMaliciousHashes.Contains(fileHash))
                {
                    ReportSuspiciousProcess(process, "Matches known malicious hash");
                    return;
                }

                // Check suspicious locations and behaviors
                foreach (var category in suspiciousBehaviors)
                {
                    if (category.Value.Any(suspicious =>
                        processPath.ToLower().Contains(suspicious.ToLower())))
                    {
                        ReportSuspiciousProcess(process, $"Suspicious {category.Key} behavior detected");
                    }
                }

                // Check for unusual process characteristics
                CheckProcessCharacteristics(process);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during process analysis: {ex.Message}");
            }
        }

        private void CheckProcessCharacteristics(Process process)
        {
            try
            {
                // Check CPU usage
                if (process.TotalProcessorTime.TotalSeconds > 30)
                {
                    ReportSuspiciousProcess(process, "High CPU usage");
                }

                // Check memory usage (>500MB)
                if (process.WorkingSet64 > 524288000)
                {
                    ReportSuspiciousProcess(process, "High memory usage");
                }

                // Check for hidden windows
                if (process.MainWindowHandle == IntPtr.Zero &&
                    process.Responding &&
                    process.WorkingSet64 > 10000000)
                {
                    ReportSuspiciousProcess(process, "Hidden window with significant resource usage");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error checking process characteristics: {ex.Message}");
            }
        }

        private string CalculateFileHash(string filePath)
        {
            try
            {
                using (var sha256 = SHA256.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    var hash = sha256.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLower();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error calculating file hash: {ex.Message}");
                return string.Empty;
            }
        }

        private void ReportSuspiciousProcess(Process process, string reason)
        {
            string report = $@"
SUSPICIOUS PROCESS DETECTED!
Time: {DateTime.Now}
Process ID: {process.Id}
Process Name: {process.ProcessName}
Reason: {reason}
Path: {process.MainModule?.FileName ?? "Unknown" }
Command Line: { process.StartInfo.Arguments }
";
            Console.WriteLine(report);

            // You could add additional actions here like:
            // - Logging to a file
            // - Sending alerts
            // - Taking automatic action
        }

        public void Dispose()
        {
            processWatcher?.Dispose();
        }
    }
}