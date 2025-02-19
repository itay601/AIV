using System;
using System.Diagnostics;
using System.Security.Principal;
using System.Management;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Collections;
using System.Runtime.InteropServices;
using System.Net;

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
                var processes = Process.GetProcesses();
                foreach (var process in processes)
                {
                    //Console.WriteLine($"id : {process.Id} , name : {process.ProcessName} , machine name : {process.MachineName} ,SessionId : " +
                    //  $"{process.SessionId}    ");
                    ExactProcess(process);
                }

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
        public static void ExactProcess(Process process)
        {
            try
            {
                var processInfo = new Dictionary<string, object>
                {
                    ["ProcessId"] = process.Id,
                    ["ProcessName"] = process.ProcessName,
                    ["SessionId"] = process.SessionId,
                    ["StartTime"] = SafeGetStartTime(process), // protected method because accessing StartTime might throw
                    ["CPU"] = process.TotalProcessorTime,
                    ["MemoryUsage"] = process.WorkingSet64,
                    ["ThreadCount"] = process.Threads?.Count,
                    ["HandleCount"] = SafeGetHandleCount(process),
                    ["ParentProcessId"] = GetParentProcessId(process.Id),
                    ["ExecutablePath"] = SafeGetExecutablePath(process),
                    ["CommandLine"] = GetCommandLine(process.Id),
                    ["Owner"] = GetProcessOwner(process.Id),
                    ["NetworkConnections"] = GetNetworkConnections(process.Id),
                    ["DllList"] = GetLoadedDlls(process),
                    ["FileAccess"] = GetFileSystemPath(process.Id),
                    ["DigitalSignature"] = GetDigitalSignature(SafeGetExecutablePath(process))
                };

                // Now send processInfo for further processing (example: for ML or logging)
                ProcessDataForML(processInfo);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error analyzing process {process.Id}: {ex.Message}");
            }
        }


        static object SafeGetStartTime(Process process)
        {
            try
            {
                return process.StartTime;
            }
            catch
            {
                return "Access Denied";
            }
        }

        /// <summary>
        /// Prevents exceptions when accessing process.HandleCount on processes where access is denied.
        /// </summary>
        static object SafeGetHandleCount(Process process)
        {
            try
            {
                return process.HandleCount;
            }
            catch
            {
                return "Access Denied";
            }
        }

        /// <summary>
        /// Retrieves the parent process ID using a WMI query.
        /// </summary>
        static int? GetParentProcessId(int processId)
        {
            try
            {
                string query = $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {processId}";
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(query))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        if (obj["ParentProcessId"] != null)
                        {
                            return Convert.ToInt32(obj["ParentProcessId"]);
                        }
                    }
                }
            }
            catch { }
            return null;
        }

        /// <summary>
        /// Retrieves the command line used to start the process via WMI.
        /// </summary>
        static string GetCommandLine(int processId)
        {
            try
            {
                string query = $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {processId}";
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(query))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        return obj["CommandLine"]?.ToString() ?? "";
                    }
                }
            }
            catch { }
            return "";
        }

        /// <summary>
        /// Retrieves the process owner using WMI.
        /// </summary>
        static string GetProcessOwner(int processId)
        {
            try
            {
                string query = $"SELECT * FROM Win32_Process WHERE ProcessId = {processId}";
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(query))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        object[] args = new object[] { string.Empty, string.Empty };
                        int returnVal = Convert.ToInt32(obj.InvokeMethod("GetOwner", args));
                        if (returnVal == 0)
                        {
                            return args[0]?.ToString() ?? "N/A";
                        }
                    }
                }
            }
            catch { }
            return "Unknown";
        }

        // Constants for GetExtendedTcpTable
        private const int AF_INET = 2; // IPv4
        private const int TCP_TABLE_OWNER_PID_ALL = 5;

        /// <summary>
        /// Retrieves a list of network connection strings for a given process.
        /// </summary>
        /// <param name="processId">The process ID to filter connections.</param>
        /// <returns>A list of strings describing the TCP connections for the process.</returns>
        static List<string> GetNetworkConnections(int processId)
        {
            List<string> connections = new List<string>();

            // First, determine the size of the TCP table.
            int buffSize = 0;
            uint result = GetExtendedTcpTable(IntPtr.Zero, ref buffSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            IntPtr tcpTablePtr = Marshal.AllocHGlobal(buffSize);

            try
            {
                // Populate the TCP table.
                result = GetExtendedTcpTable(tcpTablePtr, ref buffSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
                if (result != 0)
                {
                    return new List<string> { "Error retrieving connection data." };
                }

                // The first 4 bytes contain the number of entries.
                int numEntries = Marshal.ReadInt32(tcpTablePtr);

                // Set the pointer to the first MIB_TCPROW_OWNER_PID record.
                IntPtr rowPtr = new IntPtr(tcpTablePtr.ToInt64() + sizeof(int));
                int rowStructSize = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));

                for (int i = 0; i < numEntries; i++)
                {
                    MIB_TCPROW_OWNER_PID tcpRow = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                    if (tcpRow.owningPid == processId)
                    {
                        // Convert addresses.
                        IPAddress localIP = new IPAddress(tcpRow.localAddr);
                        IPAddress remoteIP = new IPAddress(tcpRow.remoteAddr);

                        // Convert ports from network byte order.
                        ushort localPort = (ushort)IPAddress.NetworkToHostOrder((short)tcpRow.localPort);
                        ushort remotePort = (ushort)IPAddress.NetworkToHostOrder((short)tcpRow.remotePort);

                        string connectionState = TcpStateToString(tcpRow.state);

                        string connectionString = $"Local: {localIP}:{localPort}, Remote: {remoteIP}:{remotePort}, State: {connectionState}";
                        connections.Add(connectionString);
                    }

                    // Move pointer to the next record.
                    rowPtr = new IntPtr(rowPtr.ToInt64() + rowStructSize);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(tcpTablePtr);
            }

            if (connections.Count == 0)
            {
                connections.Add("No connections found for the process.");
            }

            return connections;
        }

        /// <summary>
        /// Maps a TCP connection state's numeric value to its human-readable text.
        /// </summary>
        /// <param name="state">The numeric state.</param>
        /// <returns>String representation of the state.</returns>
        static string TcpStateToString(uint state)
        {
            // Mapping based on standard TCP state values.
            switch (state)
            {
                case 1: return "CLOSED";
                case 2: return "LISTEN";
                case 3: return "SYN_SENT";
                case 4: return "SYN_RECEIVED";
                case 5: return "ESTABLISHED";
                case 6: return "FIN_WAIT1";
                case 7: return "FIN_WAIT2";
                case 8: return "CLOSE_WAIT";
                case 9: return "CLOSING";
                case 10: return "LAST_ACK";
                case 11: return "TIME_WAIT";
                case 12: return "DELETE_TCB";
                default: return "UNKNOWN";
            }
        }

        // P/Invoke declaration for GetExtendedTcpTable.
        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable,
            ref int dwOutBufLen,
            bool sort,
            int ipVersion,
            int tableClass,
            uint reserved
        );

        // Define the MIB_TCPROW_OWNER_PID structure.
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPROW_OWNER_PID
        {
            public uint state;         // TCP state of the connection.
            public uint localAddr;     // Local IP address.
            public uint localPort;     // Local port (in network byte order).
            public uint remoteAddr;    // Remote IP address.
            public uint remotePort;    // Remote port (in network byte order).
            public uint owningPid;     // Process ID that owns this connection.
        }

        

        /// <summary>
        /// Returns a list of loaded DLLs for the process.
        /// </summary>
        static List<string> GetLoadedDlls(Process process)
        {
            var dlls = new List<string>();
            try
            {
                foreach (ProcessModule module in process.Modules)
                {
                    dlls.Add(module.FileName);
                }
            }
            catch
            {
                dlls.Add("Access Denied or Insufficient Permissions");
            }
            return dlls;
        }

        /// <summary>
        /// Returns file system activity for the process. This is a stub.
        /// In production, you could use ETW or similar to capture activity.
        /// </summary>
        static string GetFileSystemPath(int processId)
        {
            Process process = null;
            try
            {
                process = Process.GetProcessById(processId);
            }
            catch (Exception ex)
            {
                return $"Process not found: {ex.Message}";
            }
            var directoryToWatch =  Path.GetDirectoryName(process.MainModule.FileName);
            return directoryToWatch;
        }

        /// <summary>
        /// Checks if the file is digitally signed. Returns true if a certificate is found.
        /// </summary>
        static bool GetDigitalSignature(string executablePath)
        {
            if (string.IsNullOrEmpty(executablePath) || !File.Exists(executablePath))
                return false;

            try
            {
                // This will throw if the file is not digitally signed.
                X509Certificate certificate = X509Certificate.CreateFromSignedFile(executablePath);
                return certificate != null;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Retrieves the executable path for the process using WMI if necessary.
        /// </summary>
        static string SafeGetExecutablePath(Process process)
        {
            try
            {
                // process.MainModule.FileName might throw an exception if access is denied.
                return process.MainModule?.FileName;
            }
            catch
            {
                // As a fallback, use a WMI-based approach.
                try
                {
                    string query = $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {process.Id}";
                    using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(query))
                    {
                        foreach (ManagementObject obj in searcher.Get())
                        {
                            return obj["ExecutablePath"]?.ToString();
                        }
                    }
                }
                catch { }
            }
            return "";
        }

        /// <summary>
        /// Processes the collected data from a process. Currently, it prints the details.
        /// Replace or extend this method to store the data for machine learning.
        /// </summary>
        private static void ProcessDataForML(Dictionary<string, object> processInfo)
        {
            Console.WriteLine("----- Process Data -----");
            foreach (var kv in processInfo)
            {
                // If the value is an IEnumerable and not a string, iterate over its items.
                if (kv.Value is IEnumerable enumerable && !(kv.Value is string))
                {
                    Console.WriteLine($"{kv.Key}:");

                    foreach (var item in enumerable)
                    {
                        Console.WriteLine($"  - {item}");
                    }
                }
                else
                {
                    Console.WriteLine($"{kv.Key}: {kv.Value}");
                }
            }
            Console.WriteLine("------------------------\n");
        }


        /// <summary>
        /// //////////////////////////////////////
        /// </summary>
        public void StartMonitoring2()
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
                var processes = Process.GetProcesses();
                foreach (var process in processes)
                {
                    Console.WriteLine($"id : {process.Id} , name : {process.ProcessName} , ### : {process.MachineName} ," +
                        $"{process.SessionId}    ");
                    int processId = Convert.ToInt32(process.Id);
                    string processName = Convert.ToString(process.ProcessName);
                    //ring processPath = Convert.ToString(process
                    AnalyzeProcess(process);
                }

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
                AnalayzeNewProcess(process, processPath);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error analyzing process: {ex.Message}");
            }
        }
        private void AnalyzeProcess(Process process)
        {

        }
        private void AnalayzeNewProcess(Process process, string processPath)
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

        /// <summary>
        /// 
        /// </summary>
        /// <param name="process"></param>
        /// <param name="reason"></param>
        private void ReportSuspiciousProcess(Process process, string reason)
        {
            string report = $@"
SUSPICIOUS PROCESS DETECTED!
Time: {DateTime.Now}
Process ID: {process.Id}
Process Name: {process.ProcessName}
Reason: {reason}
Path: {process.MainModule?.FileName ?? "Unknown"}
Command Line: {process.StartInfo.Arguments}
";
            Console.WriteLine(report);
            /// <summary>
            /// kill malicous process 
            /// and connected files 
            /// </summary>

        }

        public void Dispose()
        {
            processWatcher?.Dispose();
        }
    }
}