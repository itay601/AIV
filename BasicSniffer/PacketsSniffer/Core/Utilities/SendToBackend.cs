using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace PacketsSniffer.Core.Utilities
{
    class SendToBackendClass
    {
        private readonly HttpClient _httpClient;
        private string _apiEndpoint;

        public SendToBackendClass(string apiEndpoint = "http://localhost:5000/process/process-service")
        {
            _httpClient = new HttpClient();
            _apiEndpoint = apiEndpoint;
        }
        public async Task SendProcessToBackend(List<Dictionary<string, object>> processes)
        {
            try
            {
                // Convert the dictionaries to have field names that match the server model
                var formattedProcesses = processes.Select(process => new Dictionary<string, object>
                {
                    ["ProcessId"] = process.ContainsKey("ProcessId") ? process["ProcessId"] : null,
                    ["ProcessName"] = process.ContainsKey("ProcessName") ? process["ProcessName"] : null,
                    ["SessionId"] = process.ContainsKey("SessionId") ? process["SessionId"] : null,
                    ["StartTime"] = process.ContainsKey("StartTime") ? process["StartTime"] : null,
                    ["CPU"] = process.ContainsKey("CPU") ? process["CPU"] : null,
                    ["MemoryUsage"] = process.ContainsKey("MemoryUsage") ? process["MemoryUsage"] : null,
                    ["ThreadCount"] = process.ContainsKey("ThreadCount") ? process["ThreadCount"] : null,
                    ["HandleCount"] = process.ContainsKey("HandleCount") ? process["HandleCount"] : null,
                    ["ParentProcessId"] = process.ContainsKey("ParentProcessId") ? process["ParentProcessId"] : null,
                    ["ExecutablePath"] = process.ContainsKey("ExecutablePath") ? process["ExecutablePath"] : null,
                    ["CommandLine"] = process.ContainsKey("CommandLine") ? process["CommandLine"] : null,
                    ["Owner"] = process.ContainsKey("Owner") ? process["Owner"] : null,
                    ["NetworkConnections"] = process.ContainsKey("NetworkConnections") ? process["NetworkConnections"] : null,
                    ["DllList"] = process.ContainsKey("DllList") ? process["DllList"] : null,
                    ["FileAccess"] = process.ContainsKey("FileAccess") ? process["FileAccess"] : null,
                    ["DigitalSignature"] = process.ContainsKey("DigitalSignature") ? process["DigitalSignature"] : null
                }).ToList();

                var options = new System.Text.Json.JsonSerializerOptions
                {
                    PropertyNamingPolicy = null, // Ensure property names are not modified during serialization
                    WriteIndented = true // Makes the JSON more readable for debugging
                };

                var json = System.Text.Json.JsonSerializer.Serialize(formattedProcesses, options);
                Console.WriteLine("Sending JSON:");
                //Console.WriteLine(json);

                var content = new StringContent(json, Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync(_apiEndpoint, content);

                if (!response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"Failed to send processes: {response.StatusCode}");
                    string responseBody = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"Response body: {responseBody}");

                    // Implement retry logic here if needed
                    // content = new StringContent(json, Encoding.UTF8, "application/json");
                    // response = await httpClient.PostAsync(apiEndpoint, content);
                }
                else
                {
                    Console.WriteLine("sc: 200");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending packets to backend: {ex.Message}");
            }
        }



    }
}
