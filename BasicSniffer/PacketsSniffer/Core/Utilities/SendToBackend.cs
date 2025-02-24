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
        public async Task SendProcessToBackend(List<Dictionary<string,object>> processes)
        {
            try
            {
                var json = System.Text.Json.JsonSerializer.Serialize(processes);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync(_apiEndpoint, content);

                if (!response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"Failed to send packets: {response.StatusCode}");
                    // Implement retry logic here if needed
                    content = new StringContent(json, Encoding.UTF8, "application/json");
                    response = await _httpClient.PostAsync(_apiEndpoint, content);
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
