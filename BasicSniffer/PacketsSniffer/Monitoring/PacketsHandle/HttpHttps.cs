using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketsSniffer.Monitoring
{
    using System;
    using System.Collections.Generic;
    using System.Text.RegularExpressions;
    using PacketDotNet;

    namespace PacketAnalyzer
    {
        public class HttpPacketAnalyzer
        {
            // Event to notify when a suspicious packet is detected
            public event Action<string> OnSuspiciousPacketDetected;



            public HttpPacket ParseHttpPacket(string payload)
            {
                var httpPacket = new HttpPacket();

                // Example parsing logic (simplified)
                var lines = payload.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
                if (lines.Length > 0)
                {
                    var requestLine = lines[0].Split(' ');
                    httpPacket.Method = requestLine[0];
                    httpPacket.Url = requestLine.Length > 1 ? requestLine[1] : null;
                }

                httpPacket.Headers = lines
                    .Skip(1)
                    .TakeWhile(line => !string.IsNullOrWhiteSpace(line))
                    .Select(line => line.Split(new[] { ": " }, 2, StringSplitOptions.None))
                    .Where(parts => parts.Length == 2)
                    .ToDictionary(parts => parts[0], parts => parts[1]);

                return httpPacket;
            }
            public class HttpPacket
            {
                public string Method { get; set; }
                public string Url { get; set; }
                public Dictionary<string, string> Headers { get; set; }
            }



            // Method to analyze a packet
            public void AnalyzePacketHTTP(TcpPacket tcpPacket)
            {
                try
                {
                    // Extract the payload data from the TcpPacket
                    string packetData = Encoding.UTF8.GetString(tcpPacket.PayloadData);

                    // Step 1: Check for unusual User-Agent strings
                    if (ContainsUnusualUserAgent(packetData))
                    {
                        RaiseAlert("Unusual User-Agent detected.");
                    }

                    // Step 2: Check for excessive POST requests
                    if (IsExcessivePostRequest(packetData))
                    {
                        RaiseAlert("Excessive POST requests detected.");
                    }

                    // Step 3: Check for suspicious paths or parameters
                    if (ContainsSuspiciousPathsOrParameters(packetData))
                    {
                        RaiseAlert("Suspicious paths or parameters detected.");
                    }

                    // Step 4: Check for command & control patterns
                    if (ContainsCommandAndControlPatterns(packetData))
                    {
                        RaiseAlert("Potential command & control patterns detected.");
                    }

                    // Step 5: Check for abnormal request timing
                    if (HasAbnormalRequestTiming(packetData))
                    {
                        RaiseAlert("Abnormal request timing detected.");
                    }

                    // Step 6: Check for encoded payloads in headers
                    if (ContainsEncodedPayloads(packetData))
                    {
                        RaiseAlert("Encoded payloads in headers detected.");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error analyzing packet: {ex.Message}");
                }
            }

            private bool ContainsUnusualUserAgent(string packetData)
            {
                // Simulate checking User-Agent header for unusual strings
                string pattern = @"User-Agent:.*(curl|wget|python|unknown-bot)"; // Example pattern
                return Regex.IsMatch(packetData, pattern, RegexOptions.IgnoreCase);
            }

            private bool IsExcessivePostRequest(string packetData)
            {
                // Check if the packet contains a POST request
                string postPattern = @"POST\s+\/";
                return Regex.IsMatch(packetData, postPattern, RegexOptions.IgnoreCase);
            }

            private bool ContainsSuspiciousPathsOrParameters(string packetData)
            {
                // Check for suspicious paths or parameters
                string suspiciousPattern = @"\/(admin|config|shell|cmd)\b";
                return Regex.IsMatch(packetData, suspiciousPattern, RegexOptions.IgnoreCase);
            }

            private bool ContainsCommandAndControlPatterns(string packetData)
            {
                // Check for command & control-like patterns
                string c2Pattern = @"(exec|eval|system|base64_decode)\(";
                return Regex.IsMatch(packetData, c2Pattern, RegexOptions.IgnoreCase);
            }

            private bool HasAbnormalRequestTiming(string packetData)
            {
                // Simulate abnormal timing check (requires timing analysis)
                // Example: Look for patterns suggesting automated requests
                return false; // Placeholder, requires real timing data
            }

            private bool ContainsEncodedPayloads(string packetData)
            {
                // Check for encoded payloads in headers
                string encodedPattern = @"(Content-Encoding:.*base64|%[0-9a-fA-F]{2})";
                return Regex.IsMatch(packetData, encodedPattern, RegexOptions.IgnoreCase);
            }

            private void RaiseAlert(string message)
            {
                // Trigger the alert event
                OnSuspiciousPacketDetected?.Invoke(message);
                Console.WriteLine($"Alert: {message}");
            }
        }
    }
}