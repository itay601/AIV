using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace PacketsSniffer.Core.Detection
{
    class FileDetectionEMBERSchema
    {
        public Dictionary<string, object> _AnalyzedFile = new Dictionary<string, object>();
        public void AnalyzeFile(string file)
        {
            var s = ComputeSha256Hash(file);
            Console.WriteLine(s);
            //var k = 
        } 
        private string ComputeSha256Hash(string filePath)
        {
            using (var sha256 = SHA256.Create())
            {
                using (var stream = File.OpenRead(filePath))
                {
                    var hashBytes = sha256.ComputeHash(stream);
                    _AnalyzedFile["sha256"] = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                }
            }
        }
    }
}
