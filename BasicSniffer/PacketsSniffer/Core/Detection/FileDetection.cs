using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using PacketsSniffer.Core.Database.SamplesSignitures;


namespace PacketsSniffer.Core.Detection
{
    class FileDetection
    {
        private readonly string _connectionString = "Server=127.0.0.1;Port=3456;Database=YourDatabaseName;Uid=root;Pwd=my-secret-pw;";

        public FileDetection(string connectionString)
        {
            _connectionString = connectionString;
        }

        // Fetch malware hashes from the database
        private List<string> FetchMalwareHashes()
        {
            var hashes = new List<string>();

            using (var connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                var query = "SELECT Sha256 FROM Hashes";
                using (var command = new SqlCommand(query, connection))
                {
                    using (var reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            hashes.Add(reader.GetString(0)); // Read the Sha256 column
                        }
                    }
                }
            }

            return hashes;
        }
        private void InsertMalwareHashes()
        {

        }

        // Calculate the SHA-256 hash of a file
        private string ComputeSha256Hash(string filePath)
        {
            using (var sha256 = SHA256.Create())
            {
                using (var stream = File.OpenRead(filePath))
                {
                    var hashBytes = sha256.ComputeHash(stream);
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                }
            }
        }

        // Check a single file against malware hashes
        public bool CheckFile(string filePath)
        {
            try
            {
                var fileHash = ComputeSha256Hash(filePath);
                var malwareHashes = FetchMalwareHashes();

                return malwareHashes.Contains(fileHash);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error checking file {filePath}: {ex.Message}");
                return false;
            }
        }

        // Check all files on the computer
        public void CheckAllFiles(string rootDirectory = "C:\\")
        {
            try
            {
                var malwareHashes = FetchMalwareHashes();

                foreach (var filePath in Directory.EnumerateFiles(rootDirectory, "*.*", SearchOption.AllDirectories))
                {
                    try
                    {
                        var fileHash = ComputeSha256Hash(filePath);
                        if (malwareHashes.Contains(fileHash))
                        {
                            Console.WriteLine($"Malware detected: {filePath}");
                        }
                    }
                    catch (UnauthorizedAccessException)
                    {
                        Console.WriteLine($"Access denied: {filePath}");
                    }
                    catch (IOException ex)
                    {
                        Console.WriteLine($"Error reading file {filePath}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error scanning files: {ex.Message}");
            }
        }
    }
}
