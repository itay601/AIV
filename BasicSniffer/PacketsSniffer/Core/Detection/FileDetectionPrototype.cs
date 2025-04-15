using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using MySql.Data.MySqlClient;
using PacketsSniffer.Core.Database.SamplesSignitures;


namespace PacketsSniffer.Core.Detection
{
    class FileDetectionPrototype
    {
        private readonly string _connectionString;//LOCAL IMAGE MYSQL
        public FileDetectionPrototype()
        {
            _connectionString = "Server=127.0.0.1;port=3456;database=Samples;uid=root;pwd=my-secret-pw;";
        }

        //Fetch malware hashes from the database
        private List<string> FetchMalwareHashes()
        {
            var hashes = new List<string>();
            using (var connection = new MySqlConnection(_connectionString))
            {
                connection.Open();
                var query = "SELECT Sha256 FROM Hashes";
                using (var command = new MySqlCommand(query, connection))
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
        public bool CheckFileIfHashISOFMalware(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    Console.WriteLine($"File does not exist: {filePath}");
                    return false;
                }

                var fileHash = ComputeSha256Hash(filePath);
                var malwareHashes = FetchMalwareHashes();
                return malwareHashes.Contains(fileHash);
            }
            catch (Exception ex)
            {
                // Log the full exception details
                Console.WriteLine($"Error checking file {filePath}:");
                Console.WriteLine($"Exception type: {ex.GetType().Name}");
                Console.WriteLine($"Message: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                throw; // Re-throw to see the full error chain
            }
        }

        // Check all files on the computer
        /// <summary>
        /// check all files in system NOT IMPLIMENTED !!!!!!!!!!!!
        /// </summary>
        /// <param name="rootDirectory"></param>
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
