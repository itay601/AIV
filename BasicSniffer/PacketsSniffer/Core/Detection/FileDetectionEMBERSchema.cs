using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Diagnostics;
using System.Reflection;
using Mono.Cecil;
using PacketsSniffer.Core.Utilities;

namespace PacketsSniffer.Core.Detection
{
    class FileDetectionEMBERSchema
    {
        public Dictionary<string, object> _AnalyzedFile;
        public Dictionary<string, object> AnalyzeFile(string filePath)
        {
            try
            {
                _AnalyzedFile = new Dictionary<string, object>
                {
                    ["sha256"] = ComputeSha256Hash(filePath),
                    ["label"] = -1,
                    ["general"] = new Dictionary<string, object>
                    {
                        ["file_size"] = ComputeFileSize(filePath),
                        ["vsize"] = PrintSectionsVirtualSizes(filePath),
                        ["has_debug"] = PEUtility.IsAssemblyBuiltWithDebug(filePath),
                        ["exports"] = PEUtility.CountExports(filePath),
                        ["imports"] = PEUtility.CountImports(filePath),
                        //["has_relocations"] = PEUtility.HasRelocation(filePath),
                        ["has_resources"] = PEUtility.HasResources(filePath),
                        ["has_signiture"] = PEUtility.HasSigniture(filePath),
                        //["has_tls"] = PEUtility.HasTLS(filePath),
                        //["symbols"] = PEUtility.Symbols(filePath),
                    },
                    /*"header": {
                        "coff": {
                        "timestamp": 1365446976,
                        "machine": "I386",
                        "characteristics": [ "LARGE_ADDRESS_AWARE", ..., "EXECUTABLE_IMAGE" ]
                    },*/
                    ["header"] = new Dictionary<string, object>
                    {
                        ["coff"] = new Dictionary<string, object>
                        {
                            //["timestamp"] = PEUtility.CountImports(filePath),
                            //["machine"] = PEUtility.CountImports(filePath),
                            //["characteristics"] = PEUtility.CountImports(filePath),
                        },

                        ["optional"] = new Dictionary<string, object>
                        {
                            //["subsystem"] = PEUtility.CountImports(filePath),
                            //["dll_characteristics"] = PEUtility.CountImports(filePath),
                            //["magic"] = PEUtility.CountImports(filePath),
                        }
                    },


                };
                
                // Now send processInfo for further processing (example: for ML or logging)
                return _AnalyzedFile;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error analyzing process {filePath}: {ex.Message}");
                return new Dictionary<string, object>();
            }
            //var k = 
        }
        private string ComputeSha256Hash(string filePath)
        {
            using (var sha256 = SHA256.Create())
            {
                using (var stream = File.OpenRead(filePath))
                {
                    var hashBytes = sha256.ComputeHash(stream);
                    Console.WriteLine(BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant());
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                }
            }
        }
        private long ComputeFileSize(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("filePath not found", filePath);
            }
            FileInfo fileInfo = new FileInfo(filePath);
            long fileSize = fileInfo.Length; // filePath size in bytes
            Console.WriteLine(fileSize);
            return fileSize;
        }
        /// <summary>
        /// Reads the PE file and prints the VirtualSize of each section.
        /// </summary>
        /// <param name="filePath">The path of the PE file (.exe or .dll).</param>
        public static long PrintSectionsVirtualSizes(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("File not found", filePath);
            }

            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            using (BinaryReader br = new BinaryReader(fs))
            {
                // Read the DOS header to get the PE header offset.
                fs.Seek(0x3C, SeekOrigin.Begin);
                int peHeaderOffset = br.ReadInt32();

                // Move to the PE header.
                fs.Seek(peHeaderOffset, SeekOrigin.Begin);
                uint peSignature = br.ReadUInt32();
                if (peSignature != 0x00004550) // "PE\0\0" in little-endian
                {
                    throw new Exception("Invalid PE signature.");
                }

                // Read the COFF header.
                ushort machine = br.ReadUInt16();
                ushort numberOfSections = br.ReadUInt16();
                uint timeDateStamp = br.ReadUInt32();
                uint pointerToSymbolTable = br.ReadUInt32();
                uint numberOfSymbols = br.ReadUInt32();
                ushort sizeOfOptionalHeader = br.ReadUInt16();
                ushort characteristics = br.ReadUInt16();

                // Skip the Optional header. (Alternatively, you can read SizeOfImage here if needed.)
                long optionalHeaderStart = fs.Position;
                // For illustration, we could extract the overall image size:
                // For PE32, SizeOfImage is at offset 56 from the Optional header start.
                // For PE32+, the offset is usually 56 as well, but the header size is different.
                fs.Seek(optionalHeaderStart + 56, SeekOrigin.Begin);
                uint sizeOfImage = br.ReadUInt32();
                Console.WriteLine($"Overall SizeOfImage : {sizeOfImage} bytes");
                return sizeOfImage;
            }
        }
    }
}
