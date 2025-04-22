using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace PacketsSniffer.Core.Utilities
{
    public static class PEChecker
    {
        // PE file signature is 'PE\0\0'
        private const uint PE_SIGNATURE = 0x00004550;

        // Offset of the PE signature pointer in the DOS header
        private const int PE_POINTER_OFFSET = 0x3C;

        // DOS magic number 'MZ'
        private const ushort DOS_SIGNATURE = 0x5A4D;

        /// <summary>
        /// Checks if a file is a valid PE format executable
        /// </summary>
        /// <param name="filePath">Path to the file to check</param>
        /// <returns>True if the file is a valid PE file, false otherwise</returns>
        public static bool IsValidPEFile(string filePath)
        {
            try
            {
                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    // Check file size
                    if (fs.Length < 64) // Minimum size for a PE file
                    {
                        return false;
                    }

                    using (BinaryReader reader = new BinaryReader(fs))
                    {
                        // Check DOS header signature (MZ)
                        ushort dosSignature = reader.ReadUInt16();
                        if (dosSignature != DOS_SIGNATURE)
                        {
                            return false;
                        }

                        // Seek to the PE header offset location
                        fs.Position = PE_POINTER_OFFSET;
                        uint peOffset = reader.ReadUInt32();

                        // Validate the PE offset is within the file
                        if (peOffset >= fs.Length - 4)
                        {
                            return false;
                        }

                        // Seek to PE header location
                        fs.Position = peOffset;

                        // Check PE signature
                        uint peSignature = reader.ReadUInt32();
                        return peSignature == PE_SIGNATURE;
                    }
                }
            }
            catch (Exception ex)
            {
                //Console.WriteLine($"Error checking PE format: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Checks if a PE file is a .NET assembly
        /// </summary>
        /// <param name="filePath">Path to the PE file</param>
        /// <returns>True if the file is a .NET assembly, false otherwise</returns>
        public static bool IsDotNetAssembly(string filePath)
        {
            if (!IsValidPEFile(filePath))
            {
                return false;
            }

            try
            {
                // Try to load as .NET assembly
                System.Reflection.AssemblyName.GetAssemblyName(filePath);
                return true;
            }
            catch (BadImageFormatException)
            {
                // Not a .NET assembly
                return false;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Gets more detailed information about a PE file
        /// </summary>
        /// <param name="filePath">Path to the PE file</param>
        /// <returns>A string with information about the PE file</returns>
        public static Dictionary<string,object> GetPEFileInfo(string filePath)
        {
            if (!IsValidPEFile(filePath))
            {
                return new Dictionary<string, object> { { "IsValidPE", false } };
            }

            try
            {
                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                using (BinaryReader reader = new BinaryReader(fs))
                {
                    // Read DOS header
                    ushort dosSignature = reader.ReadUInt16();

                    // Seek to PE offset
                    fs.Position = PE_POINTER_OFFSET;
                    uint peOffset = reader.ReadUInt32();

                    // Go to PE header
                    fs.Position = peOffset;
                    uint peSignature = reader.ReadUInt32();

                    // Read Machine type
                    ushort machine = reader.ReadUInt16();

                    // Read Number of sections
                    ushort numberOfSections = reader.ReadUInt16();

                    // Read TimeDateStamp
                    uint timeDateStamp = reader.ReadUInt32();
                    DateTime compilationTime = new DateTime(1970, 1, 1).AddSeconds(timeDateStamp);

                    // Skip some fields
                    reader.ReadUInt32(); // PointerToSymbolTable
                    reader.ReadUInt32(); // NumberOfSymbols

                    // Read size of optional header
                    ushort sizeOfOptionalHeader = reader.ReadUInt16();

                    // Read characteristics
                    ushort characteristics = reader.ReadUInt16();

                    bool isDll = (characteristics & 0x2000) != 0;
                    bool isExe = (characteristics & 0x0002) != 0;

                    string machineType = GetMachineType(machine);

                    return new Dictionary<string, object>
                    {
                        { "IsValidPE"  , true },
                        { "FileName", Path.GetFileName(filePath) },
                        { "MachineType", machineType },
                        { "CompilationTime", compilationTime },
                        { "NumberOfSections", numberOfSections },
                        { "FileType", isDll ? "DLL" : isExe ? "EXE" : "Unknown" },
                        { "IsDotNetAssembly", IsDotNetAssembly(filePath) },
                        { "Characteristics", characteristics }
                    };
                }
            }
            catch (Exception ex)
            {
                return new Dictionary<string, object>
                {
                    { "IsValidPE", false },
                    { "Error", ex.Message }
                };
            }
        }

        private static string GetMachineType(ushort machine)
        {
            switch (machine)
            {
                case 0x014c: return "x86 (32-bit)";
                case 0x0200: return "Intel Itanium";
                case 0x8664: return "x64 (64-bit)";
                case 0x01c4: return "ARM";
                case 0xAA64: return "ARM64";
                default: return $"Unknown ({machine:X4})";
            }
        }
    }
}
