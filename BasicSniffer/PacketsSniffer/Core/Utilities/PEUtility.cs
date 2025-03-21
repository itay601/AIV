using System;
using System.Configuration.Assemblies;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Reflection;
using System.Runtime.CompilerServices;
using Mono.Cecil;
using Mono.Cecil.PE;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using PacketsSniffer.Core.Models;




namespace PacketsSniffer.Core.Utilities
{
    public static class PEUtility
    {
        /// <summary>
        /// Counts the number of imported functions in the assembly.
        /// Here, an "import" is considered as any method with a PInvoke implementation.
        /// </summary>
        /// <param name="assemblyPath">The path to the .NET assembly.</param>
        /// <returns>The count of imported functions.</returns>
        public static int CountImports(string assemblyPath)
        {
            // Read the assembly using Mono.Cecil
            var assemblyDef = AssemblyDefinition.ReadAssembly(assemblyPath);
            int importCount = 0;

            // Iterate through all modules, types, and methods
            foreach (var module in assemblyDef.Modules)
            {
                foreach (var type in module.Types)
                {
                    foreach (var method in type.Methods)
                    {
                        // A method is considered to be a P/Invoke import if it has an external implementation.
                        if (method.IsPInvokeImpl)
                        {
                            importCount++;
                        }
                    }
                }
            }
            Console.WriteLine($"Imports : {importCount}");
            return importCount;
        }

        /// <summary>
        /// Counts the number of exported functions in the assembly.
        /// In managed assemblies, exports are not built-in. Tools like DllExport add a custom attribute.
        /// Here, we look for any method with a custom attribute whose type name contains "DllExport".
        /// Adjust the condition based on the actual export attribute your project uses.
        /// </summary>
        /// <param name="assemblyPath">The path to the .NET assembly.</param>
        /// <returns>The count of exported functions.</returns>
        public static int CountExports(string assemblyPath)
        {
            // Read the assembly using Mono.Cecil
            var assemblyDef = AssemblyDefinition.ReadAssembly(assemblyPath);
            int exportCount = 0;

            // Iterate through all modules, types, and methods
            foreach (var module in assemblyDef.Modules)
            {
                foreach (var type in module.Types)
                {
                    foreach (var method in type.Methods)
                    {
                        // Check for a custom attribute that indicates an export.
                        // This is heuristic; if your export attribute uses a different name, change the condition accordingly.
                        bool isExported = method.CustomAttributes.Any(attr =>
                            attr.AttributeType.FullName.IndexOf("DllExport", StringComparison.OrdinalIgnoreCase) >= 0);
                        if (isExported)
                        {
                            exportCount++;
                        }
                    }
                }
            }
            Console.WriteLine($"Exports : {exportCount}");
            return exportCount;
        }

        /// <summary>
        /// indicates that symbol information (eg., from a .pdb) is available.
        /// 
        /// </summary>
        /// <param name="assemblyPath">The path to the EXE or DLL file.</param>
        /// <returns>
        ///   <c>true</c> if the assembly has debugging enabled (i.e. is a Debug build); 
        ///   otherwise, <c>false</c>.
        /// </returns>
        public static bool IsAssemblyBuiltWithDebug(string assemblyPath)
        {
            // Configure reading parameters to load symbols, if available.
            var readerParams = new ReaderParameters { ReadSymbols = true };
            try
            {
                var module = ModuleDefinition.ReadModule(assemblyPath);//, readerParams);
                bool hasDebugInfo = module.HasSymbols;
                Console.WriteLine("Debug Symbols available: " + hasDebugInfo);
                return hasDebugInfo;
            }
            catch (Exception ex)
            {
                throw new Exception($"NO READER PARAMS : {ex}");
                //return false;
            }
        }



        public static bool HasResources(string filePath)
        {
            // Configure reading parameters to load symbols, if available.
            var readerParams = new ReaderParameters { ReadSymbols = true };
            try
            {
                // Read the assembly (module) from the given path.
                var module = ModuleDefinition.ReadModule(filePath, readerParams);
                bool hasResources = module.Resources.Any();
                Console.WriteLine(hasResources);
                return hasResources;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        public static object HasSigniture(string filePath)
        {
            // Configure reading parameters to load symbols, if available.
            var readerParams = new ReaderParameters { ReadSymbols = true };
            try
            {
                // Read the assembly (module) from the given path.
                var module = ModuleDefinition.ReadModule(filePath, readerParams);
                // Check for a strong name signature by examining if the assembly has a public key.
                bool hasSignature = module.Assembly != null && module.Assembly.Name.HasPublicKey;
                Console.WriteLine("Has Strong Name Signature: " + hasSignature);
                return hasSignature;
            }
            catch (Exception ex)
            {
                throw new Exception("hasSigniture func problem");
            }
        }

        internal static object HasTLS(string filePath)
        {
            throw new NotImplementedException();
        }

        public static bool HasRelocation(string filePath)
        {
            return true;
        }


        //internal static object Symbols(string filePath)
        //{
        //    // Configure reading parameters to load symbols, if available.
        //    var readerParams = new ReaderParameters { ReadSymbols = true };
        //    try
        //    {
        //        // Read the assembly (module) from the given path.
        //        var module = ModuleDefinition.ReadModule(filePath, readerParams);
        //        // Mono.Cecil does not provide a direct symbol count. If symbols are loaded, you might
        //        // inspect parts of the debug information. Here, we count the number of unique document
        //        // entries which can serve as a proxy.
        //        var hasDebugInfo = PEUtility.IsAssemblyBuiltWithDebug(filePath);
        //        int symbolCount = 0;
        //        if (hasDebugInfo && module.SymbolReader != null)
        //        {
        //            // Count the documents referenced in debugging information.
        //            symbolCount = module.SymbolReader.GetDocuments().Count();
        //        }
        //            return hasSignature;
        //    }
        //    catch (Exception ex)
        //    {
        //        throw new Exception("hasSigniture func problem");
        //    }
        //}



        /// <summary>
        /// this is for the Header file (PE file) 
        /// the coff (timestamp , machine , strings) 
        /// NOT SURE HOW THE DATA IS REAL DATA!!!!!!!!!!!!!!!!!!!!!!!
        /// </summary>
        // PE file constants
        private const uint PE_SIGNATURE_OFFSET = 0x3C;
        private const uint PE_SIGNATURE = 0x00004550;  // "PE\0\0"


        // File characteristic flags
        private const ushort IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
        private const ushort IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020;
        private static readonly Dictionary<string, string> MachineTypes = new Dictionary<string, string>()
        {
            { "0x014C", "x86" },
            { "0x8664", "x64" },
            { "0x0200", "Itanium" },
            // Add more as needed
            { "0x0000", "Unknown" } // Default for unrecognized values
        };

        // File characteristic flags
        private static readonly Dictionary<ushort, string> CharacteristicsFlags = new Dictionary<ushort, string>
        {
            { 0x0001, "RELOCS_STRIPPED" },
            { 0x0002, "EXECUTABLE_IMAGE" },
            { 0x0004, "LINE_NUMS_STRIPPED" },
            { 0x0008, "LOCAL_SYMS_STRIPPED" },
            { 0x0010, "AGGRESSIVE_WS_TRIM" },
            { 0x0020, "LARGE_ADDRESS_AWARE" },
            { 0x0080, "BYTES_REVERSED_LO" },
            { 0x0100, "32BIT_MACHINE" },
            { 0x0200, "DEBUG_STRIPPED" },
            { 0x0400, "REMOVABLE_RUN_FROM_SWAP" },
            { 0x0800, "NET_RUN_FROM_SWAP" },
            { 0x1000, "SYSTEM" },
            { 0x2000, "DLL" },
            { 0x4000, "UP_SYSTEM_ONLY" },
            { 0x8000, "BYTES_REVERSED_HI" }
        };
        public static Dictionary<String, object> ReadPEHeaderCoff(string filePath)
        {
            try
            {
                var coff = new Dictionary<string, object>();
                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    using (BinaryReader reader = new BinaryReader(fs))
                    {
                        // Read the PE signature offset from the DOS header
                        fs.Seek(PE_SIGNATURE_OFFSET, SeekOrigin.Begin);
                        uint peOffset = reader.ReadUInt32();

                        // Move to the PE signature
                        fs.Seek(peOffset, SeekOrigin.Begin);
                        uint peSignature = reader.ReadUInt32();

                        if (peSignature != PE_SIGNATURE)
                        {
                            Console.WriteLine("Invalid PE file signature");
                            return (null);
                        }

                        // Read the COFF header
                        ushort machine = reader.ReadUInt16();
                        ushort numberOfSections = reader.ReadUInt16();
                        uint timestamp = reader.ReadUInt32();
                        uint pointerToSymbolTable = reader.ReadUInt32();
                        uint numberOfSymbols = reader.ReadUInt32();
                        ushort sizeOfOptionalHeader = reader.ReadUInt16();
                        ushort characteristics = reader.ReadUInt16();

                        // Create JSON-like output
                        Console.WriteLine("\"header\": {");
                        Console.WriteLine("  \"coff\": {");
                        Console.WriteLine($"    \"timestamp\": {timestamp},");
                        Console.WriteLine($"    \"machine\": {MachineTypes["0x" + machine.ToString("X4")]} ");  //{machine.ToString("X4")}\",");

                        // Extract all characteristics
                        List<string> characteristicsList = new List<string>();
                        foreach (var flag in CharacteristicsFlags)
                        {
                            if ((characteristics & flag.Key) != 0)
                            {
                                characteristicsList.Add($"\"{flag.Value}\"");
                            }
                        }

                        Console.WriteLine("    \"characteristics\": [");
                        Console.WriteLine("      " + string.Join(",\n      ", characteristicsList));
                        Console.WriteLine("    ]");
                        Console.WriteLine("  }");
                        Console.WriteLine("}");
                        coff["timestamp"] = timestamp;

                        coff["machine"] = MachineTypes["0x" + machine.ToString("X4")];
                        coff["characteristics"] = characteristicsList;
                        return (coff);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return null;
            }
        }
        public static Dictionary<string, object> ExactHeaderOptional(string filePath)
        {
            try
            {
                // Load the assembly using Mono.Cecil (if needed for further analysis)
                AssemblyDefinition assembly = AssemblyDefinition.ReadAssembly(filePath);
                ModuleDefinition module = assembly.MainModule;

                // Now extract the PE header details as a dictionary
                Dictionary<string, object> headerDetails = ExtractPeHeaderOptional(filePath);

                // Print the details
                foreach (var kvp in headerDetails)
                {
                    if (kvp.Value is Array arr)
                    {
                        Console.WriteLine($"{kvp.Key}: {string.Join(", ", arr)}");
                    }
                    else
                    {
                        Console.WriteLine($"{kvp.Key}: {kvp.Value}");
                    }
                }
                return headerDetails;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error extracting PE header: " + ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Extract PE header details from the given executable/dll file.
        /// This reads the Optional Header of the PE format manually.
        /// </summary>
        /// <param name="filePath">Full path to the PE file</param>
        /// <returns>Dictionary with header fields and values</returns>
        public static Dictionary<string, object> ExtractPeHeaderOptional(string filePath)
        {
            Dictionary<string, object> headerDict = new Dictionary<string, object>();

            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            using (BinaryReader reader = new BinaryReader(fs))
            {
                // --- DOS Header ---
                // The DOS header is 64 bytes; at offset 0x3C there is a 4-byte pointer to the PE header
                fs.Seek(0x3C, SeekOrigin.Begin);
                int peHeaderOffset = reader.ReadInt32();

                // --- PE Header Signature ---
                fs.Seek(peHeaderOffset, SeekOrigin.Begin);
                uint peSignature = reader.ReadUInt32(); // Should read "PE\0\0" (0x00004550)
                if (peSignature != 0x00004550)
                    throw new Exception("Invalid PE signature.");

                // --- COFF File Header (20 bytes) ---
                // We skip the contents as they are not used in this example.
                fs.Seek(20, SeekOrigin.Current);

                // --- Optional Header ---
                // Read the Magic value to distinguish between PE32 and PE32+.
                ushort magic = reader.ReadUInt16();
                // 0x10b = PE32, 0x20b = PE32+
                string magicStr = (magic == 0x10b) ? "PE32" : (magic == 0x20b) ? "PE32+" : "Unknown";
                headerDict["magic"] = magicStr;

                // Read Linker Version
                byte majorLinkerVersion = reader.ReadByte();
                byte minorLinkerVersion = reader.ReadByte();
                headerDict["major_linker_version"] = (int)majorLinkerVersion;
                headerDict["minor_linker_version"] = (int)minorLinkerVersion;

                // Read SizeOfCode (4 bytes)
                uint sizeofCode = reader.ReadUInt32();
                headerDict["sizeof_code"] = sizeofCode;

                // For completeness, read SizeOfInitializedData and SizeOfUninitializedData (4 bytes each)
                uint sizeofInitializedData = reader.ReadUInt32();
                uint sizeofUninitializedData = reader.ReadUInt32();

                // Read AddressOfEntryPoint, BaseOfCode (4 bytes each)
                uint addressOfEntryPoint = reader.ReadUInt32();
                uint baseOfCode = reader.ReadUInt32();

                uint baseOfData = 0;
                if (magic == 0x10b)
                {
                    // PE32: BaseOfData exists
                    baseOfData = reader.ReadUInt32();
                }

                // Read ImageBase (4 bytes for PE32, 8 bytes for PE32+)
                ulong imageBase = (magic == 0x10b) ? reader.ReadUInt32() : reader.ReadUInt64();

                // SectionAlignment and FileAlignment (4 bytes each)
                uint sectionAlignment = reader.ReadUInt32();
                uint fileAlignment = reader.ReadUInt32();

                // --- Version Numbers ---
                // MajorOperatingSystemVersion and MinorOperatingSystemVersion (2 bytes each)
                ushort majorOS = reader.ReadUInt16();
                ushort minorOS = reader.ReadUInt16();
                headerDict["major_operating_system_version"] = majorOS;
                headerDict["minor_operating_system_version"] = minorOS;

                // MajorImageVersion and MinorImageVersion (2 bytes each)
                ushort majorImageVersion = reader.ReadUInt16();
                ushort minorImageVersion = reader.ReadUInt16();
                headerDict["major_image_version"] = majorImageVersion;
                headerDict["minor_image_version"] = minorImageVersion;

                // MajorSubsystemVersion and MinorSubsystemVersion (2 bytes each)
                ushort majorSubsystemVersion = reader.ReadUInt16();
                ushort minorSubsystemVersion = reader.ReadUInt16();
                headerDict["major_subsystem_version"] = majorSubsystemVersion;
                headerDict["minor_subsystem_version"] = minorSubsystemVersion;

                // Skip Win32VersionValue (4 bytes)
                uint win32VersionValue = reader.ReadUInt32();

                // SizeOfImage (4 bytes) and SizeOfHeaders (4 bytes)
                uint sizeOfImage = reader.ReadUInt32();
                uint sizeOfHeaders = reader.ReadUInt32();
                headerDict["sizeof_headers"] = sizeOfHeaders;

                // CheckSum (4 bytes) – skip
                uint checkSum = reader.ReadUInt32();

                // --- Subsystem and DllCharacteristics ---
                ushort subsystem = reader.ReadUInt16();
                string subsystemStr;
                switch (subsystem)
                {
                    case 1:
                        subsystemStr = "NATIVE";
                        break;
                    case 2:
                        subsystemStr = "WINDOWS_GUI";
                        break;
                    case 3:
                        subsystemStr = "WINDOWS_CUI";
                        break;
                    default:
                        subsystemStr = "UNKNOWN";
                        break;
                }
                headerDict["subsystem"] = subsystemStr;

                ushort dllCharacteristics = reader.ReadUInt16();
                List<string> dllFlags = new List<string>();
                // See Microsoft's documentation for flags.
                if ((dllCharacteristics & 0x0040) != 0) dllFlags.Add("DYNAMIC_BASE");
                if ((dllCharacteristics & 0x0080) != 0) dllFlags.Add("FORCE_INTEGRITY");
                if ((dllCharacteristics & 0x0100) != 0) dllFlags.Add("NX_COMPAT");
                if ((dllCharacteristics & 0x0200) != 0) dllFlags.Add("NO_ISOLATION");
                if ((dllCharacteristics & 0x0400) != 0) dllFlags.Add("NO_SEH");
                if ((dllCharacteristics & 0x0800) != 0) dllFlags.Add("NO_BIND");
                if ((dllCharacteristics & 0x1000) != 0) dllFlags.Add("APPCONTAINER");
                if ((dllCharacteristics & 0x2000) != 0) dllFlags.Add("WDM_DRIVER");
                if ((dllCharacteristics & 0x4000) != 0) dllFlags.Add("GUARD_CF");
                if ((dllCharacteristics & 0x8000) != 0) dllFlags.Add("TERMINAL_SERVER_AWARE");
                headerDict["dll_characteristics"] = dllFlags.ToArray();

                // --- Heap and Stack Sizes ---
                // The order here is as follows for PE32 and (similarly for PE32+ with adjusted sizes):
                // SizeOfStackReserve (4 bytes), SizeOfStackCommit (4 bytes),
                // SizeOfHeapReserve (4 bytes), SizeOfHeapCommit (4 bytes)
                uint sizeOfStackReserve = reader.ReadUInt32();
                uint sizeOfStackCommit = reader.ReadUInt32();
                uint sizeOfHeapReserve = reader.ReadUInt32();
                uint sizeOfHeapCommit = reader.ReadUInt32();
                headerDict["sizeof_heap_commit"] = sizeOfHeapCommit;

                // You can continue further if you want to extract more fields.
            }
            return headerDict;
        }
        public static Dictionary<string, List<string>> ExtractPeImports(string filePath)
        {
            // Dictionary to hold the import information.
            Dictionary<string, List<string>> imports = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            try
            {
                // Read the assembly from the given file path.
                var assembly = AssemblyDefinition.ReadAssembly(filePath);

                // Iterate over each module in the assembly.
                foreach (var module in assembly.Modules)
                {
                    // Iterate over each type in the module.
                    foreach (var type in module.Types)
                    {
                        // Iterate over every method of the type.
                        foreach (var method in type.Methods)
                        {
                            // Print out the method name and its declaring type.
                            //Console.WriteLine(method.Name);
                            //Console.WriteLine(method.DeclaringType);

                            // Get the full name of the declaring type.
                            string fullTypeName = method.DeclaringType.FullName;

                            // Find the position of the last dot.
                            int lastDotIndex = fullTypeName.LastIndexOf('.');

                            // Take the substring after the last dot (or the entire string if no dot found)
                            string dllNameBase = lastDotIndex >= 0 && lastDotIndex < fullTypeName.Length - 1
                                ? fullTypeName.Substring(lastDotIndex + 1)
                                : fullTypeName;

                            // Append ".dll" to form the DLL name.
                            string dllName = dllNameBase + ".dll";

                            // If the dictionary does not have this DLL, add it.
                            if (!imports.ContainsKey(dllName))
                            {
                                imports[dllName] = new List<string>();
                            }
                            // Add the method name if not already added.
                            if (!imports[dllName].Contains(method.Name))
                            {
                                imports[dllName].Add(method.Name);
                            }
                        }
                    }
                }


                // Convert the resulting dictionary into JSON with indentation.
                var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
                string jsonOutput = JsonSerializer.Serialize(new { Imports = imports }, jsonOptions);
                Console.WriteLine(jsonOutput);

                return imports;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing {filePath}: {ex.Message}");
                return new Dictionary<string, List<string>>();
            }
        }

        public static List<string> ExtractExports(string filePath)
        {
            // Read the file as a binary
            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                // Create a PE image from the file (if needed)
                // Note: The variable `peReader` can be used to get additional info if required.
                using (var peReader = new PEReader(fs))
                {
                    Console.WriteLine("\nExported Functions:");

                    // Create a module definition using Mono.Cecil to access exports
                    ModuleDefinition module = ModuleDefinition.ReadModule(filePath);

                    // Display exported types and their public methods
                    if (module.HasExportedTypes)
                    {
                        foreach (var exportedType in module.ExportedTypes)
                        {
                            Console.WriteLine($"Type: {exportedType.FullName}");

                            // Resolve the type to inspect its methods (if possible)
                            TypeDefinition resolvedType = exportedType.Resolve();
                            if (resolvedType != null)
                            {
                                foreach (var method in resolvedType.Methods.Where(m => m.IsPublic))
                                {
                                    Console.WriteLine($"  Method: {method.Name}");
                                }
                            }
                        }
                    }

                    // Get native exports (more common in DLLs) by calling the helper method.
                    List<string> nativeExports = GetNativeExports(module);
                    if (nativeExports.Count > 0)
                    {
                        foreach (var export in nativeExports)
                        {
                            Console.WriteLine($"Export: {export}");
                        }
                    }
                    return nativeExports;
                }
            }
        }

        /// <summary>
        /// Attempts to extract native export names from the given module using reflection.
        /// </summary>
        /// <param name="module">The module definition (Mono.Cecil) of the assembly.</param>
        /// <returns>A list of native export names.</returns>
        static List<string> GetNativeExports(ModuleDefinition module)
        {
            List<string> exports = new List<string>();

            try
            {
                // Use reflection to access the internal PE image property.
                var peImageProperty = module.GetType().GetProperty("Image", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
                var peImage = peImageProperty?.GetValue(module);

                if (peImage != null)
                {
                    // Attempt to get the ExportDirectory property from the PE image.
                    var exportDirectoryProperty = peImage.GetType().GetProperty("ExportDirectory", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
                    var exportDirectory = exportDirectoryProperty?.GetValue(peImage);

                    if (exportDirectory != null)
                    {
                        // Get the Entries property that holds individual export entries.
                        var entriesProperty = exportDirectory.GetType().GetProperty("Entries", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
                        var entries = entriesProperty?.GetValue(exportDirectory) as System.Collections.IEnumerable;

                        if (entries != null)
                        {
                            foreach (var entry in entries)
                            {
                                var nameProp = entry.GetType().GetProperty("Name", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
                                var name = nameProp?.GetValue(entry)?.ToString();
                                if (!string.IsNullOrEmpty(name))
                                {
                                    exports.Add(name);
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting native exports: {ex.Message}");
            }

            return exports;
        }



        public static Dictionary<string, List<string>> GetReferencedAssemblies(string filePath)
        {
            var references = new Dictionary<string, List<string>>();
            var assembly = AssemblyDefinition.ReadAssembly(filePath);

            foreach (var module in assembly.Modules)
            {
                foreach (var reference in module.AssemblyReferences)
                {
                    if (!references.ContainsKey(reference.Name))
                        references[reference.Name] = new List<string>();

                    references[reference.Name].Add(reference.FullName);
                }
            }
            var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
            Console.WriteLine(JsonSerializer.Serialize(new { Imports = references }, jsonOptions));
            return references;
        }

        /// <summary>
        /// Generates a standard byte histogram with 256 bins, which counts
        /// how many times each byte value (0-255) occurs in the input data.
        /// </summary>
        /// <param name="data">The input file data.</param>
        /// <returns>An array of 256 integers.</returns>
        public static int[] GetByteHistogram(byte[] data)
        {
            int[] histogram = new int[256];
            foreach (byte b in data)
            {
                histogram[b]++;
            }
            return histogram;
        }

        /// <summary>
        /// Generates a byte-entropy histogram by sliding a window through the data.
        /// For each window, the Shannon entropy is computed and quantized into 16 bins.
        /// Then, each byte in the window is quantized into 16 bins and the corresponding
        /// count is incremented. Finally, the 16x16 histogram is flattened into a
        /// single array of 256 integers.
        /// </summary>
        /// <param name="data">The input file data.</param>
        /// <param name="windowSize">Size of the sliding window (default 2048 bytes).</param>
        /// <param name="stepSize">Step size for sliding the window (default 1024 bytes).</param>
        /// <returns>A flattened 16x16 (256-element) histogram.</returns>
        public static int[] GetByteEntropyHistogram(byte[] data, int windowSize = 2048, int stepSize = 1024)
        {
            // Create a 16x16 histogram matrix.
            int[,] entropyHist = new int[16, 16];

            // Slide the window through the data.
            for (int offset = 0; offset < data.Length; offset += stepSize)
            {
                // Ensure we do not go past the end of the file.
                int currentWindowSize = Math.Min(windowSize, data.Length - offset);
                byte[] window = new byte[currentWindowSize];
                Array.Copy(data, offset, window, 0, currentWindowSize);

                // Calculate the window's Shannon entropy (range: 0 to ~8 for byte data).
                double entropy = SectionDataPEFile.CalculateShannonEntropy(window);
                // Expected value in range 0 to 8
                // Quantize the entropy into 16 bins. Each bin corresponds to an entropy interval of 8/16 = 0.5.
    
                int entropyBin = (int)(entropy / 8.0 * 16);
                if (entropyBin >= 16)
                {
                    entropyBin = 15;
                }

                // For each byte in the window, quantize the byte into 16 bins.
                for (int i = 0; i < currentWindowSize; i++)
                {
                    int byteBin = window[i] / 16;  // Each bin covers 16 byte values (0-15).
                    entropyHist[entropyBin, byteBin]++;
                }
            }

            // Flatten the 16x16 histogram matrix into a one-dimensional 256-element array.
            int[] flattened = new int[256];
            int index = 0;
            for (int i = 0; i < 16; i++)
            {
                for (int j = 0; j < 16; j++)
                {
                    flattened[index++] = entropyHist[i, j];
                }
            }
            return flattened;
        }
      






    }
}



