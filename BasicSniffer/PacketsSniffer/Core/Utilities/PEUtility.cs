using System;
using System.Configuration.Assemblies;
using System.Linq;
using System.Runtime.CompilerServices;
using Mono.Cecil;
using static System.Net.Mime.MediaTypeNames;



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
                var module = ModuleDefinition.ReadModule(assemblyPath, readerParams);
                bool hasDebugInfo = module.HasSymbols;
                Console.WriteLine("Debug Symbols available: " + hasDebugInfo);
                return hasDebugInfo;
            }
            catch (Exception ex) {
                throw new Exception("NO READER PARAMS");
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


    }
}
