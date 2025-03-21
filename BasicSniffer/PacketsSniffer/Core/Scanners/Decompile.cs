using System;
using Mono.Cecil;
using Mono.Cecil.Cil;


namespace PacketsSniffer.Core.Scanners
{
  
    public class Decompiler
    {
        public static void AnalyzeAssembly(string assemblyPath)
        {
            // Load the assembly
            var module = ModuleDefinition.ReadModule(assemblyPath);

            // Iterate through all types in the assembly
            foreach (var type in module.Types)
            {
                Console.WriteLine($"Type: {type.FullName}");

                // Iterate through methods in the type
                foreach (var method in type.Methods)
                {
                    Console.WriteLine($"  Method: {method.Name} ({method.ReturnType}) ");

                    // Decompile IL code of the method
                    if (method.HasBody)
                    {
                        Console.WriteLine("    IL Code:");
                        foreach (var instruction in method.Body.Instructions)
                        {
                            Console.WriteLine($"      {instruction.OpCode} {instruction.Operand}");
                        }
                    }
                }
            }
        }
    }
}
