using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace PacketsSniffer.Core.Models
{
    public class SectionDataPEFile
    {
        public static List<Dictionary<string,object>> ExtractSectionInfo(string filePath)
        {
            using (var stream = File.OpenRead(filePath))
            using (var peReader = new PEReader(stream))
            {
                var headers = peReader.PEHeaders;
                var sectionHeaders = headers.SectionHeaders;

                // Determine the section that contains the entry point (if available).
                string entrySectionName = "";
                if (headers.PEHeader != null)
                {
                    int entryPoint = headers.PEHeader.AddressOfEntryPoint;
                    foreach (var section in sectionHeaders)
                    {
                        // Check if the entry point address falls in the virtual address range of this section.
                        if (entryPoint >= section.VirtualAddress && entryPoint < section.VirtualAddress + section.VirtualSize)
                        {
                            entrySectionName = section.Name;
                            break;
                        }
                    }
                }

                // Build section details.
                List<Dictionary<string, object>> sectionInfos = new List<Dictionary<string, object>>();
                foreach (var section in sectionHeaders)
                {
                    // Some sections may have no raw data so we need to handle that.
                    byte[] sectionBytes = new byte[section.SizeOfRawData];

                    // The raw data offset is specified by the section.
                    // PEReader.GetEntireImage can be used to get the complete file content.
                    var peImage = peReader.GetEntireImage();
                    if (peImage.Length >= section.PointerToRawData + section.SizeOfRawData)
                    {
                        sectionBytes = peImage.GetReader(section.PointerToRawData, section.SizeOfRawData).ReadBytes(section.SizeOfRawData);
                    }
                    else
                    {
                        // Fallback: if the section's raw bytes cannot be fully read.
                        sectionBytes = new byte[0];
                    }

                    double entropy = CalculateShannonEntropy(sectionBytes);
                    List<string> props = GetSectionProperties(section.SectionCharacteristics);

                    sectionInfos.Add(new Dictionary<string, object>
                    {
                        ["Name"] = section.Name,
                        ["Size"] = section.SizeOfRawData,
                        ["Entropy"] = Math.Round(entropy, 6),
                        ["VSize"] = section.VirtualSize,
                        ["Props"] = props
                    });
                }

                // Build final JSON structure.
                var result = new
                {
                    section = new
                    {
                        entry = entrySectionName,
                        sections = sectionInfos
                    }
                };

                // Serialize output to JSON with indented formatting.
                var json = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
                Console.WriteLine(json);
                return sectionInfos;
            }
        }

        /// <summary>
        /// Calculates the Shannon entropy of a byte array.
        /// </summary>
        /// <param name="data">The data bytes.</param>
        /// <returns>The calculated entropy value.</returns>
        public static double CalculateShannonEntropy(byte[] data)
        {
            if (data == null || data.Length == 0)
                return 0;

            var frequency = new double[256];
            foreach (var b in data)
            {
                frequency[b]++;
            }

            double entropy = 0;
            int len = data.Length;
            for (int i = 0; i < 256; i++)
            {
                if (frequency[i] > 0)
                {
                    double p = frequency[i] / len;
                    entropy -= p * Math.Log(p, 2);
                }
            }
            return entropy;
        }

        /// <summary>
        /// Determines the properties of a section from its characteristics.
        /// </summary>
        /// <param name="characteristics">The section characteristics.</param>
        /// <returns>A list of string properties.</returns>
        private static List<string> GetSectionProperties(SectionCharacteristics characteristics)
        {
            var props = new List<string>();

            if ((characteristics & SectionCharacteristics.ContainsCode) != 0)
                props.Add("CNT_CODE");

            if ((characteristics & SectionCharacteristics.ContainsInitializedData) != 0)
                props.Add("CNT_INITIALIZED_DATA");

            if ((characteristics & SectionCharacteristics.ContainsUninitializedData) != 0)
                props.Add("CNT_UNINITIALIZED_DATA");

            if ((characteristics & SectionCharacteristics.MemExecute) != 0)
                props.Add("MEM_EXECUTE");

            if ((characteristics & SectionCharacteristics.MemRead) != 0)
                props.Add("MEM_READ");

            if ((characteristics & SectionCharacteristics.MemWrite) != 0)
                props.Add("MEM_WRITE");
            return props;
        }
    }
}