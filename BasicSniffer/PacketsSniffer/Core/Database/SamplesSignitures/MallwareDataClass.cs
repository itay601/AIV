using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketsSniffer.Core.Database.SamplesSignitures
{
    class MallwareDataClass
    {
        public string _Sha256 { get; set; }
        public General _Label { get; set; }
     
    }
    class General
    {
        public int _FileSize { get; set; }
        public int _Vsize {  get; set; }
        public int _Has_debug {  get; set; } 
        public int _Exports {  get; set; }
        public int _Imports{ get; set; }
        public int _HasRelocations { get; set; }
        public int _HasResources { get; set; }

        public int _HasSignature { get; set; }
        public int _HasTLS{ get; set; }
        public int _Symbols { get; set; }

    }
}
