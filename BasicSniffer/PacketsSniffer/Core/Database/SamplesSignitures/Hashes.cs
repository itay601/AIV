using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketsSniffer.Core.Database.SamplesSignitures
{
    public class Hashes
    {
        public string Sha256 { get; set; }
        public string Sha3_384 { get; set; }
        public string Sha1 { get; set; }
        public string Md5 { get; set; }
        public string Humanhash { get; set; }

        private void GetSignituresHashMallwares() { }
        private void MakeHashSha256(string filePath) { }
        private void MakeSha1() { }
        private void MakeHashMD5() { }
    }
}
