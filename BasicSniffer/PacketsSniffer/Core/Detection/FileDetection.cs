using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PacketsSniffer.Core.Database.SamplesSignitures;


namespace PacketsSniffer.Core.Detection
{
    class FileDetection
    {
        List<SignituresDataClasses> _MalwareSignitures = new List<SignituresDataClasses>();
        
        
        public void CheckMalwareSignature(Hashes hash ,FileInfo fileInfo ,Classification malwareType ,Behavior behave,
            Ioc c2servers,VendorDetection analisys, YaraRule yara)
        {
            SignituresDataClasses k = new SignituresDataClasses();
            k.Hashes = hash;
            
            
            
            
            //in the end
            _MalwareSignitures.Add(k);
        }
        public void FetchMalwaresSignituresFromDB()
        {

        }
        public void FetectFileMalwaresSignituresFromDB()
        {

        }
        public void DetectDirMalwaresSignituresFromDB()
        {

        }

    }
}
