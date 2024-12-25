using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PacketsSniffer.Core.Detection;

namespace PacketsSniffer.Core.Database.SamplesSignitures
{
    public class DNSQuery
    {
        public string Domain { get; set; }
        public ushort Type { get; set; }
        public ThreatPacketsAnalyzer.DnsRecordType RecordType { get; internal set; }
    }
    public class Hashes
    {
        public string Sha256 { get; set; }
        public string Sha3_384 { get; set; }
        public string Sha1 { get; set; }
        public string Md5 { get; set; }
        public string Humanhash { get; set; }
    }
    public class FileInfo
    {
        public string FileName { get; set; }
        public long FileSize { get; set; }
        public string FileType { get; set; }
        public string MimeType { get; set; }
        public string OriginCountry { get; set; }
        public DateTime? FirstSeen { get; set; }
        public DateTime? LastSeen { get; set; }
        public List<string> DeliveryMethods { get; set; }
    }
    public class Classification
    {
        public string MalwareFamily { get; set; }
        public int ThreatLevel { get; set; }
        public int DetectionConfidence { get; set; }
        public List<string> Tags { get; set; }
    }
    public class Behavior
    {
        public bool CpuChecks { get; set; }
        public bool MemoryChecks { get; set; }
        public bool RuntimeBroadcastReceiver { get; set; }
        public bool TaskScheduling { get; set; }
        public bool CryptoApiUsage { get; set; }
        public bool SensorEnvironmentMonitoring { get; set; }
        public bool MccQuery { get; set; }
        public bool BatteryOptimizationRequest { get; set; }
        public bool DroppedDexJar { get; set; }
        public bool AccessibilityServiceUsage { get; set; }
        public bool ClipboardDataAccess { get; set; }
        public bool InstalledAppListQuery { get; set; }
        public bool PhoneNumberQuery { get; set; }
    }

    public class Ioc
    {
        public List<string> C2Servers { get; set; }
    }

    public class VendorDetection
    {
        public string Vendor { get; set; }
        public string Verdict { get; set; }
        public double? ThreatLevel { get; set; }
        public int? Confidence { get; set; }
        public string Link { get; set; }
        public int? Score { get; set; }
        public string ThreatName { get; set; }
        public string Family { get; set; }
    }

    public class YaraRule
    {
        public string RuleName { get; set; }
        public string Author { get; set; }
        public string Description { get; set; }
    }

    public class SignituresDataClasses
    {
        public Hashes Hashes { get; set; }
        public FileInfo FileInfo { get; set; }
        public Classification Classification { get; set; }
        public Behavior Behavior { get; set; }
        public Ioc Ioc { get; set; }
        public List<VendorDetection> VendorDetections { get; set; }
        public List<YaraRule> YaraRules { get; set; }


    }


}
/*
 {
  "hashes": {
    "sha256": "2e6c7354f7b4dce59752054929731c5055df15301ed094820bdbbcd5c0cfa12e",
    "sha3_384": "e1f2d2fa24e90f09c6be64819d42a4e6af0f0192e5b8a5f286189854f76e343eb8e7af20bd0ed0015913573fb39c3c66",
    "sha1": "db165b084b44f98cd47540f4c73a8ab8feb05660",
    "md5": "125591b1ba792dc40478fba12b09970c",
    "humanhash": "carbon-november-lemon-echo"
  },
  "file_info": {
    "file_name": "12.apk",
    "file_size": 8095859,
    "file_type": "apk",
    "mime_type": "application/zip",
    "origin_country": "DE",
    "first_seen": "2024-12-18T15:37:27Z",
    "last_seen": null,
    "delivery_methods": []
  },
  "classification": {
    "malware_family": "TrickMo",
    "threat_level": 10,
    "detection_confidence": 100,
    "tags": [
      "family:trickmo",
      "android",
      "banker",
      "collection",
      "credential_access",
      "discovery",
      "evasion",
      "execution",
      "impact",
      "infostealer",
      "persistence",
      "trojan"
    ]
  },
  "behavior": {
    "cpu_checks": true,
    "memory_checks": true,
    "runtime_broadcast_receiver": true,
    "task_scheduling": true,
    "crypto_api_usage": true,
    "sensor_environment_monitoring": true,
    "mcc_query": true,
    "battery_optimization_request": true,
    "dropped_dex_jar": true,
    "accessibility_service_usage": true,
    "clipboard_data_access": true,
    "installed_app_list_query": true,
    "phone_number_query": true
  },
  "ioc": {
    "c2_servers": [
      "http://skyfrostweb.cn.com/c"
    ]
  },
  "vendor_detections": [
    {
      "vendor": "ClamAV",
      "verdict": "Gathering data"
    },
    {
      "vendor": "FileScan.IO",
      "verdict": "Unknown",
      "threat_level": 2.5,
      "confidence": 100,
      "link": "https://www.filescan.io/uploads/6762ec609ce6256fa2fe74f6/reports/ecfa84fc-dcda-4cdf-85c5-0d4ef3755fd8/overview"
    },
    {
      "vendor": "Nucleon Malprob",
      "verdict": "Malware",
      "score": 100,
      "link": "https://malprob.io/report/2e6c7354f7b4dce59752054929731c5055df15301ed094820bdbbcd5c0cfa12e"
    },
    {
      "vendor": "ReversingLabs TitaniumCloud",
      "verdict": "Suspicious",
      "threat_name": "Android.Infostealer.Generic",
      "threat_level": 5,
      "link": "https://labs.inquest.net/dfi/sha256/2e6c7354f7b4dce59752054929731c5055df15301ed094820bdbbcd5c0cfa12e"
    },
    {
      "vendor": "Spamhaus",
      "verdict": "Suspicious",
      "link": "https://check.spamhaus.org/check/?searchterm=fzwhgvhxwtoolf2savess4y4kbk56fjqd3ijjaql3o6nlqgpuexa._file"
    },
    {
      "vendor": "Hatching Triage",
      "verdict": "Malware",
      "family": "TrickMo",
      "score": 10,
      "link": "https://tria.ge/reports/241218-s22gystmhs/"
    }
  ],
  "yara_rules": [
    {
      "rule_name": "golang_david_CSC846",
      "author": "David",
      "description": "CSC-846 Golang"
    },
    {
      "rule_name": "Packer_Android",
      "author": "R3R0K",
      "description": "Android.Packer_Android"
    },
    {
      "rule_name": "Sus_Obf_Enc_Spoof_Hide_PE",
      "author": "XiAnzheng",
      "description": "Check for Overlay, Obfuscating, Encrypting, Spoofing, Hiding, or Entropy Technique(can create FP)"
    },
    {
      "rule_name": "XWorm_3_0_3_1_Detection",
      "author": "Archevod",
      "description": "Detects XWorm versions 3.0 and 3.1"
    }
  ]
}
 */