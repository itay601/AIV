CREATE DATABASE Samples;
USE Samples;

-- Table for Hashes
CREATE TABLE Hashes (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    Sha256 VARCHAR(64),
    Sha3_384 VARCHAR(96),
    Sha1 VARCHAR(40),
    Md5 VARCHAR(32),
    Humanhash TEXT
);

-- Table for FileInfo
CREATE TABLE FileInfo (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    FileName TEXT,
    FileSize BIGINT,
    FileType TEXT,
    MimeType TEXT,
    OriginCountry TEXT,
    FirstSeen DATETIME,
    LastSeen DATETIME
);

-- Table for DeliveryMethods (list of delivery methods in FileInfo)
CREATE TABLE DeliveryMethods (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    FileInfoId INT,
    DeliveryMethod TEXT,
    FOREIGN KEY (FileInfoId) REFERENCES FileInfo(Id)
);

-- Table for Classification
CREATE TABLE Classification (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    MalwareFamily TEXT,
    ThreatLevel INT,
    DetectionConfidence INT
);

-- Table for ClassificationTags (list of tags in Classification)
CREATE TABLE ClassificationTags (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    ClassificationId INT,
    Tag TEXT,
    FOREIGN KEY (ClassificationId) REFERENCES Classification(Id)
);

-- Table for Behavior
CREATE TABLE Behavior (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    CpuChecks BOOLEAN,
    MemoryChecks BOOLEAN,
    RuntimeBroadcastReceiver BOOLEAN,
    TaskScheduling BOOLEAN,
    CryptoApiUsage BOOLEAN,
    SensorEnvironmentMonitoring BOOLEAN,
    MccQuery BOOLEAN,
    BatteryOptimizationRequest BOOLEAN,
    DroppedDexJar BOOLEAN,
    AccessibilityServiceUsage BOOLEAN,
    ClipboardDataAccess BOOLEAN,
    InstalledAppListQuery BOOLEAN,
    PhoneNumberQuery BOOLEAN
);

-- Table for Ioc
CREATE TABLE Ioc (
    Id INT AUTO_INCREMENT PRIMARY KEY
);

-- Table for C2Servers (list of C2 servers in Ioc)
CREATE TABLE C2Servers (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    IocId INT,
    C2Server TEXT,
    FOREIGN KEY (IocId) REFERENCES Ioc(Id)
);

-- Table for VendorDetection
CREATE TABLE VendorDetection (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    Vendor TEXT,
    Verdict TEXT,
    ThreatLevel DOUBLE,
    Confidence INT,
    Link TEXT,
    Score INT,
    ThreatName TEXT,
    Family TEXT
);

-- Table for YaraRule
CREATE TABLE YaraRule (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    RuleName TEXT,
    Author TEXT,
    Description TEXT
);

-- Table for SignituresDataClasses
CREATE TABLE SignituresDataClasses (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    HashesId INT,
    FileInfoId INT,
    ClassificationId INT,
    BehaviorId INT,
    IocId INT,
    FOREIGN KEY (HashesId) REFERENCES Hashes(Id),
    FOREIGN KEY (FileInfoId) REFERENCES FileInfo(Id),
    FOREIGN KEY (ClassificationId) REFERENCES Classification(Id),
    FOREIGN KEY (BehaviorId) REFERENCES Behavior(Id),
    FOREIGN KEY (IocId) REFERENCES Ioc(Id)
);

-- Table for VendorDetections in SignituresDataClasses
CREATE TABLE SignituresVendorDetections (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    SignituresDataClassesId INT,
    VendorDetectionId INT,
    FOREIGN KEY (SignituresDataClassesId) REFERENCES SignituresDataClasses(Id),
    FOREIGN KEY (VendorDetectionId) REFERENCES VendorDetection(Id)
);

-- Table for YaraRules in SignituresDataClasses
CREATE TABLE SignituresYaraRules (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    SignituresDataClassesId INT,
    YaraRuleId INT,
    FOREIGN KEY (SignituresDataClassesId) REFERENCES SignituresDataClasses(Id),
    FOREIGN KEY (YaraRuleId) REFERENCES YaraRule(Id)
);
