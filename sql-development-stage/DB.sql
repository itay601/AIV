CREATE DATABASE Samples;
USE Samples;

-- Table for Hashes Malwares (from EMBER dataset)
CREATE TABLE MalwareHashes (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    Sha256 VARCHAR(64),
    Sha1 VARCHAR(40),
    Md5 VARCHAR(32)
);

INSERT INTO MalwareHashes (Sha256, Sha1, Md5) VALUES 
('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', 'd41d8cd98f00b204e9800998ecf8427e'),
('a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e', '3da541559918a808c2402bba5012f6c60b27661c', 'c1ea66c70a5f71dc503e2be5182340db'),
('6dcd4ce23d88e2ee9568ba546c007c63d9131c1b85f7ab2cbb3ff65e9a8a88af', 'fb96549631c835eb239cd614cc6b5cb7d295121a', 'eb9279c3c0e604e5e7c90874bb9ed9ef');

-- Table for UserInfo needed registration 
CREATE TABLE UserInfo (
    Email VARCHAR(50) PRIMARY KEY ,
    HashesDatabaseMatch BOOLEAN,
    AEModelClassifier BOOLEAN,
    TransformerClassifier BOOLEAN,
    FirstRegistered DATETIME,
    LastSeen DATETIME 
);

INSERT INTO UserInfo (Email , HashesDatabaseMatch , AEModelClassifier , TransformerClassifier , FirstRegistered , LastSeen) VALUES
("a@walla.co.il" , FALSE, FALSE, FALSE, '2025-03-02 14:22:15', '2025-04-27 19:10:05'),
("john.doe@example.com", FALSE, FALSE, FALSE, '2025-01-15 08:30:00', '2025-04-28 12:45:22'),
("itay47561@gmail.com" ,FALSE ,FALSE ,FALSE ,'2025-01-15 08:30:00', '2025-04-28 13:45:22');

-- Table for UserInfo needed registration 
CREATE TABLE MaliciousContentPerUser (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    Email VARCHAR(50),
    HashesDatabaseMatch TEXT,
    AEModelClassifier TEXT,
    TransformerClassifier TEXT,
    SeenAt DATETIME 
);