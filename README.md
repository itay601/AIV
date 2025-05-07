# Antivirus Project

## AIV: Advanced Intrusion Visualization & Analysis
- Welcome to AIV, a sophisticated system for packet analysis, process scanning, and static analysis of Portable Executable (PE) files. This project integrates a Windows client console application developed in C# with multiple microservices built using FastAPI, providing functionality similar to Wireshark alongside advanced machine learning analysis for security monitoring.

----------------------------------------------------------------------------------------------------------------------
### Table of Contents 
- [Project Overview ](https://github.com/itay601/AIV/edit/main/README.md#project-overview)
- [Components](https://github.com/itay601/AIV/edit/main/README.md#components)
  - [Client Application (C#)](https://github.com/itay601/AIV/edit/main/README.md#client-application-c) 
  - [** Microservices **](https://github.com/itay601/AIV/edit/main/README.md#microservices)
    - [ Autoencoder Service](https://github.com/itay601/AIV/edit/main/README.md#autoencoder-service)
    - [ Transformer Service](https://github.com/itay601/AIV/edit/main/README.md#transformer-service)
    - [ Backend Routing Service](https://github.com/itay601/AIV/edit/main/README.md#backend-routing-service)
  - [Database (MySQL)](https://github.com/itay601/AIV/edit/main/README.md#database)
- [Features](https://github.com/itay601/AIV/edit/main/README.md#features)
- [Setup & Installation](https://github.com/itay601/AIV/edit/main/README.md#components)
  - [Download the Client App](https://github.com/itay601/AIV/edit/main/README.md#components)
  - [Local Setup with Docker](https://github.com/itay601/AIV/edit/main/README.md#components)
- [Usage](https://github.com/itay601/AIV/edit/main/README.md#usage)
- [Structure Details](https://github.com/itay601/AIV/edit/main/README.md#structure-details)
- [License](https://github.com/itay601/AIV/edit/main/README.md#license)

----------------------------------------------------------------------------------------------------------------------

### Project Overview
##### AIV is designed to serve as a comprehensive packet analysis and security monitoring tool with the following objectives:

* Packet Analysis & Presentation: A client console application written in C# that captures, analyzes, and displays network packets (similar to Wireshark) in real time.

* Process Scanning: It scans all running processes using the executable along with machine learning techniques to detect unusual process behaviors.

* Static PE Analysis: Performs static analysis on .NET binaries by extracting detailed information from executable (EXE) and dynamic link library (DLL) files. It leverages the EMBER dataset for in-depth static analysis.

### Machine Learning Microservices:
- Autoencoder for Packet Analysis: A custom autoencoder model to identify anomalous packets.
- Transformer Encoder for Classification: A FastAPI microservice that uses a transformer encoder architecture to classify unusual packets.
- Backend Service: A FastAPI-based backend routes client requests to the appropriate microservices.
- Database: A simple MySQL microservice is prepared for storing and managing project-specific data, with custom table schemas (currently in development/standalone).

----------------------------------------------------------------------------------------------------------------------
### Components
##### Client Application (C#)

Developed as a Windows console application.

Responsibilities:

Capture and analyze network packets.

Present data in a user-friendly format.

Scan running processes to identify suspicious activities.

Extract details from EXE and DLL files using the EMBER dataset.

----------------------------------------------------------------------------------------------------------------------
#### Microservices
##### The project utilizes Docker to deploy and manage microservices which are built with FastAPI:

##### Autoencoder Service

Purpose: Detect unusual network packets using your custom autoencoder model.

Deployment: Available as a Docker image (itay601/itay601-images:autoencoder-v1.0).

##### Transformer Service

Purpose: Classify packets for security analysis.

Deployment: Available as a Docker image (itay601/itay601-images:transformer-v1.0).

##### Backend Routing Service

Purpose: Acts as the central hub that routes requests between the client and other microservices.

Deployment: Available as a Docker image (itay601/itay601-images:v1.0).

##### Database (MySQL)

A basic MySQL microservice has been set up to handle data storage.

Status: The database includes foundational table structures and schema design, with integration to the other components currently in progress.

----------------------------------------------------------------------------------------------------------------------
#### Features

Real-Time Packet Analysis: Monitor live network traffic similar to Wireshark.

Process and Static PE Analysis: Comprehensive scanning and analysis of running processes and .NET binaries.

Anomaly Detection with Autoencoder: Automated detection of unusual network activity.

Classification with Transformer Encoder: High-performance classification of abnormal packets.

Microservice Deployment: All major services are containerized with Docker for scalability and ease of deployment.

Modular Architecture: Easily extendable and maintainable structure to support future enhancements.

----------------------------------------------------------------------------------------------------------------------
#### Setup & Installation

Download the Client App
Download the AV Client Application for Windows:

##### 👉 [Click here to download AV Client App (.exe)](https://github.com/itay601/Packet-Sniffer/blob/main/BasicSniffer/Antivirus-setup/Release/Antivirus-setup.msi)

Local Setup with Docker
Prerequisites
Docker: Ensure you have Docker installed on your local machine. You can download it from Docker's official website.
Pull the Microservices
Open your terminal and pull the required Docker images using the following commands:

docker pull itay601/itay601-images:autoencoder-v1.0
docker pull itay601/itay601-images:transformer-v1.0
docker pull itay601/itay601-images:v1.0  # (Backend Routing Service)

----------------------------------------------------------------------------------------------------------------------
#### Usage
Run the Microservices:
Start each image using Docker:

bash

Copy
docker run -d -p 5000:5000 itay601/itay601-images:autoencoder-v1.0
docker run -d -p 5001:5001 itay601/itay601-images:transformer-v1.0
docker run -d -p 5002:5002 itay601/itay601-images:v1.0


Start the Client:

Launch the downloaded Windows client application. Ensure that the microservices are accessible from the client by configuring the correct endpoint URIs if necessary.

Monitor & Analyze:

Utilize the client to capture network packets, scan running processes, and perform static analysis on .NET binaries.

----------------------------------------------------------------------------------------------------------------------
#### Structure Details

##### Client Console Application

- Implementation: C# application that integrates:
- Packet Capture and Presentation: Real-time network data analysis similar to Wireshark.
- Process Analysis: Scanning of all running processes, leveraging machine learning for anomaly detection.
- Static Analysis: Detailed parsing of PE files (EXE, DLL) using data from the EMBER dataset.
##### Microservices
##### FastAPI Autoencoder Service:
Implements a custom autoencoder algorithm to flag unusual packets.
##### FastAPI Transformer Service:
Utilizes an encoder-only transformer model for packet classification.
##### FastAPI Backend Service:
Routes client requests and orchestrates communication between services.
##### Database
- MySQL Setup:

A simple MySQL microservice configured for data persistence.

Contains preliminary schema definitions, with plans for further integration.

----------------------------------------------------------------------------------------------------------------------
#### License
### MIT License

Copyright (c) [2025] [Itay Marlinsly]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

1. **Attribution and Third-Party Licenses:**  
   - This project incorporates the **EMBER dataset** for machine learning and deep learning processes. Use of the EMBER dataset is subject to the terms and conditions provided by its original authors. By using this project, you agree to comply with the EMBER dataset license and acknowledge that any models or analysis results derived from it are subject to those terms.
   - This project employs **MonoCIL LIB** to perform manual static analysis on Portable Executable (PE) files. Use of MonoCIL LIB is governed by its own license, and you must comply with all applicable terms and conditions as specified in the MonoCIL LIB documentation and license file.

2. **Redistribution:**  
   Redistributions of source code must retain the above copyright
   notice, this list of conditions, and the following disclaimer.

3. **Disclaimer:**  
   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.

4. **Third-Party Components:**  
   - **EMBER Dataset:** Usage of the EMBER dataset must strictly adhere to the terms of its license. Redistribution of the dataset or derivative works based on the dataset (without explicit permission) is prohibited.
   - **MonoCIL LIB:** All usage of MonoCIL LIB within this project is in compliance with its license. Any modifications or distributions involving MonoCIL LIB must reflect the original license and attribution as required by its maintainers.

By using or distributing this software, you acknowledge that you have read and understood these terms.

