# SIEM-Lite

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Docker](https://img.shields.io/badge/docker-enabled-blue)
![Language](https://img.shields.io/badge/language-C%23%20%7C%20Python-blue)
![Framework](https://img.shields.io/badge/framework-.NET%2010-purple)

**SIEM-Lite** is a containerized security pipeline designed to capture, ingest, and analyze network traffic in real-time. It bridges the gap between raw packet sniffing and high-level security visualization, providing a "single pane of glass" view into network health and threat activity.

## System Architecture

The application is built using a microservices architecture, completely containerized via Docker for easy deployment and isolation.

* **Live Sensor (`Log_Generator.py`)**: A Python-based sensor using **Scapy** to sniff live network interfaces or generate test traffic. It converts raw L2-L4 packets into structured JSON telemetry and transmits them to the ingest engine.
* **Ingest & Analysis Engine (C#/.NET 10)**: A high-performance middleware service that receives logs via REST API, performs data normalization, handles damaged payloads, and evaluates data against a signature-based threat detection library.
* **The Elastic Stack (ELK)**: 
    * **Elasticsearch**: A NoSQL document-oriented database used to index logs for sub-second retrieval.
    * **Kibana**: The visualization layer where analysts interact with live dashboards and review flagged incidents.

---

## Getting Started

### Prerequisites
* [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running.
* [Python 3.10+](https://www.python.org/downloads/) installed locally.
* **Nping/Nmap** (Optional, for generating test packets).

### Installation & Execution
1.  **Clone the Repository**
    ```bash
    git clone [https://github.com/YOUR-USERNAME/SIEM-Lite.git](https://github.com/YOUR-USERNAME/SIEM-Lite.git)
    cd SIEM-Lite
    ```
2.  **Install Sensor Dependencies**
    ```bash
    pip install scapy requests
    ```
3.  **One-Click Deployment**
    Double-click the `Run-SIEM.bat` file in the root directory. 
    * This script builds the C# Engine, spins up the Elastic Stack, and launches the Python sensor in a dedicated terminal window once the API is healthy.

---

## Kibana Configuration
To visualize your data, you must configure a **Data View** upon the first run:

1.  Open **Kibana** at [http://localhost:5601](http://localhost:5601).
2.  Navigate to **Stack Management** > **Data Views**.
3.  Click **Create Data View**.
4.  **Index Pattern**: Enter `siem-logs*` (Kibana will recognize the index once the first log is sent).
5.  **Timestamp Field**: Select `timestamp`.
6.  Navigate to the **Discover** tab to view live traffic.

---

## Threat Detection Capabilities
The C# Engine automatically evaluates logs against predefined security rules, flagging activity as **Low**, **Medium**, or **High** severity:

* **Suspicious Port Access**: Detects attempts to reach sensitive ports like SSH (22), RDP (3389), or Telnet (23).
* **Malicious Payloads**: Scans message content for SQL Injection (`OR 1=1`, `SELECT`) and Cross-Site Scripting (`<script>`) signatures.
* **Automated Tooling**: Identifies signatures from security tools like `Nmap` or `Curl` based on User-Agent strings.

---

## Testing the Pipeline
To verify the rules engine is working, run the following commands in a separate PowerShell window to trigger alerts:

* **Trigger SSH Alert**:
    `Test-NetConnection -ComputerName 1.1.1.1 -Port 22`
* **Trigger Scripting Alert**:
    `curl http://localhost:5000/api/ingest -UserAgent "Nmap Scripting Engine"`