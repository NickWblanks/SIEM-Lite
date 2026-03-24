# SIEM-Lite

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Docker](https://img.shields.io/badge/docker-enabled-blue)
![Architecture](https://img.shields.io/badge/architecture-microservices-orange)

SIEM-Lite is a custom, lightweight Security Information and Event Management (SIEM) pipeline. It is designed to simulate, ingest, parse, and visualize network traffic to detect and flag malicious activity in real-time. 

This project demonstrates the end-to-end lifecycle of security data, from raw generation to indexed storage and visual analysis.

## System Architecture

The application is built using a microservices architecture, completely containerized via Docker for easy deployment and isolation.

* **Log Generator (`Log_Generator.py`)**: A Python-based traffic simulator. It continuously generates realistic network logs to `stdout`, simulating:
    * **Benign Traffic:** Standard `200 OK` web requests.
    * **Anomalies & Errors:** Malformed JSON, truncated data, and brute-force login attempts (`401`/`403`).
    * **Active Threats:** Clear attack signatures including SQL Injection (SQLi), Cross-Site Scripting (XSS), and Path Traversal attempts.
* **Parsing & Rules Engine (`Parsing_Engine.cs`)**: The core C#/.NET backend service. It ingests the raw data stream, normalizes the logs, handles damaged payloads gracefully, and evaluates the data against predefined security rules to flag suspicious behavior.
* **Data Storage (Elasticsearch)**: A NoSQL document-oriented database used to index the parsed logs, allowing for blazing-fast, complex queries across millions of events.
* **Threat Dashboard (`Analysis.js` / React)**: A frontend interactive web application designed for security analysts to visualize traffic spikes, pinpoint attack origins, and review flagged incidents.

## Getting Started

*(Instructions will be updated as the Docker Compose infrastructure is finalized.)*

### Prerequisites
* [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running.

### Installation & Execution
1. Clone the repository:
   ```bash
   git clone [https://github.com/YOUR-USERNAME/SIEM-Lite.git](https://github.com/YOUR-USERNAME/SIEM-Lite.git)
   cd SIEM-Lite