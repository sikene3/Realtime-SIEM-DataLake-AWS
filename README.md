

Uploading Video_Project_24_compressed.mp4…

# 🛡️ Real-Time AI-Driven SIEM Data Lake Architecture

![Architecture](https://img.shields.io/badge/Architecture-Distributed_System-blue)
![Data Engineering](https://img.shields.io/badge/Focus-Data_Engineering_&_MLOps-orange)
![Cloud](https://img.shields.io/badge/Cloud-AWS_S3-yellow?logo=amazon-aws)
![Infrastructure](https://img.shields.io/badge/Infrastructure-Docker_Compose-blue?logo=docker)

An enterprise-grade, end-to-end Real-Time Security Information and Event Management (SIEM) Data Lake built on the **Medallion Architecture**. This distributed system ingests simulated high-velocity server logs via **Apache Kafka**, structures and stores them as optimized **Parquet** formats inside an **AWS S3 Bronze Layer**, evaluates threats via an automated **AI Security Agent**, pushes curated data to the **Silver Layer**, and serves a live intelligence **Gold Layer Dashboard** via **Streamlit**.

---

## 📁 Project File Architecture

```text
Data Lake & Cybersecurity SIEM/
├── docker-compose.yml                    # Infrastructure: Kafka & Zookeeper stack
├── logs_ingestion/
│   ├── kafka_producer.py                 # Live server traffic & attack vector simulator
│   └── kafka_to_s3_consumer.py           # Bronze Layer: Kafka consumer & micro-batching engine
├── ai_agents/
│   └── ai_security_agent.py              # Silver Layer: AI threat detector & S3 archiver
├── dashboard/
│   └── app_siem_dashboard.py             # Gold Layer: Streamlit real-time monitoring portal
├── requirements.txt                      # Project dependencies
└── README.md                             # Documentation
```

---

## 🏗️ Architecture Flow (The Medallion Architecture)

The pipeline is designed for high throughput and scalability, following these stages:

1. **Log Generation (Producer):** A Python script simulates Nginx and SSH server logs (including malicious payloads) and acts as a Kafka Producer.
2. **Message Broker (Ingestion):** A single-node **Apache Kafka** cluster (containerized via Docker) receives the raw logs in real-time on the `server-logs` topic.
3. **Bronze Layer (Raw Data):** A Kafka Consumer micro-batches the JSON logs, converts them to **Parquet** format for optimized storage, and uploads them to an `AWS S3 Bucket` partitioned by date.
4. **Silver Layer (Processed & Filtered):** An AI Security Agent continuously polls the Bronze S3 bucket, analyzes the logs for threats, splits them into `safe` and `threat` categories, and moves them to a Silver S3 bucket.
5. **Gold Layer (Visualization):** A live **Streamlit Dashboard** reads the curated Parquet files from the Silver S3 bucket, presenting real-time security metrics, threat distribution, and critical alerts to the SOC analyst.

---

## 🛠️ Tech Stack & Tools

| Layer | Technology |
|-------|-----------|
| **Data Ingestion** | Apache Kafka, Zookeeper, Docker Compose |
| **Storage & Cloud** | AWS S3, Boto3 |
| **Data Processing** | Python, Pandas, PyArrow (Parquet) |
| **Threat Detection** | Regex-based pattern matching (SQLi, SSH Brute Force) |
| **Visualization** | Streamlit, Plotly |

---

## ⚙️ Prerequisites

1. **Linux/Ubuntu Environment** (Recommended)
2. **Docker & Docker Compose** installed
3. **AWS CLI** configured (`aws configure`) with `AmazonS3FullAccess` permissions
4. **Python 3.10+** and a virtual environment

---

## 📦 Installation

```bash
# Clone the repository
git clone <repo-url>
cd "Data Lake & Cybersecurity SIEM"

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## 🚀 How to Run the Pipeline

### 1. Start the Kafka Infrastructure

```bash
docker compose up -d
```

Verify the containers are running:

```bash
docker compose ps
```

### 2. Start the Log Producer (Simulated Server Traffic)

```bash
python logs_ingestion/kafka_producer.py
```

This generates continuous Nginx and SSH logs with periodic SQL injection and brute-force attack patterns.

### 3. Start the Bronze Layer Consumer (Kafka → S3)

```bash
python logs_ingestion/kafka_to_s3_consumer.py
```

Micro-batches logs every 100 messages or 10 seconds, converts to Parquet, and uploads to `s3://siem-datalake-bronze/logs/`.

### 4. Start the AI Security Agent (Silver Layer)

```bash
python ai_agents/ai_security_agent.py
```

Polls the Bronze bucket, detects threats, splits into safe/threat categories, and uploads to `s3://siem-datalake-silver/data/`.

### 5. Launch the SOC Dashboard (Gold Layer)

```bash
streamlit run dashboard/app_siem_dashboard.py
```

Opens a real-time monitoring dashboard at `http://localhost:8501` with KPIs, charts, and threat alert tables.

---

## 📊 S3 Bucket Structure

### Bronze Layer (`siem-datalake-bronze`)
```
s3://siem-datalake-bronze/
├── logs/
│   └── year=YYYY/month=MM/day=DD/
│       └── batch_<timestamp>.parquet
└── archive/
    └── year=YYYY/month=MM/day=DD/
        └── batch_<timestamp>.parquet
```

### Silver Layer (`siem-datalake-silver`)
```
s3://siem-datalake-silver/
└── data/
    ├── status=safe/
    │   └── year=YYYY/month=MM/day=DD/
    │       └── batch_<timestamp>.parquet
    └── status=threat/
        └── year=YYYY/month=MM/day=DD/
            └── batch_<timestamp>.parquet
```

---

## 🔍 Threat Detection Capabilities

| Threat Type | Detection Method | Severity |
|-------------|-----------------|----------|
| **SQL Injection** | Regex patterns: `UNION SELECT`, `OR 1=1`, `--`, `information_schema`, `DROP TABLE` | CRITICAL |
| **SSH Brute Force** | >3 failed logins per IP within 60-second window | HIGH / CRITICAL (≥10) |

---

## 🧹 Cleanup

```bash
# Stop Kafka containers
docker compose down

# Deactivate virtual environment
deactivate
```
