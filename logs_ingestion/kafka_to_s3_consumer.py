#!/usr/bin/env python3
import json
import os
import signal
import sys
import time
from datetime import datetime, timezone

import pandas as pd
import boto3
from confluent_kafka import Consumer, KafkaError, KafkaException

KAFKA_BROKER = "localhost:9092"
TOPIC = "server-logs"
S3_BUCKET = "siem-datalake-bronze"
S3_PREFIX = "logs"
BATCH_SIZE = 100
BATCH_TIMEOUT = 10.0

running = True


def shutdown(signum, frame):
    global running
    print("\n[*] Shutting down...")
    running = False


signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)


def create_consumer():
    conf = {
        "bootstrap.servers": KAFKA_BROKER,
        "group.id": "s3-ingestion-group",
        "auto.offset.reset": "earliest",
        "enable.auto.commit": True,
    }
    consumer = Consumer(conf)
    consumer.subscribe([TOPIC])
    return consumer


def upload_batch(batch: list, s3_client):
    if not batch:
        return

    df = pd.DataFrame(batch)
    now = datetime.now(timezone.utc)
    year = now.strftime("%Y")
    month = now.strftime("%m")
    day = now.strftime("%d")
    timestamp_str = now.strftime("%Y%m%dT%H%M%S%f")
    s3_key = f"{S3_PREFIX}/year={year}/month={month}/day={day}/batch_{timestamp_str}.parquet"

    local_path = f"temp_batch_{timestamp_str}.parquet"

    try:
        df.to_parquet(local_path, index=False)
        s3_client.upload_file(local_path, S3_BUCKET, s3_key)
        print(f"[+] Batch uploaded: {len(batch)} records -> s3://{S3_BUCKET}/{s3_key}")
    finally:
        if os.path.exists(local_path):
            os.remove(local_path)


def main():
    print(f"[*] Kafka-to-S3 consumer started. Topic: '{TOPIC}', Bucket: '{S3_BUCKET}'")
    print(f"[*] Batch config: {BATCH_SIZE} messages or {BATCH_TIMEOUT}s timeout")
    print("[*] Press Ctrl+C to stop.")

    consumer = create_consumer()
    s3_client = boto3.client("s3")
    batch = []
    last_flush = time.time()

    try:
        while running:
            msg = consumer.poll(timeout=1.0)

            if msg is None:
                pass
            elif msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                else:
                    raise KafkaException(msg.error())
            else:
                record = json.loads(msg.value().decode("utf-8"))
                batch.append(record)

            elapsed = time.time() - last_flush
            if len(batch) >= BATCH_SIZE or (batch and elapsed >= BATCH_TIMEOUT):
                upload_batch(batch, s3_client)
                batch.clear()
                last_flush = time.time()

    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
    finally:
        if batch:
            upload_batch(batch, s3_client)
        consumer.close()
        print(f"[*] Consumer stopped.")


if __name__ == "__main__":
    main()
