#!/usr/bin/env python3
import io
import json
import re
import time
from datetime import datetime, timezone

import boto3
import pandas as pd
import pyarrow.parquet as pq

BRONZE_BUCKET = "siem-datalake-bronze"
SILVER_BUCKET = "siem-datalake-silver"
BRONZE_PREFIX = "logs/"
ARCHIVE_PREFIX = "archive/"
POLL_INTERVAL = 15
BRUTE_FORCE_WINDOW_SECONDS = 60
BRUTE_FORCE_THRESHOLD = 3

SQLI_PATTERN = re.compile(
    r"(?i)(\bUNION\b.*\bSELECT\b|\bSELECT\b.*\bFROM\b|"
    r"\bDROP\s+TABLE\b|\bINSERT\s+INTO\b|"
    r"'?\s*OR\s+'?\d?'?\s*=\s*'?\d|"
    r"\b1\s*=\s*1\b|"
    r"--\s*$|"
    r"\binformation_schema\b|"
    r"'\s*;\s*)"
)

RED = "\033[1;31m"
YELLOW = "\033[1;33m"
GREEN = "\033[1;32m"
CYAN = "\033[1;36m"
RESET = "\033[0m"
BOLD = "\033[1m"


def list_bronze_files(s3_client) -> list[str]:
    keys = []
    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=BRONZE_BUCKET, Prefix=BRONZE_PREFIX):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith(".parquet"):
                keys.append(key)
    return keys


def read_parquet_from_s3(s3_client, key: str) -> pd.DataFrame:
    resp = s3_client.get_object(Bucket=BRONZE_BUCKET, Key=key)
    buffer = io.BytesIO(resp["Body"].read())
    table = pq.read_table(buffer)
    df = table.to_pandas()
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    return df


def archive_bronze_file(s3_client, key: str):
    archive_key = key.replace(BRONZE_PREFIX, ARCHIVE_PREFIX, 1)
    copy_source = {"Bucket": BRONZE_BUCKET, "Key": key}
    s3_client.copy_object(
        Bucket=BRONZE_BUCKET, Key=archive_key, CopySource=copy_source
    )
    s3_client.delete_object(Bucket=BRONZE_BUCKET, Key=key)


def detect_sqli(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame()

    nginx = df[df["service"] == "Nginx"].copy()
    if nginx.empty:
        return pd.DataFrame()

    alerts = []
    now = datetime.now(timezone.utc)

    for _, row in nginx.iterrows():
        message = str(row.get("message", ""))
        http_path = str(row.get("http_path", ""))
        event_type = str(row.get("event_type", ""))
        combined = f"{message} {http_path}"

        threat_type = None
        pattern_matched = ""

        if event_type == "SQL_INJECTION_ATTEMPT":
            threat_type = "SQL_INJECTION"
            pattern_matched = "explicit_event_type"
        else:
            match = SQLI_PATTERN.search(combined)
            if match:
                threat_type = "SQL_INJECTION"
                pattern_matched = match.group()

        if threat_type:
            alert = row.to_dict()
            alert["threat_type"] = threat_type
            alert["threat_severity"] = "CRITICAL"
            alert["detection_timestamp"] = now.isoformat()
            alert["threat_detail"] = (
                f"SQLi detected in Nginx request: matched pattern '{pattern_matched}'"
            )
            alert["attacker_ip"] = row.get("source_ip", "unknown")
            alert["matched_pattern"] = pattern_matched
            alerts.append(alert)

    return pd.DataFrame(alerts)


def detect_ssh_brute_force(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame()

    ssh_failures = df[
        (df["service"] == "SSH") & (df["event_type"] == "LOGIN_FAILURE")
    ].copy()

    if ssh_failures.empty:
        return pd.DataFrame()

    ssh_failures = ssh_failures.sort_values("timestamp")

    alerts = []
    now = datetime.now(timezone.utc)
    window_start = now - pd.Timedelta(seconds=BRUTE_FORCE_WINDOW_SECONDS)

    for ip, group in ssh_failures.groupby("source_ip"):
        recent = group[group["timestamp"] >= window_start]
        count = len(recent)
        if count > BRUTE_FORCE_THRESHOLD:
            first_attempt = recent["timestamp"].min()
            last_attempt = recent["timestamp"].max()
            usernames = (
                recent["username"].unique().tolist()
                if "username" in recent.columns
                else []
            )

            for _, row in recent.iterrows():
                alert = row.to_dict()
                alert["threat_type"] = "SSH_BRUTE_FORCE"
                alert["threat_severity"] = "CRITICAL" if count >= 10 else "HIGH"
                alert["detection_timestamp"] = now.isoformat()
                alert["threat_detail"] = (
                    f"IP {ip} had {count} failed SSH logins in "
                    f"{BRUTE_FORCE_WINDOW_SECONDS}s window "
                    f"(users: {', '.join(usernames[:5])})"
                )
                alert["attacker_ip"] = ip
                alert["failed_attempts_count"] = count
                alert["first_attempt"] = first_attempt.isoformat()
                alert["last_attempt"] = last_attempt.isoformat()
                alerts.append(alert)

    return pd.DataFrame(alerts)


def upload_to_silver(s3_client, df: pd.DataFrame, status: str):
    if df.empty:
        return

    now = datetime.now(timezone.utc)
    year = now.strftime("%Y")
    month = now.strftime("%m")
    day = now.strftime("%d")
    timestamp_str = now.strftime("%Y%m%dT%H%M%S%f")
    key = f"data/status={status}/year={year}/month={month}/day={day}/batch_{timestamp_str}.parquet"

    local_path = f"/tmp/silver_batch_{timestamp_str}.parquet"
    try:
        df.to_parquet(local_path, index=False)
        s3_client.upload_file(local_path, SILVER_BUCKET, key)
        print(f"  {GREEN}[+] Uploaded {len(df)} {status} records -> s3://{SILVER_BUCKET}/{key}{RESET}")
    finally:
        import os
        if os.path.exists(local_path):
            os.remove(local_path)


def process_file(s3_client, key: str) -> tuple:
    print(f"  {CYAN}[~] Processing: s3://{BRONZE_BUCKET}/{key}{RESET}")
    df = read_parquet_from_s3(s3_client, key)
    print(f"      Rows loaded: {len(df)}")

    sqli_alerts = detect_sqli(df)
    ssh_alerts = detect_ssh_brute_force(df)

    threat_alerts = pd.concat([sqli_alerts, ssh_alerts], ignore_index=True, sort=False)

    threat_indices = set()
    if not threat_alerts.empty:
        for col in ["timestamp", "source_ip", "message"]:
            if col in df.columns and col in threat_alerts.columns:
                threat_indices.update(
                    threat_alerts[threat_alerts[col].isin(df[col])].index
                )

    if not threat_alerts.empty and "timestamp" in df.columns and "timestamp" in threat_alerts.columns:
        threat_timestamps = set(threat_alerts["timestamp"].astype(str))
        threat_indices.update(
            df[df["timestamp"].astype(str).isin(threat_timestamps)].index
        )

    safe_logs = df.drop(index=threat_indices.intersection(df.index)) if threat_indices else df.copy()

    return safe_logs, threat_alerts


def main():
    print(f"{CYAN}{BOLD}")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║     AI SECURITY AGENT — Silver Layer Processor (S3)         ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"{RESET}")
    print(f"  Bronze bucket:  s3://{BRONZE_BUCKET}/{BRONZE_PREFIX}")
    print(f"  Silver bucket:  s3://{SILVER_BUCKET}/data/")
    print(f"  Poll interval:  {POLL_INTERVAL}s")
    print(f"  Brute-force:    >{BRUTE_FORCE_THRESHOLD} failures / {BRUTE_FORCE_WINDOW_SECONDS}s")
    print(f"{GREEN}[*] Agent is watching for new Parquet files...{RESET}")
    print(f"{GREEN}[*] Press Ctrl+C to stop.{RESET}\n")

    s3_client = boto3.client("s3")

    try:
        while True:
            keys = list_bronze_files(s3_client)

            if not keys:
                time.sleep(POLL_INTERVAL)
                continue

            print(f"{YELLOW}[+] Found {len(keys)} unprocessed Parquet file(s){RESET}")

            total_safe = 0
            total_threats = 0

            for key in keys:
                safe_logs, threat_alerts = process_file(s3_client, key)

                upload_to_silver(s3_client, safe_logs, "safe")
                upload_to_silver(s3_client, threat_alerts, "threat")

                archive_bronze_file(s3_client, key)
                print(f"      {GREEN}[✓] Archived: {key} -> {ARCHIVE_PREFIX}{RESET}")

                total_safe += len(safe_logs)
                total_threats += len(threat_alerts)

                if not threat_alerts.empty:
                    for _, alert in threat_alerts.iterrows():
                        threat_type = alert.get("threat_type", "UNKNOWN")
                        severity = alert.get("threat_severity", "HIGH")
                        source_ip = alert.get("attacker_ip", "N/A")
                        detail = alert.get("threat_detail", "")
                        color = RED if severity == "CRITICAL" else YELLOW
                        print(f"    {color}[!] {threat_type} | {severity} | {source_ip} | {detail}{RESET}")

            print(f"\n{GREEN}{BOLD}╔══ BATCH SUMMARY ═══════════════════════════════════════════╗{RESET}")
            print(f"  Files processed : {len(keys)}")
            print(f"  Safe records    : {total_safe}")
            print(f"  Threat alerts   : {total_threats}")
            print(f"{GREEN}{'─' * 62}{RESET}\n")

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print(f"\n{YELLOW}[*] Security agent shutting down. Goodbye.{RESET}")


if __name__ == "__main__":
    main()
