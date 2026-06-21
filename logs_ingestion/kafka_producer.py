#!/usr/bin/env python3
import json
import random
import time
import signal
import sys
from datetime import datetime, timezone

from confluent_kafka import Producer

KAFKA_BROKER = "localhost:9092"
TOPIC = "server-logs"

INTERNAL_IPS = [f"192.168.1.{i}" for i in range(2, 50)]
EXTERNAL_IPS = [
    f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    for _ in range(100)
]
MALICIOUS_IPS = [
    "45.33.32.156", "103.224.182.240", "185.220.101.42",
    "23.129.64.210", "5.188.62.18", "91.121.87.105",
]

VALID_USERS = ["admin", "deploy", "root", "ubuntu", "sayed"]
COMMON_ATTACK_USERNAMES = ["root", "admin", "test", "oracle", "postgres", "user", "guest"]

NORMAL_PATHS = [
    "/", "/index.html", "/api/v1/status", "/api/v1/users",
    "/images/logo.png", "/css/main.css", "/js/app.js",
    "/favicon.ico", "/robots.txt", "/about", "/contact",
]

SQLI_PAYLOADS = [
    "/login?user=admin' OR '1'='1",
    "/search?q='; DROP TABLE users; --",
    "/api/v1/users?id=1 UNION SELECT username,password FROM users",
    "/product?id=1' AND 1=2 UNION SELECT 1,table_name FROM information_schema.tables--",
    "/admin?password=' OR 1=1 --",
]

HTTP_METHODS = ["GET", "POST", "HEAD"]
NORMAL_STATUS_CODES = [200, 200, 200, 200, 200, 301, 304, 201, 204]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "curl/8.4.0",
    "python-requests/2.31.0",
]

producer = Producer({"bootstrap.servers": KAFKA_BROKER})
log_count = 0
running = True


def delivery_report(err, msg):
    if err is not None:
        print(f"  [!] Delivery failed: {err}", file=sys.stderr)


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def random_ip(pool=None):
    if pool:
        return random.choice(pool)
    return random.choice(EXTERNAL_IPS)


def send_log(entry: dict):
    global log_count
    producer.produce(TOPIC, key=None, value=json.dumps(entry), callback=delivery_report)
    log_count += 1
    if log_count % 50 == 0:
        print(f"[*] {log_count} logs produced so far...")


def generate_nginx_normal():
    path = random.choice(NORMAL_PATHS)
    method = random.choice(HTTP_METHODS)
    status = random.choice(NORMAL_STATUS_CODES)
    size = random.randint(256, 15000)
    return {
        "timestamp": now_iso(),
        "source_ip": random_ip(),
        "service": "Nginx",
        "event_type": "HTTP_REQUEST",
        "severity": "INFO",
        "message": f'{method} {path} HTTP/1.1" {status} {size}',
        "http_method": method,
        "http_path": path,
        "http_status": status,
        "response_size": size,
        "user_agent": random.choice(USER_AGENTS),
    }


def generate_ssh_success():
    user = random.choice(VALID_USERS)
    ip = random.choice(INTERNAL_IPS)
    return {
        "timestamp": now_iso(),
        "source_ip": ip,
        "service": "SSH",
        "event_type": "LOGIN_SUCCESS",
        "severity": "INFO",
        "message": f"Accepted publickey for {user} from {ip} port {random.randint(1024, 65535)}",
        "username": user,
        "auth_method": "publickey",
    }


def generate_ssh_brute_force(attacker_ip: str, attempt: int):
    user = random.choice(COMMON_ATTACK_USERNAMES)
    return {
        "timestamp": now_iso(),
        "source_ip": attacker_ip,
        "service": "SSH",
        "event_type": "LOGIN_FAILURE",
        "severity": "WARNING" if attempt < 5 else "CRITICAL",
        "message": f"Failed password for {user} from {attacker_ip} port {random.randint(1024, 65535)}",
        "username": user,
        "auth_method": "password",
        "attempt_number": attempt,
    }


def generate_sqli_attack():
    path = random.choice(SQLI_PAYLOADS)
    return {
        "timestamp": now_iso(),
        "source_ip": random.choice(MALICIOUS_IPS),
        "service": "Nginx",
        "event_type": "SQL_INJECTION_ATTEMPT",
        "severity": "CRITICAL",
        "message": f'GET {path} HTTP/1.1" 403 0',
        "http_method": "GET",
        "http_path": path,
        "http_status": 403,
        "attack_type": "SQLi",
        "user_agent": random.choice(USER_AGENTS),
    }


def shutdown(signum, frame):
    global running
    print("\n[*] Shutting down... flushing producer.")
    running = False


signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)


def main():
    print(f"[*] Kafka producer started. Sending to topic '{TOPIC}' on {KAFKA_BROKER}")
    print("[*] Press Ctrl+C to stop.")

    last_attack_time = time.time()
    attack_interval = random.uniform(25, 45)

    while running:
        now = time.time()
        if now - last_attack_time >= attack_interval:
            attack_type = random.choice(["brute_force", "sqli"])

            if attack_type == "brute_force":
                attacker_ip = random.choice(MALICIOUS_IPS)
                num_attempts = random.randint(5, 15)
                print(f"  [!] Injecting SSH brute-force: {num_attempts} attempts from {attacker_ip}")
                for attempt in range(1, num_attempts + 1):
                    send_log(generate_ssh_brute_force(attacker_ip, attempt))
                    time.sleep(0.05)

            elif attack_type == "sqli":
                print("  [!] Injecting SQL Injection attempt")
                send_log(generate_sqli_attack())

            last_attack_time = now
            attack_interval = random.uniform(25, 45)
        else:
            service = random.choice(["Nginx", "SSH"])
            if service == "Nginx":
                send_log(generate_nginx_normal())
            else:
                send_log(generate_ssh_success())

        time.sleep(random.uniform(0.1, 0.5))

    producer.flush()
    print(f"[*] Producer stopped. Total logs sent: {log_count}")


if __name__ == "__main__":
    main()
