import json
import random
import time
import datetime
import argparse
import sys
import requests

# Try to import scapy for live sniffing
try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# --- Mock Data Pools (For Test Mode) ---
NORMAL_IPS = ["192.168.1.10", "192.168.1.15", "10.0.0.5", "172.16.0.22"]
ATTACKER_IPS = ["198.51.100.23", "203.0.113.45", "45.33.32.156"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/91.0"
]
SUSPICIOUS_AGENTS = ["curl/7.68.0", "Nmap Scripting Engine", "python-requests/2.25.1", "-"]

ENDPOINTS = ["/index.html", "/about", "/api/v1/data", "/images/logo.png"]
SENSITIVE_ENDPOINTS = ["/admin/login", "/api/v1/users", "/config.yml"]

# --- Generators for Edge Cases (Test Mode) ---

def generate_good_log():
    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "ip": random.choice(NORMAL_IPS),
        "method": random.choice(["GET", "POST"]),
        "endpoint": random.choice(ENDPOINTS),
        "status": 200,
        "user_agent": random.choice(USER_AGENTS),
        "message": "Request processed successfully"
    }

def generate_bad_log():
    payloads = ["/?id=1' OR '1'='1", "/?search=<script>alert(1)</script>", "/../../../../etc/passwd"]
    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "ip": random.choice(ATTACKER_IPS),
        "method": "GET",
        "endpoint": random.choice(payloads),
        "status": 403,
        "user_agent": random.choice(USER_AGENTS),
        "message": "Potential malicious payload detected"
    }

def generate_suspicious_log():
    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "ip": random.choice(ATTACKER_IPS + NORMAL_IPS),
        "method": "POST",
        "endpoint": random.choice(SENSITIVE_ENDPOINTS),
        "status": random.choice([401, 403, 404, 500]),
        "user_agent": random.choice(SUSPICIOUS_AGENTS),
        "message": "Failed authentication or unauthorized access attempt"
    }

def generate_damaged_log():
    raw_json = json.dumps(generate_good_log())
    damage_type = random.randint(1, 3)
    if damage_type == 1:
        return raw_json[:len(raw_json) // 2] 
    elif damage_type == 2:
        return raw_json.replace('"', "'") 
    else:
        return r"\x00\x00\x00\x00\x00\xFF\xFF\xFA\x8B\x01\x02\x03\x04"

# --- Live Traffic Processor ---

def process_live_packet(packet):
    """Callback function executed for every packet sniffed by Scapy."""
    if IP in packet:
        log_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "ip": packet[IP].src,          
            "dest_ip": packet[IP].dst,     
            "protocol": "IP",
            "length": len(packet),
            "message": "Live network packet captured"
        }
        
        if TCP in packet:
            log_entry["src_port"] = packet[TCP].sport
            log_entry["dest_port"] = packet[TCP].dport
            log_entry["protocol"] = "TCP"
        elif UDP in packet:
            log_entry["src_port"] = packet[UDP].sport
            log_entry["dest_port"] = packet[UDP].dport
            log_entry["protocol"] = "UDP"

        json_data = json.dumps(log_entry)
        print(json_data, flush=True)

        # --- NEW API HANDOFF FOR LIVE TRAFFIC ---
        try:
            headers = {'Content-Type': 'application/json'}
            # Note: Timeout added so live mode doesn't completely freeze if C# is off
            requests.post("http://localhost:5000/api/ingest", data=json_data, headers=headers, timeout=0.5)
        except requests.exceptions.RequestException:
            pass # We pass silently here so it doesn't spam the console 100 times a second

# --- Main Event Loop ---

def main():
    # Set up command line arguments
    parser = argparse.ArgumentParser(description="SIEM-Lite Log Generator")
    parser.add_argument('--mode', choices=['test', 'live'], default='test', 
                        help="Run in 'test' (mock data) or 'live' (packet sniffing) mode.")
    args = parser.parse_args()

    if args.mode == 'test':
        print("Starting SIEM Log Generator in TEST mode... Press Ctrl+C to stop.", flush=True)
        while True:
            roll = random.randint(1, 100)
            if roll <= 70:
                log_entry = json.dumps(generate_good_log())
            elif roll <= 85:
                log_entry = json.dumps(generate_bad_log())
            elif roll <= 95:
                log_entry = json.dumps(generate_suspicious_log())
            else:
                log_entry = generate_damaged_log()
            
            print(log_entry, flush=True)
            try:
                headers = {'Content-Type': 'application/json'}
                requests.post("http://localhost:5000/api/ingest", data=log_entry, headers=headers)
            except requests.exceptions.ConnectionError:
                print("C# API is offline. Make sure ParsingEngine is running.")
            
            time.sleep(random.uniform(0.1, 1.5))

    elif args.mode == 'live':
        if not SCAPY_AVAILABLE:
            print("CRITICAL ERROR: 'scapy' library is not installed. Cannot run live mode.", file=sys.stderr)
            print("Run 'pip install scapy' to install it.", file=sys.stderr)
            sys.exit(1)
            
        print("Starting SIEM Log Generator in LIVE mode... Sniffing host traffic. Press Ctrl+C to stop.", flush=True)
        # Sniff network traffic. store=0 ensures we don't hold packets in RAM and crash the app.
        sniff(prn=process_live_packet, store=0)

if __name__ == "__main__":
    main()