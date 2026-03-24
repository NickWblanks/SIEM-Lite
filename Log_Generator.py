import json
import random
import time
import datetime

# Mock Data
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

# Log Generator Functions

def generate_good_log():
    """Normal traffic: 200 OK, standard user agents, normal endpoints."""
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
    """Clear attacks: SQLi, XSS, Path Traversal."""
    payloads = [
        "/?id=1' OR '1'='1",               # SQL Injection
        "/?search=<script>alert(1)</script>", # XSS
        "/../../../../etc/passwd"          # Path Traversal
    ]
    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "ip": random.choice(ATTACKER_IPS),
        "method": "GET",
        "endpoint": random.choice(payloads),
        "status": 403, # Blocked or forbidden
        "user_agent": random.choice(USER_AGENTS),
        "message": "Potential malicious payload detected"
    }

def generate_suspicious_log():
    """Potentially bad: Brute force attempts (401s), weird user agents, admin access."""
    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "ip": random.choice(ATTACKER_IPS + NORMAL_IPS),
        "method": "POST",
        "endpoint": random.choice(SENSITIVE_ENDPOINTS),
        "status": random.choice([401, 403, 404, 500]), # Failed logins or errors
        "user_agent": random.choice(SUSPICIOUS_AGENTS),
        "message": "Failed authentication or unauthorized access attempt"
    }

def generate_damaged_log():
    """Damaged in transit: Truncated JSON, missing fields, or completely corrupted strings."""
    # Start with a good log
    raw_json = json.dumps(generate_good_log())
    
    damage_type = random.randint(1, 3)
    if damage_type == 1:
        # Truncate the string halfway (Simulates network drop)
        return raw_json[:len(raw_json) // 2] 
    elif damage_type == 2:
        # Corrupt the syntax (Replace quotes, which breaks JSON parsing)
        return raw_json.replace('"', "'") 
    else:
        # Send complete gibberish (Simulates buffer overflow attempt or bad encoding)
        return r"\x00\x00\x00\x00\x00\xFF\xFF\xFA\x8B\x01\x02\x03\x04"


def main():
    print("Starting SIEM Log Generator... Press Ctrl+C to stop.", flush=True)
    
    while True:
        # Determine the probability of each log type
        roll = random.randint(1, 100)
        
        if roll <= 70:
            log_entry = json.dumps(generate_good_log())      # 70% Good traffic
        elif roll <= 85:
            log_entry = json.dumps(generate_bad_log())       # 15% Definite Attacks
        elif roll <= 95:
            log_entry = json.dumps(generate_suspicious_log())# 10% Suspicious/Anomalous
        else:
            log_entry = generate_damaged_log()               # 5% Corrupted/Damaged
        
        # Print to stdout (Docker collects this)
        print(log_entry, flush=True)
        
        # Sleep to simulate real-world log spacing (between 0.1 and 1.5 seconds)
        time.sleep(random.uniform(0.1, 1.5))

if __name__ == "__main__":
    main()