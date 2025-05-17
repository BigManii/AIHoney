from collections import Counter

LOG_FILE = "honeypot_logs.txt"

def analyze_logs():
    ip_attempts = Counter()
    with open(LOG_FILE, "r") as f:
        for line in f:
            parts = line.strip().split(" | ")
            if len(parts) >= 3:
                ip = parts[1]
                action = parts[2]
                if "Login attempt" in action or "Signup attempt" in action:
                    ip_attempts[ip] += 1

    print("Top 5 IPs by number of attempts:")
    for ip, count in ip_attempts.most_common(5):
        print(f"{ip}: {count} attempts")

if __name__ == "__main__":
    analyze_logs()
