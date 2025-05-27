import requests
import json
import ipaddress
import time # For simulating delays if needed

# Placeholder for a simple IP blocking mechanism
BLOCKED_IPS = set()

def get_geolocation_data(ip_address):
    # This is a placeholder function for getting geo-location
    # In a real app, you'd use a service like ipinfo.io or ip-api.com
    print(f"DEBUG: Getting geolocation for IP: {ip_address}")
    if ip_address == "127.0.0.1" or ip_address.startswith("192.168.") or ip_address.startswith("172.16.") or ip_address.startswith("10."):
        return {"country": "Local", "city": "N/A", "latitude": None, "longitude": None}
    
    # Placeholder for a real API call (example with ip-api.com, check their terms of service)
    # try:
    #     response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=country,city,lat,lon")
    #     data = response.json()
    #     if data.get('status') == 'success':
    #         return {
    #             "country": data.get('country'),
    #             "city": data.get('city'),
    #             "latitude": data.get('lat'),
    #             "longitude": data.get('lon')
    #         }
    # except Exception as e:
    #     print(f"Error getting geolocation for {ip_address}: {e}")
    
    return {"country": "Unknown", "city": "Unknown", "latitude": None, "longitude": None}

def check_ip_reputation(ip_address):
    # This is a placeholder function for checking IP reputation
    # In a real app, you'd integrate with services like VirusTotal, AbuseIPDB, etc.
    print(f"DEBUG: Checking IP reputation for IP: {ip_address}")
    
    # Simple logic for demonstration
    if ip_address.startswith("10."): # Example: internal network, no threat
        return {"is_threat": False, "threat_score": 0, "details": "Internal IP"}
    elif ip_address.endswith(".13"): # Example: known bad IP
        return {"is_threat": True, "threat_score": 90, "details": "Known malicious IP (example)"}
    elif random.random() < 0.1: # 10% chance of being a mild threat
        return {"is_threat": True, "threat_score": random.randint(30, 70), "details": "Suspicious IP (example)"}
    else:
        return {"is_threat": False, "threat_score": random.randint(0, 20), "details": "No known threat"}

def is_ip_blocked(ip_address):
    # Checks if an IP is currently blocked
    return ip_address in BLOCKED_IPS

def block_ip(ip_address):
    # Adds an IP to the blocked list
    BLOCKED_IPS.add(ip_address)
    print(f"ACTION: IP {ip_address} BLOCKED.")

def unblock_ip(ip_address):
    # Removes an IP from the blocked list
    if ip_address in BLOCKED_IPS:
        BLOCKED_IPS.remove(ip_address)
        print(f"ACTION: IP {ip_address} UNBLOCKED.")