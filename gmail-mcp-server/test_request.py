import requests

url = "http://localhost:8002/comprehensive_scan"
data = {
    "target": "https://httpbin.org",
    "email": "tejaavinash431@gmail.com",
    "scan_type": "comprehensive"
}

response = requests.post(url, json=data)
print(response.status_code)
print(response.json())