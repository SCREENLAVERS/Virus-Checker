import requests
import hashlib

# Ganti dengan API Key VirusTotal Anda
API_KEY = "YOUR_API_KEY"

def scan_url(url):
    """Mengecek status keamanan dari URL."""
    vt_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": API_KEY,
        "accept": "application/json"
    }

    # Encode URL ke dalam hash yang diperlukan oleh VirusTotal
    url_id = hashlib.sha256(url.encode()).hexdigest()
    response = requests.get(f"{vt_url}/{url_id}", headers=headers)

    if response.status_code == 200:
        result = response.json()
        print("Hasil Pemindaian URL:")
        print(result)
    else:
        print("Gagal memeriksa URL:", response.status_code, response.text)

def scan_file(file_path):
    """Mengecek status keamanan dari file."""
    vt_url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "x-apikey": API_KEY,
    }
    
    with open(file_path, "rb") as file:
        files = {"file": (file_path, file)}
        response = requests.post(vt_url, headers=headers, files=files)

    if response.status_code == 200:
        result = response.json()
        print("Hasil Pemindaian File:")
        print(result)
    else:
        print("Gagal memeriksa file:", response.status_code, response.text)

# Contoh Penggunaan
url_to_check = "https://example.com"
file_to_check = "path/to/your/file.exe"

# Cek URL
scan_url(url_to_check)

# Cek File
scan_file(file_to_check)
