import requests
import base64
import os
import time

API_KEY = "fab27c09657c8ee5e2229b788625106a27e2ec37eac7791d8bd8d633df96fd58"

def install_requirements():
    try:
        import requests
        print("[*] Semua komponen sudah diinstal.")
    except ImportError:
        print("[*] Menginstal komponen yang diperlukan...")
        os.system("pip install requests")
    print("\n[*] Semua dependensi telah diinstal.")
    
    # Hitungan mundur dari 5 sampai 1
    for i in range(5, 0, -1):
        print(f"[!] Kembali ke menu utama dalam {i} detik...", end="\r")
        time.sleep(1)
    print(" " * 50)  # Kosongkan garis untuk tampilan rapi

def scan_file(file_path):
    if not os.path.isfile(file_path):
        print(f"[!] File tidak ditemukan di jalur: {file_path}")
        return
    try:
        with open(file_path, "rb") as file:
            files = {"file": file}
            headers = {"x-apikey": API_KEY}
            response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)
            if response.status_code == 200:
                print("Hasil Scan:")
                print(response.json())
            else:
                print(f"Gagal memindai file: {response.status_code} {response.json()}")
    except Exception as e:
        print(f"[!] Kesalahan: {str(e)}")

def scan_url(url):
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": API_KEY}
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
        if response.status_code == 200:
            print("Hasil Scan URL:")
            print(response.json())
        else:
            print(f"Gagal memeriksa URL: {response.status_code} {response.json()}")
    except Exception as e:
        print(f"[!] Kesalahan: {str(e)}")

def main_menu():
    print("\nMenu:")
    print("[1] Install Komponen yang Diperlukan")
    print("[2] Scan File dari Direktori")
    print("[3] Scan URL")
    print("[4] Keluar")
    
    choice = input("Pilih opsi (1/2/3/4): ")
    if choice == "1":
        install_requirements()
        main_menu()  # Kembali ke menu utama setelah instalasi
    elif choice == "2":
        file_path = input("Masukkan path lengkap file: ")
        scan_file(file_path)
    elif choice == "3":
        url = input("Masukkan URL: ")
        scan_url(url)
    elif choice == "4":
        print("Keluar...")
    else:
        print("[!] Pilihan tidak valid.")
        main_menu()

if __name__ == "__main__":
    main_menu()
