import os
import subprocess
import speedtest
import ping3
from scapy.all import sniff, ARP
import re
import tkinter as tk
from tkinter import scrolledtext

# 1. İnternet Hızı Testi
def test_speed():
    try:
        output_box.insert(tk.END, "\n-- İnternet Hız Testi --\n")
        st = speedtest.Speedtest()
        download_speed = st.download() / 1_000_000  # Mbps
        upload_speed = st.upload() / 1_000_000  # Mbps
        output_box.insert(tk.END, f"İndirme Hızı: {download_speed:.2f} Mbps\n")
        output_box.insert(tk.END, f"Yükleme Hızı: {upload_speed:.2f} Mbps\n")
    except Exception as e:
        output_box.insert(tk.END, f"Hata: {e}\n")

# 2. Ping Testi
def test_ping():
    host = "8.8.8.8"
    try:
        output_box.insert(tk.END, "\n-- Ping Testi --\n")
        response = ping3.ping(host)
        if response is None:
            output_box.insert(tk.END, f"{host} yanıt vermiyor.\n")
        else:
            output_box.insert(tk.END, f"{host} yanıt süresi: {response:.2f} ms\n")
    except Exception as e:
        output_box.insert(tk.END, f"Hata: {e}\n")

# 3. Wi-Fi Sinyal Gücü Testi (Linux/Windows)
def test_signal_strength():
    try:
        output_box.insert(tk.END, "\n-- Sinyal Gücü Testi --\n")
        if os.name == "posix":  # Linux/Mac
            result = subprocess.run(["iwconfig"], capture_output=True, text=True)
            match = re.search(r"Signal level=(-\d+)", result.stdout)
            if match:
                signal_level = int(match.group(1))
                output_box.insert(tk.END, f"Sinyal Gücü: {signal_level} dBm\n")
            else:
                output_box.insert(tk.END, "Wi-Fi bağlantısı bulunamadı.\n")
        elif os.name == "nt":  # Windows
            result = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True)
            match = re.search(r"Signal\s*:\s*(\d+)%", result.stdout)
            if match:
                signal_strength = int(match.group(1))
                output_box.insert(tk.END, f"Sinyal Gücü: {signal_strength}%\n")
            else:
                output_box.insert(tk.END, "Wi-Fi bağlantısı bulunamadı.\n")
    except Exception as e:
        output_box.insert(tk.END, f"Hata: {e}\n")

# 4. Ağdaki Cihazları Bulma (ARP Taraması)
def find_connected_devices():
    output_box.insert(tk.END, "\n-- Ağdaki Cihazları Bulma --\n")
    def arp_display(pkt):
        if pkt.haslayer(ARP):
            if pkt[ARP].op == 1:  # who-has (request)
                output_box.insert(tk.END, f"ARP Request: {pkt[ARP].psrc} is asking about {pkt[ARP].pdst}\n")
            elif pkt[ARP].op == 2:  # is-at (response)
                output_box.insert(tk.END, f"ARP Reply: {pkt[ARP].hwsrc} has address {pkt[ARP].psrc}\n")

    output_box.insert(tk.END, "Bağlı cihazlar taranıyor...\n")
    sniff(filter="arp", prn=arp_display, count=10, timeout=10)

# GUI uygulaması
root = tk.Tk()
root.title("Kablosuz Ağ Test Aracı")

# Butonlar ve metin kutusu
frame = tk.Frame(root)
frame.pack(pady=10)

output_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=50, height=20)
output_box.pack(padx=10, pady=10)

# Butonlar
btn_speed_test = tk.Button(frame, text="İnternet Hız Testi", command=test_speed)
btn_speed_test.grid(row=0, column=0, padx=10, pady=10)

btn_ping_test = tk.Button(frame, text="Ping Testi", command=test_ping)
btn_ping_test.grid(row=0, column=1, padx=10, pady=10)

btn_signal_test = tk.Button(frame, text="Wi-Fi Sinyal Gücü Testi", command=test_signal_strength)
btn_signal_test.grid(row=1, column=0, padx=10, pady=10)

btn_arp_test = tk.Button(frame, text="Ağdaki Cihazları Bulma", command=find_connected_devices)
btn_arp_test.grid(row=1, column=1, padx=10, pady=10)

# Uygulamanın çalıştırılması
root.mainloop()
