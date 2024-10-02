from scapy.all import sniff
import networkx as nx
import matplotlib.pyplot as plt
from collections import defaultdict
import socket
import requests

# Veri trafiği analizini tutacak bir sözlük
traffic_data = defaultdict(int)

# IP adresi ve cihaz adı eşleştirme işlevi
def get_device_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]  # IP adresini cihaz adı ile eşleştir
    except socket.herror:
        return "Bilinmeyen Cihaz"

# IP adresinin coğrafi konumunu alma işlevi
def get_ip_location(ip):
    try:
        response = requests.get(f'https://ipinfo.io/{ip}/json')
        data = response.json()
        return data.get('city', 'Bilinmeyen Şehir'), data.get('country', 'Bilinmeyen Ülke')
    except requests.RequestException:
        return 'Bilinmeyen Şehir', 'Bilinmeyen Ülke'

# Paket yakalama işlevi
def packet_callback(packet):
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        packet_size = len(packet)
        
        # Kaynak ve hedef IP'ler arasındaki veri trafiğini güncelle
        traffic_data[(src_ip, dst_ip)] += packet_size

# Doğru arayüz adını buraya yerleştirin
selected_iface = "Wi-Fi"  # veya "Ethernet" gibi uygun bir isim

# Ağ trafiğini yakala (daha uzun süre yakalamak için timeout'u artırın)
sniff(iface=selected_iface, timeout=30, prn=packet_callback)

# Trafik verilerinin boş olup olmadığını kontrol edin
if len(traffic_data) == 0:
    print("Hiçbir paket yakalanmadı, ağ trafiği yok.")
else:
    # Trafik verilerini NetworkX grafiğine dök
    G = nx.Graph()

    # Trafik verilerini grafiğe ekle
    for (src, dst), data_size in traffic_data.items():
        G.add_edge(src, dst, weight=data_size)

    # Kenarları veri trafiğine göre renklendir
    edge_colors = [G[u][v]['weight'] for u, v in G.edges()]
    edge_widths = [G[u][v]['weight'] / 1000 for u, v in G.edges()]  # Görsel genişlik için ölçeklendirme

    # Ağın görselleştirilmesi
    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(G)  # Düğüm düzeni

    # Kenarları çiz
    nx.draw_networkx_edges(G, pos, edge_color=edge_colors, width=edge_widths, edge_cmap=plt.cm.Blues)

    # Düğümleri ve etiketleri çiz
    node_labels = {src: get_device_name(src) for src in G.nodes()}  # Düğüm etiketleri
    nx.draw_networkx_nodes(G, pos, node_size=700, node_color='lightgreen')
    nx.draw_networkx_labels(G, pos, labels=node_labels, font_size=10)

    # Başlık ve renk çubuğu
    plt.title("Ağ Trafiği ve Veri Tüketimi", size=15)
    sm = plt.cm.ScalarMappable(cmap=plt.cm.Blues, norm=plt.Normalize(vmin=min(edge_colors), vmax=max(edge_colors)))
    sm.set_array([])  # Boş bir dizi ayarlayın
    cbar = plt.colorbar(sm, ax=plt.gca(), label='Veri Tüketimi (Bayt)')  # ax parametresini ekleyin

    # Grafiği göster
    plt.show()

    # Veri trafiği bilgilerini yazdır
    for (src, dst), data_size in traffic_data.items():
        src_name = get_device_name(src)
        dst_name = get_device_name(dst)
        src_city, src_country = get_ip_location(src)
        dst_city, dst_country = get_ip_location(dst)
        print(f"{src_name} ({src}) -> {dst_name} ({dst}): {data_size} bayt")
        print(f"Kaynak: {src_city}, {src_country} | Hedef: {dst_city}, {dst_country}")
