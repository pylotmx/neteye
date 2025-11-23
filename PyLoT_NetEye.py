import customtkinter as ctk
from tkinter import messagebox
import scapy.all as scapy
import threading
import time
import socket
import psutil
import requests
import os
import sys

# --- CONFIGURACIÓN VISUAL ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class NetLogic:
    def __init__(self):
        self.my_ip = self.get_local_ip()

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def escanear_red(self, ip_range):
        """Escanea la red usando ARP Request (Más rápido y preciso que ping)"""
        try:
            # Crea un paquete ARP preguntando "¿Quién tiene esta IP?"
            arp_request = scapy.ARP(pdst=ip_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            
            # Envía el paquete y espera respuesta
            answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

            dispositivos = []
            for element in answered_list:
                device = {
                    "ip": element[1].psrc,
                    "mac": element[1].hwsrc,
                    "vendor": self.get_mac_vendor(element[1].hwsrc)
                }
                dispositivos.append(device)
            return dispositivos
        except Exception as e:
            print(f"Error escaneando: {e}")
            return []

    def get_mac_vendor(self, mac):
        """Intenta adivinar el fabricante por la MAC (API simple)"""
        try:
            url = f"https://api.macvendors.com/{mac}"
            response = requests.get(url, timeout=1)
            if response.status_code == 200:
                return response.text
            return "Desconocido"
        except:
            return "Desconocido"

    def obtener_conexiones_activas(self):
        """Obtiene qué procesos están hablando con internet y dónde están"""
        conexiones_data = []
        try:
            # Obtener conexiones de red del sistema
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    
                    # Ignorar IPs locales (192.168... o 127.0...)
                    if remote_ip.startswith("192.168") or remote_ip.startswith("127.") or remote_ip.startswith("10."):
                        continue

                    # Obtener nombre del proceso (ej. chrome.exe)
                    try:
                        process = psutil.Process(conn.pid)
                        name = process.name()
                    except:
                        name = "Sistema"

                    # GeoIP (Usamos ip-api.com que es gratis para uso bajo)
                    try:
                        geo_url = f"http://ip-api.com/json/{remote_ip}?fields=country,city,countryCode"
                        r = requests.get(geo_url, timeout=0.5).json()
                        pais = r.get("country", "Desconocido")
                        ciudad = r.get("city", "")
                        codigo = r.get("countryCode", "")
                    except:
                        pais = "Mundo"
                        ciudad = ""
                        codigo = ""

                    conexiones_data.append({
                        "programa": name,
                        "ip_remota": remote_ip,
                        "pais": pais,
                        "ciudad": ciudad,
                        "puerto": conn.raddr.port
                    })
                    
                    if len(conexiones_data) >= 8: # Limitar a 8 para no saturar la API gratuita
                        break
            return conexiones_data
        except Exception as e:
            print(e)
            return []

class AppNetEye(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PyLoT NetEye - Monitor de Red")
        self.geometry("1000x700")
        self.logic = NetLogic()
        
        # --- LAYOUT ---
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=20)

        self.tab_lan = self.tabview.add("🏠 Dispositivos (Wi-Fi Local)")
        self.tab_world = self.tabview.add("🌍 Tráfico Saliente (GeoIP)")

        self.setup_lan_ui()
        self.setup_world_ui()

    # --- PESTAÑA 1: LAN ---
    def setup_lan_ui(self):
        frame = self.tab_lan
        
        # Header
        head = ctk.CTkFrame(frame, fg_color="transparent")
        head.pack(fill="x", pady=10)
        
        self.lbl_ip = ctk.CTkLabel(head, text=f"Tu IP Local: {self.logic.my_ip}", font=("Consolas", 16, "bold"), text_color="#00ff00")
        self.lbl_ip.pack(side="left", padx=10)

        self.btn_scan = ctk.CTkButton(head, text="🔄 ESCANEAR RED", command=self.start_scan_lan, fg_color="#1f6aa5")
        self.btn_scan.pack(side="right", padx=10)

        # Lista
        self.scroll_lan = ctk.CTkScrollableFrame(frame)
        self.scroll_lan.pack(fill="both", expand=True, padx=5, pady=5)
        
        ctk.CTkLabel(self.scroll_lan, text="Presiona Escanear para buscar intrusos...", text_color="gray").pack(pady=50)

    def start_scan_lan(self):
        self.btn_scan.configure(state="disabled", text="Escaneando...")
        # Limpiar
        for w in self.scroll_lan.winfo_children(): w.destroy()
        
        # Hilo
        threading.Thread(target=self.run_scan_lan).start()

    def run_scan_lan(self):
        # Asumimos mascara /24 estándar (ej 192.168.1.1/24)
        base_ip = ".".join(self.logic.my_ip.split(".")[:3]) + ".1/24"
        dispositivos = self.logic.escanear_red(base_ip)
        
        self.after(0, self.mostrar_lan, dispositivos)

    def mostrar_lan(self, dispositivos):
        self.btn_scan.configure(state="normal", text="🔄 ESCANEAR RED")
        
        if not dispositivos:
            ctk.CTkLabel(self.scroll_lan, text="No se encontraron dispositivos o falta Npcap.", text_color="red").pack(pady=20)
            return

        ctk.CTkLabel(self.scroll_lan, text=f"Se encontraron {len(dispositivos)} equipos conectados", font=("Arial", 14, "bold")).pack(pady=10)

        for dev in dispositivos:
            card = ctk.CTkFrame(self.scroll_lan, fg_color="#2b2b2b")
            card.pack(fill="x", pady=5, padx=5)
            
            # Icono visual simple
            icon = "📱" if "Apple" in dev['vendor'] or "Samsung" in dev['vendor'] else "💻"
            
            ctk.CTkLabel(card, text=icon, font=("Arial", 30)).pack(side="left", padx=15)
            
            info = ctk.CTkFrame(card, fg_color="transparent")
            info.pack(side="left", fill="x", expand=True)
            
            ctk.CTkLabel(info, text=f"IP: {dev['ip']}", font=("Consolas", 16, "bold"), text_color="#4ea6f2").pack(anchor="w")
            ctk.CTkLabel(info, text=f"MAC: {dev['mac']}  |  Fab: {dev['vendor']}", font=("Arial", 12)).pack(anchor="w")

    # --- PESTAÑA 2: MUNDO (GeoIP) ---
    def setup_world_ui(self):
        frame = self.tab_world
        
        head = ctk.CTkFrame(frame, fg_color="transparent")
        head.pack(fill="x", pady=10)
        
        ctk.CTkLabel(head, text="¿Con quién habla tu computadora?", font=("Arial", 18)).pack(side="left")
        self.btn_geo = ctk.CTkButton(head, text="📡 RASTREAR CONEXIONES", command=self.start_scan_geo, fg_color="#9b59b6")
        self.btn_geo.pack(side="right")

        self.scroll_geo = ctk.CTkScrollableFrame(frame)
        self.scroll_geo.pack(fill="both", expand=True, padx=5, pady=5)
        
        ctk.CTkLabel(self.scroll_geo, text="Analiza el tráfico saliente de tus apps.", text_color="gray").pack(pady=50)

    def start_scan_geo(self):
        self.btn_geo.configure(state="disabled", text="Rastreando...")
        for w in self.scroll_geo.winfo_children(): w.destroy()
        threading.Thread(target=self.run_scan_geo).start()

    def run_scan_geo(self):
        conexiones = self.logic.obtener_conexiones_activas()
        self.after(0, self.mostrar_geo, conexiones)

    def mostrar_geo(self, conexiones):
        self.btn_geo.configure(state="normal", text="📡 RASTREAR CONEXIONES")
        
        if not conexiones:
            ctk.CTkLabel(self.scroll_geo, text="No hay tráfico activo externo detectable.", text_color="yellow").pack()
            return

        for conn in conexiones:
            card = ctk.CTkFrame(self.scroll_geo)
            card.pack(fill="x", pady=5, padx=5)
            
            # CORRECCIÓN APLICADA AQUÍ: width va dentro del Frame
            left = ctk.CTkFrame(card, fg_color="transparent", width=150)
            left.pack(side="left", padx=10)
            
            ctk.CTkLabel(left, text=conn['programa'], font=("Arial", 14, "bold")).pack(anchor="w")
            ctk.CTkLabel(left, text=f"Puerto: {conn['puerto']}", font=("Arial", 10), text_color="gray").pack(anchor="w")

            # Flecha
            ctk.CTkLabel(card, text="➡", font=("Arial", 20), text_color="gray").pack(side="left", padx=10)

            # Lado Derecho (Destino)
            right = ctk.CTkFrame(card, fg_color="transparent")
            right.pack(side="left", fill="x", expand=True)
            
            ubicacion = f"{conn['ciudad']}, {conn['pais']}"
            ctk.CTkLabel(right, text=conn['ip_remota'], font=("Consolas", 14, "bold"), text_color="#f39c12").pack(anchor="w")
            ctk.CTkLabel(right, text=f"📍 {ubicacion}", font=("Arial", 12)).pack(anchor="w")

if __name__ == "__main__":
    # Verificación de permisos (Scapy requiere admin a veces)
    try:
        app = AppNetEye()
        app.mainloop()
    except Exception as e:
        messagebox.showerror("Error de Permisos", f"Error iniciando: {e}\nPrueba ejecutar como Administrador.")