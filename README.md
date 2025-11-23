# ⚡ PyLoT NetEye  
**Monitor de red avanzado en Python — Escaneo LAN + GeoIP de conexiones salientes**

PyLoT NetEye es una herramienta gráfica creada con **CustomTkinter** que permite monitorear tu red local (Wi-Fi / LAN), detectar dispositivos conectados mediante ARP y visualizar las conexiones salientes de tu computadora hacia Internet, incluyendo ubicación aproximada (GeoIP), puertos y procesos involucrados.

Este proyecto fue diseñado para usuarios que desean conocer qué dispositivos están conectados a su red, así como monitorear hacia qué países/servidores se comunican sus aplicaciones.

---

## 🚀 Funcionalidades principales

### 🏠 Escaneo de Red Local (LAN)
- Detecta todos los dispositivos conectados a tu red.
- Utiliza **ARP Scan** para mayor velocidad y precisión.
- Muestra:
  - Dirección IP
  - MAC Address
  - Fabricante del dispositivo (Vendor)
- Identifica computadores y smartphones mediante iconos.

---

### 🌍 Monitoreo de Conexiones Salientes (GeoIP)
- Muestra qué aplicaciones están enviando tráfico a Internet.
- Incluye:
  - Nombre del proceso (ej. chrome.exe, discord.exe)
  - IP remota
  - País y ciudad (GeoIP via ip-api.com)
  - Puerto remoto
- Filtra IP locales para evitar ruido.
- Limitación inteligente a 8 conexiones para evitar saturación de la API gratuita.

---

## 🖥️ Requisitos

### 🔧 Librerías de Python
Instala todas las dependencias ejecutando:

```bash
pip install customtkinter scapy psutil requests
