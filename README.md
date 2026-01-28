# CyberNatu Tool

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Status](https://img.shields.io/badge/status-in%20construction-orange)
![License](https://img.shields.io/badge/license-MIT-green)

Framework de ciberseguridad con interfaz gráfica para uso **ético y educativo**.  
Incluye escaneo, fuzzer web, generación de payloads, listener, utilidades, cripto/cracking y visor HTML.  
**Estado:** en construcción (v2.x). Funcional, pero sigue evolucionando.

---

## ✨ Qué hace

**Módulos principales**
- **Escáner**: escaneo de puertos con Nmap y visualización limpia de resultados.
- **Web Fuzzer**: fuerza bruta de directorios con wordlists (multihilo).
- **Payload Builder**: interfaz para msfvenom (en Windows genera el comando; en Linux lo ejecuta).
- **Listener**: listener nativo en Python que abre **terminal modal** cuando llega una shell.
- **Utilidades**: servidor HTTP rápido + gestión de hosts.
- **Cripto / Cracking**: Base64, binario/hex, hashes, y wrapper para John the Ripper.
- **Visor HTML / Archivos**: analiza URL o archivo local, con tabs estilo mini‑VSCode y numeración de líneas.
- **Logs**: vista separada para logs copiables y scrollables.

---

## ✅ Requisitos

- **Python 3.10+**
- **Windows o Linux**
- Dependencias Python:
  - `customtkinter`
  - `requests`
  - `python-nmap` (si usas el escáner)
- Opcionales:
  - **Nmap** instalado (imprescindible para escaneo real)
  - **John the Ripper** (para cracking)
  - **msfvenom** (Linux)

---

## 📦 Instalación

```bash
git clone https://github.com/davidrscout/NatuScan.git
cd cybernatu

python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows

pip install -r requirements.txt
```

---

## ▶️ Uso

```bash
python tool.py
```

### Escáner
1. Escribe IP o URL.
2. Inicia escaneo.
3. Resultados en lista.

### Listener
1. Puerto → “Poner a la escucha”.
2. Cuando llega una conexión, se abre **terminal modal**.

### Web Fuzzer
1. URL base.
2. Wordlist.
3. Ejecutar / detener fuzzing.

### Utilidades
1. Servidor HTTP (elige carpeta, puerto).
2. Hosts (añadir dominio → IP).

### Cripto / Cracking
1. Codifica/decodifica (Base64, Bin/Hex).
2. Hashes (SHA‑256 / MD5).
3. John the Ripper con wordlist.

### Visor HTML
1. Abre URL o archivo local.
2. Aparecen tabs (HTML + recursos detectados).
3. Resumen rápido de posibles riesgos.

---

## ⚠️ Aviso ético

Esta herramienta es **solo para uso educativo, auditorías autorizadas y entornos controlados**.  
El autor no se hace responsable del mal uso.

---

## 🔧 Estado del proyecto

✅ Funcional y usable  
🚧 En construcción (UI/UX y módulos mejorables)  

Ideas futuras:
- reportes exportables (PDF/HTML)
- persistencia de targets
- más herramientas de análisis

---

## 🧩 Estructura del repo

```
CyberNatu/
├─ interfaz/
│  ├─ __init__.py
│  └─ app.py          # UI principal
├─ tool.py            # launcher
├─ README.md
└─ .gitignore
```

---

## 📜 Licencia

MIT License

Copyright (c) 2026 Natu 

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

