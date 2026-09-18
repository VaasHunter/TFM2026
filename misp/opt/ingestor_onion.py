#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
=============================================================================
MÓDULO DE DARK WEB (TOR NETWORK)
=============================================================================
Objetivo: Monitorizar, a través de la red Tor (SOCKS5), las URL de tipo .onion
usados por actores y grupos ransomware de amenazas. A partir de dos repositorios,
que mantienen una BBDD actualizada con los portales .onion de los principales
actores ransomware, se buscan los actores contenidos en un listado local (actores.txt)
y se extraen las URL de sus respectivos portales para posteriormente buscar empresas 
españolas afectadas. En este caso, se añade la búsqueda de dominios españoles .es
=============================================================================
"""

import requests
from bs4 import BeautifulSoup
from pymisp import PyMISP, MISPEvent
import urllib3
import time
import os
import re
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===========================================================================
# 1. SEGURIDAD OPERACIONAL (OPSEC) Y CONFIGURACION DE RED TOR
# ===========================================================================
load_dotenv('/opt/.secrets.env')
MISP_URL = os.getenv('MISP_URL')
MISP_KEY = os.getenv('MISP_API_KEY')

PROXIES = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0'}
TIMEOUT = 45 

# ===========================================================================
# 2. GESTIÓN DE ACTIVOS Y DEDUPLICACIÓN
# ===========================================================================
def leer_diccionario_seguro(ruta):
    try:
        with open(ruta, 'r', encoding='utf-8') as f:
            return [line.strip().lower() for line in f if line.strip()]
    except UnicodeDecodeError:
        with open(ruta, 'r', encoding='latin-1') as f:
            return [line.strip().lower() for line in f if line.strip()]
    except FileNotFoundError:
        return []

def es_duplicado(misp_instance, info_text):
    try:
        matches = misp_instance.search(controller='events', eventinfo=info_text)
        if isinstance(matches, list) and len(matches) > 0:
            return True
        return False
    except Exception as e:
        print(f"    [-] Excepción en motor de duplicidad: {e}")
        return False

def conectar_misp():
    return PyMISP(MISP_URL, MISP_KEY, False)

# ===========================================================================
# 3. DESCUBRIMIENTO DE PORTALES MALICIOSOS
# ===========================================================================
def obtener_onions_dinamicos(actores_monitorizados):
    print("    [*] Obteniendo posible infraestructura ransomware ...")
    onions_dict = {} 

#Se consulta a plataformas de repositorios de actores ransomware

    try:
        res1 = requests.get("https://api.ransomware.live/groups", timeout=15)
        if res1.status_code == 200:
            for grupo in res1.json():
                nombre_actor = (grupo.get('name') or '').lower()
                if nombre_actor in actores_monitorizados:
                    for loc in grupo.get('locations', []):
                        dominio = loc.get('fqdn', '')
                        if dominio.endswith('.onion'):
                            if not dominio.startswith('http'): dominio = 'http://' + dominio
                            onions_dict[dominio] = grupo.get('name', 'Desconocido')
    except Exception as e:
        print(f"    [-] Aviso: Degradación de servicio en fuente Ransomware.live: {e}")

    try:
        res2 = requests.get("https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json", timeout=15)
        if res2.status_code == 200:
            for grupo in res2.json():
                nombre_actor = (grupo.get('name') or '').lower()
                if nombre_actor in actores_monitorizados:
                    for loc in grupo.get('locations', []):
                        dominio = loc.get('fqdn', '')
                        if dominio.endswith('.onion'):
                            if not dominio.startswith('http'): dominio = 'http://' + dominio
                            onions_dict[dominio] = grupo.get('name', 'Desconocido')
    except Exception as e:
        print(f"    [-] Aviso: Degradación de servicio en fuente Ransomwatch: {e}")

    lista_final = [(url, actor) for url, actor in onions_dict.items()]
    print(f"    [+] Topología de red actualizada: {len(lista_final)} nodos .onion resueltos.")
    return lista_final

# ===========================================================================
# 4. LÓGICA DE EXTRACCIÓN Y ANÁLISIS DE MUESTRAS
# ===========================================================================
def scrape_onion():
    print("[*] Iniciando módulo Dark Web (Tor)...")
    
    empresas = leer_diccionario_seguro('/opt/empresas.txt')
    actores = leer_diccionario_seguro('/opt/actores.txt')
    
    if not empresas:
        print("[-] ERROR: El diccionario de activos corporativos está vacío.")
        return
        
    onion_data = obtener_onions_dinamicos(actores)
    if not onion_data:
        print("[-] Abortando: No se localizaron URLS .onion para los perfiles seleccionados.")
        return
        
    print(f"[*] Comenzando análisis de portales onion...")
    
    try: misp = conectar_misp()
    except Exception as e:
        print(f"[-] Error fatal de conexión al clúster MISP: {e}")
        return

    hits = 0
    # Se inspecciona el sitio .onion para ver si está activo.
    # Lo intenta tres veces debido a la latencia de la red
    for site, actor in onion_data:
        print(f"[*] Analizando infraestructura de {actor}: {site}")
        
        MAX_RETRIES = 3
        html_content = None
        
        for intento in range(MAX_RETRIES):
            try:
                respuesta = requests.get(site, proxies=PROXIES, headers=HEADERS, timeout=TIMEOUT)
                if respuesta.status_code == 200: 
                    html_content = respuesta.text
                    break 
                else:
                    print(f"    [-] Respuesta HTTP {respuesta.status_code} en intento {intento + 1}.")
            except requests.exceptions.RequestException:
                print(f"    [-] Fallo de conexión en intento {intento + 1}...")
                if intento < MAX_RETRIES - 1:
                    time.sleep(5) 
                else:
                    print("    [-] Nodo offline o Timeout de red Tor excedido tras múltiples reintentos.")
        
        if not html_content:
            continue
            
        try:
            #Con la librería BeautifulSoup, se parsea el código html de la web para hacerlo procesable por Python
            #por ejemplo, eliminando etiquetas HTML y pasando todo el texto a minúsculas
            texto_web = BeautifulSoup(html_content, 'html.parser').get_text().lower()
            
            # 1. BÚSQUEDA DE EMPRESAS
            for emp in empresas:
                if emp and re.search(rf"(?<![a-zA-Z0-9_]){re.escape(emp)}(?![a-zA-Z0-9_])", texto_web, re.IGNORECASE): 
                    empresa_detectada = emp.upper()
                    info_evento = f"Dark Web Leak | Objetivo: {empresa_detectada} | Actor: {actor} | Informe: Posible víctima detectada"

                    if es_duplicado(misp, info_evento):
                        print(f"    [~] La exposición de {empresa_detectada} por {actor} ya está registrada.")
                        continue

                    hits += 1
                    print(f"    [!] POSIBLE RANSOMWARE: '{empresa_detectada}' referenciada en el portal de {actor}")
                    
                    evento = MISPEvent()
                    evento.info = info_evento
                    evento.date = time.strftime('%Y-%m-%d')
                    evento.distribution = 0
                    evento.threat_level_id = 1 
                    evento.analysis = 2
                    evento.published = True
                    
                    evento.add_attribute('target-org', empresa_detectada)
                    evento.add_attribute('threat-actor', actor)
                    evento.add_attribute('url', site, comment="Posible ataque ransomware")

                    evento.add_tag(f'Objetivo:{empresa_detectada}')
                    evento.add_tag('Sector:Logistica')
                    evento.add_tag('Country:ES')
                    evento.add_tag('Fuente:DarkWeb')
                    
                    try:
                        misp.add_event(evento)
                    except Exception as e:
                        print(f"    [-] Error al inyectar el evento en MISP: {e}")

            # 2. BÚSQUEDA DE DOMINIOS .ES
            # Extrae cadenas en la forma "dominio.es" puesto que, en determinados portales de presentación de los actores, se incluye el dominio de la empresa víctima, v.g. Lockbit3.0
            dominios_es = set(re.findall(r'\b([a-z0-9\-]+\.es)\b', texto_web, re.IGNORECASE))
            
            for dominio in dominios_es:
                dominio_upper = dominio.upper()
                info_evento_es = f"Dark Web Leak | Objetivo: {dominio_upper} | Actor: {actor} | Informe: Posible víctima detectada (.es)"
                
                if es_duplicado(misp, info_evento_es):
                    print(f"    [~] La exposición del dominio {dominio_upper} por {actor} ya está registrada.")
                    continue
                    
                hits += 1
                print(f"    [!] Posible víctima: Dominio '{dominio_upper}' expuesto en el portal del grupo o actor {actor}")
                
                evento_es = MISPEvent()
                evento_es.info = info_evento_es
                evento_es.date = time.strftime('%Y-%m-%d')
                evento_es.distribution = 0
                evento_es.threat_level_id = 1 
                evento_es.analysis = 2
                evento_es.published = True
                
                evento_es.add_attribute('target-org', dominio_upper)
                evento_es.add_attribute('threat-actor', actor)
                evento_es.add_attribute('url', site, comment="Posible ataque ransomware (Víctima Española)")

                evento_es.add_tag(f'Objetivo:{dominio_upper}')
                evento_es.add_tag('Sector:Logistica')
                evento_es.add_tag('Country:ES')
                evento_es.add_tag('Fuente:DarkWeb')
                
                try:
                    misp.add_event(evento_es)
                except Exception as e:
                    print(f"    [-] Error al inyectar evento nacional en MISP: {e}")
                
        except Exception as e:
            print(f"    [-] Excepción no controlada durante el escaneo: {e}")
        
        time.sleep(10)

    if hits == 0:
        print("[+] Patrulla Dark Web finalizada: Superficie corporativa segura (0 menciones).")
    else:
        print(f"[+] Patrulla Dark Web finalizada: Se han escalado {hits} incidentes críticos a MISP.")

if __name__ == "__main__":
    scrape_onion()
