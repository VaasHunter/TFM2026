#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
=============================================================================
MÓDULO EASM (EXTERNAL ATTACK SURFACE MANAGEMENT): INTEGRACIÓN SHODAN - MISP
=============================================================================
Objetivo: Monitorizar la superficie de exposición de ataque externa de 
          las organizaciones. Evalúa la exposición de puertos 
          e identifica aquellos con CVES. Verifica actualizaciones
          de CVEs en eventos previamente inyectados en MISP.
=============================================================================
"""

import shodan
from pymisp import PyMISP, MISPEvent
import urllib3
import os
import re
import time

# Desactivación de advertencias de certificados SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from dotenv import load_dotenv

# ===========================================================================
# 1. SEGURIDAD OPERACIONAL (OPSEC) Y CONFIGURACIÓN SEGURA
# ===========================================================================
load_dotenv('/opt/.secrets.env')
MISP_URL = os.getenv('MISP_URL')
MISP_KEY = os.getenv('MISP_API_KEY')
SHODAN_KEY = os.getenv('SHODAN_API')

def leer_diccionario_seguro(ruta):
    """
    Carga y normaliza los ficheros fuente locales
    """
    try:
        with open(ruta, 'r', encoding='utf-8') as f:
            return [line.strip().lower() for line in f if line.strip()]
    except UnicodeDecodeError:
        with open(ruta, 'r', encoding='latin-1') as f:
            return [line.strip().lower() for line in f if line.strip()]
    except FileNotFoundError:
        return []

# ===========================================================================
# 2. COMPROBACION DE CVEs (nuevo, duplicado o cambio)
# ===========================================================================
def evaluar_estado_shodan(misp_instance, ip, port, current_cve_count):
    """
    Verifica el IOC en la BBDD de Shodan, por si ya existiera y ver el numero de CVEs que contenía inicialmente    
    Flujo Lógico:
      - NUEVO: Primera ocurrencia con vulnerabilidades.
      - DUPLICADO: El número de CVEs no ha variado.
      - CAMBIO: Modificación de CVEs
    """
    try:
        
        matches = misp_instance.search(controller='attributes', value=ip, type='ip-dst')
        
        if not matches or 'Attribute' not in matches:
            return "NUEVO", 0
            
        # El puerto debe coincidir completo ("Puerto: 80" no debe casar con "Puerto: 8080")
        patron_puerto = re.compile(rf'Puerto: {re.escape(str(port))}(?!\d)')

        # Si existen registros correlacionados, se recuperan los eventos padre y se toma el
        # MÁS RECIENTE como último estado conocido. Cuenta tanto el evento original
        # ("Shodan: N Vulnerabilidades") como los posteriores ("EASM UPDATE: ... a -> b"):
        # si solo se mirase el original, cada ejecución volvería a generar el mismo UPDATE.
        ultimo_id = -1
        ultimo_count = None
        for attr in matches.get('Attribute', []):
            event_id = attr.get('event_id')
            event = misp_instance.get_event(event_id)
            if not event or 'Event' not in event:
                continue

            info = event['Event'].get('info', '')

            # Verificación de contexto (Origen Shodan y persistencia de puerto)
            if ("Shodan" in info or "EASM UPDATE" in info) and patron_puerto.search(info):
                # Búsqueda de vulnerabilidades (en un UPDATE cuenta el valor NUEVO: "a -> b")
                m = re.search(r'CVEs: \d+ -> (\d+)', info)
                if not m:
                    m = re.search(r': (\d+) Vuln', info)

                if m and int(event_id) > ultimo_id:
                    ultimo_id = int(event_id)
                    ultimo_count = int(m.group(1))

        if ultimo_count is None:
            return "NUEVO", 0

        # Análisis de variación de CVEs respecto al último estado registrado
        if ultimo_count == current_cve_count:
            return "DUPLICADO", ultimo_count
        return "CAMBIO", ultimo_count
    except Exception as e:
        print(f"    [-] Excepción en el motor analítico de estados EASM: {e}")
        return "NUEVO", 0

# ===========================================================================
# 3. EXTRACCION DEL DATO
# ===========================================================================
def search_shodan():
    print("[*] Iniciando scraper de Superficie de Ataque (Shodan) ...")
    
    if not SHODAN_KEY:
        print("[-] ERROR: Credencial SHODAN_API no localizada en el entorno OPSEC.")
        return

    empresas = leer_diccionario_seguro('/opt/empresas.txt')
    if not empresas:
        print("[-] ERROR: El diccionario de empresas monitorizadas está vacío.")
        return

    # Inicialización la API
    api = shodan.Shodan(SHODAN_KEY)
    
    try:
        misp = PyMISP(MISP_URL, MISP_KEY, False)
    except Exception as e:
        print(f"[-] Error de conexión con la infraestructura MISP: {e}")
        return
    
    hits = 0
    
    # Búsqueda iterativa de empresas del fichero en Shodan
    for company in empresas:
        if not company: continue
        try:
            # Consulta de empresa
            query = f'org:"{company}"'
            print(f"[*] Consultando exposición externa (Filtro Org): {query}")
            results = api.search(query)
            
            for result in results.get('matches', []):
                ip = result.get('ip_str', '')
                port = result.get('port', '')
                vulns = result.get('vulns', [])
                banner = result.get('data', '') or ''
                org_name = result.get('org', '') or ''
                
                # Solo se procesa si la dupla IP-PUERTO presenta vulnerabilidades confirmadas (CVEs)
                if vulns:
                    # Uso de expresiones regulares basadas en delimitadores nativos (\b)
                    # para buscar razones sociales del WHOIS
                    match_banner = re.search(rf'\b{re.escape(company)}\b', banner, re.IGNORECASE)
                    match_org = re.search(rf'\b{re.escape(company)}\b', org_name, re.IGNORECASE)
                    
                    if match_banner or match_org:
                        current_count = len(vulns)
                        
                        # Evaluación histórica del activo
                        estado, old_count = evaluar_estado_shodan(misp, ip, port, current_count)
                        
                        # -----------------------------------------------------------
                        # LÓGICA CONDICIONAL. En esta sección es donde comprueba si el evento es nuevo, ya existe y si hay actualizaciones
                        # -----------------------------------------------------------
                        if estado == "DUPLICADO":
                            print(f"    [~] Estado Invariable en {ip}:{port} ({current_count} CVEs). Omisión segura.")
                            continue
                        
                        if estado == "CAMBIO":
                            info_evento = f"EASM UPDATE: Variación en {company.upper()} | IP: {ip} | Puerto: {port} | CVEs: {old_count} -> {current_count}"
                            print(f"    [!] ENRIQUECIMIENTO: {ip}:{port} presentó una variación crítica (CVEs: {old_count} -> {current_count}).")
                        else:
                            info_evento = f"Shodan: {current_count} Vulnerabilidades (CVEs) en {company.upper()} | IP: {ip} | Puerto: {port}"
                            print(f"    [!] VULNERABILIDAD CRÍTICA DETECTADA: {company.upper()} -> {ip}:{port} ({current_count} CVEs)")
                            
                        # Formateo del evento CTI en MISP
                        event = MISPEvent()
                        event.info = info_evento
                        event.distribution = 0     # Nivel de confidencialidad del evento para su compartición (TLP)
                        event.threat_level_id = 1  # Criticidad: Alta
                        event.analysis = 2         # Estado: Análisis completado (Dato empírico)
                        event.published = True     # Se establece en true para que aparezca en MISP
                        
                        # Tageado del evento
                        event.add_tag('Sector:Logistica')
                        event.add_tag('Country:ES')
                        event.add_tag('Fuente:Shodan')
                        event.add_tag('Type:EASM')
                        event.add_tag(f'Objetivo:{company.upper()}')
                        
                        # Inyección de Atributos : IP y puerto
                        event.add_attribute('ip-dst', ip, comment=f"Puerto expuesto: {port}")
                        
                        # Añade la info de detección por cada vulnerabilidad detectada
                        for v in vulns:
                            event.add_attribute('vulnerability', v, comment=f"Detectado expuesto en puerto {port}")
                        
                        # Adición del evento a MISP
                        misp.add_event(event)
                        hits += 1
                        
        except shodan.APIError as e:
            print(f"    [-] Excepción controlada en el servicio API de Shodan para {company}: {e}")
        except Exception as e:
            print(f"    [-] Excepción imprevista durante el análisis de {company}: {e}")
            
        # Control preventivo de Rate Limiting para cumplir las políticas de la API de Shodan
        time.sleep(3) 

    print(f"[+] Ciclo EASM finalizado. Se han consolidado {hits} actualizaciones de superficie de ataque en MISP.")

if __name__ == "__main__":
    search_shodan()