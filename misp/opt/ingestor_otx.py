#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
=============================================================================
MÓDULO DE INGESTA DE INTELIGENCIA TÁCTICA: ALIENVAULT OTX
=============================================================================
Objetivo: Recolectar, normalizar y filtrar informes de amenazas (Pulses) 
de la plataforma OTX de Alienvault. Implementa filtrado por país y sector
y extrae los posibles IoCs.
=============================================================================
"""

from OTXv2 import OTXv2
from pymisp import PyMISP, MISPEvent
import urllib3
import os
import re
import time
from datetime import datetime, timedelta

# Se desactivan las advertencias SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from dotenv import load_dotenv

# ===========================================================================
# 1. SEGURIDAD OPERACIONAL (OPSEC)
# ===========================================================================
# Se cargan las APIs y otros valores sensibles almacenados en un archivo oculto y con permisos de minimo privilegio

load_dotenv('/opt/.secrets.env')
MISP_URL = os.getenv('MISP_URL')
MISP_KEY = os.getenv('MISP_API_KEY')
OTX_KEY = os.getenv('OTX_API')

def leer_diccionario(ruta):
    """
    Lee archivos de texto locales que contienen los activos a monitorizar.
    """
    try:
        with open(ruta, 'r', encoding='utf-8') as f:
            return [line.strip().lower() for line in f if line.strip()]
    except: 
        return []

# ===========================================================================
# 2. SISTEMA DE PREVENCIÓN DE EVENTOS DUPLICADOS
# ===========================================================================
def es_duplicado(misp_instance, info_text):
    """
    Consulta la base de datos de MISP antes de realizar cualquier inyección y
    prevenir la duplicación de eventos.
    """
    try:
        
        matches = misp_instance.search(controller='events', eventinfo=info_text, deleted=0)
        if isinstance(matches, list) and len(matches) > 0:
            return True
        return False
    except:
        return False

# ===========================================================================
# 3. LÓGICA DEL SCRIPT
# ===========================================================================
def main():
    print("[*] Iniciando scraper de OTX AlienVault ...")
    
    # Verificación de tokens
    if not OTX_KEY: 
        print("[-] Error: Clave de AlienVault no detectada.")
        return
        
    otx = OTXv2(OTX_KEY)
    
    try:
        misp = PyMISP(MISP_URL, MISP_KEY, False)
    except Exception as e:
        print(f"[-] Error de conexión con MISP: {e}")
        return
    
    # Carga de ficheros
    empresas = leer_diccionario('/opt/empresas.txt')
    terminos = leer_diccionario('/opt/terminos.txt')
    
    # Se añaden términos logísticos en inglés
    terminos.extend(['logistic', 'transport', 'supply chain', 'freight', 'shipping', 'logistics', 'transportation'])

    # Se analizan los informes de los últimos 100 días

    rango_dias = 100
    fecha_inicio = (datetime.now() - timedelta(days=rango_dias)).isoformat()
    
    print(f"[*] Consultando informes de AlienVault desde {fecha_inicio[:10]}...")
    try:
        pulsos = otx.getsince(fecha_inicio)
    except Exception as e:
        print(f"[-] Error al descargar informes desde la API: {e}")
        return
    
    hits = 0
    
    for pulso in pulsos:
        # Se extran los diferentes campos del informe (pulse)
        titulo = (pulso.get('name') or '').lower()
        desc = (pulso.get('description') or '').lower()

        #Extracción de los Tags de la API
        tags_nativos = [str(t).lower() for t in pulso.get('tags', [])]
        
        # Se unifican todos los campos de texto
        texto_completo = f"{titulo} {desc} {' '.join(tags_nativos)}"
        
        # Se extraen los metadatos relacionados con los campos de países afectados y empresas
        paises_nativos = [str(p).lower() for p in pulso.get('targeted_countries', [])]
        industrias_nativas = [str(i).lower() for i in pulso.get('industries', [])]
        
        # -------------------------------------------------------------------
        # Se establecen términos geográficos españoles (algunos con su equivalente en inglés dado el idioma de la plataforma)
        # -------------------------------------------------------------------
        es_espana = False
        marcadores_geo = ['spain', 'españa', 'espana', 'madrid', 'barcelona', 'valencia', 'bilbao', 'sevilla', 'malaga', 'coruna' ]
        
        # Se valida si el país es España
        if any(re.search(r'\b(spain|españa|espana)\b', p) for p in paises_nativos): 
            es_espana = True
        else:
             for marcador in marcadores_geo:
                if re.search(rf'\b{marcador}\b', texto_completo, re.IGNORECASE):
                    es_espana = True
                    break
        
        # Si no afecta a España, se ignora el informe
        if not es_espana:
            continue
            
        # -------------------------------------------------------------------
        # Se verifica los terminos relacionados con las empresas y sector logístico
        # -------------------------------------------------------------------
        es_empresa = False
        es_sector = False
        nombre_objetivo = "Múltiples / Sector Logístico"
        palabra_trigger = "" #Variable de depuración

        # Busca empresas españolas
        for emp in empresas:
            if emp and re.search(rf'\b{re.escape(emp)}\b', texto_completo, re.IGNORECASE):
                es_empresa = True
                nombre_objetivo = emp.upper()
                palabra_trigger = emp
                break
                
        # Se buscan los términos logísticos
        match_industria = None
        for i in industrias_nativas:
            match = re.search(r'\b(logistic|logistics|transport|transportation)\b', i)
            if match:
                match_industria = match.group(0) # Extrae la palabra exacta (ej. "transportation")
                break
                
        if match_industria:
            es_sector = True
            palabra_trigger = match_industria # Asignamos la palabra real al disparador
        else:
            # Búsqueda de terminología logística mediante expresiones regulares
            for term in terminos:
                if term and re.search(rf'\b{re.escape(term)}\b', texto_completo, re.IGNORECASE):
                    es_sector = True
                    palabra_trigger = term
                    break
        # -------------------------------------------------------------------
        # Creación de evento e ingesta en la BBDD
        # -------------------------------------------------------------------
        # Si aparece una empresa española o bien el termino se encuentra en el listado,  inyecta el evento.
        if es_empresa or es_sector:
            
            actor_final = pulso.get('adversary') or "Sin determinar"
            titulo_pulso_original = pulso.get('name') or 'Reporte OTX'
            info_evento = f"OTX Pulse | Objetivo: {nombre_objetivo} | Actor: {actor_final} | Informe: {titulo_pulso_original[:50]}..."
            
            # Comprobación de eventos previos para no duplicar
            if es_duplicado(misp, info_evento):
                continue
                
            hits += 1
            pulse_id = pulso.get('id', '')
            url_informe = f"https://otx.alienvault.com/pulse/{pulse_id}"
            
            # Se indica por pantalla cuando se detecta un posible match
            print(f"[!] ALERTA OTX CONFIRMADA: {nombre_objetivo} (Actor: {actor_final})")
            print(f"    -> Se ha añadido evento en MISP por el término: '{palabra_trigger}'")
            
            # Generación del evento en formato JSON para MISP
            evento = MISPEvent()
            evento.info = info_evento
            evento.date = time.strftime('%Y-%m-%d')
            evento.distribution = 0     # Nivel de confidencialidad para distribución de información (TLP)
            evento.threat_level_id = 2  # Nivel Medio (Análisis posterior necesario)
            evento.analysis = 2         # Análisis inicial completado
            evento.published = True     # Se establece el evento publicado para posterio ingesta en SIEM (WAZUH)
            
            # Etiquetado y atributos en MISP
            
            evento.add_tag('Sector:Logistica')
            evento.add_tag('Country:ES')
            evento.add_tag('Fuente:AlienVault')
  
            evento.add_attribute('link', url_informe, comment="Informe Original OTX")
            evento.add_attribute('threat-actor', actor_final)

            # Si afecta a una empresa de listado, se añade el tag y atributo extra
            if es_empresa:
                evento.add_tag(f'Objetivo:{nombre_objetivo}')
                evento.add_attribute('target-org', nombre_objetivo)
            
            # ---------------------------------------------------------------
            # Extracción de posibles IOCs
            # ---------------------------------------------------------------
            for ioc in pulso.get('indicators', []):
                tipo = (ioc.get('type') or '').lower()
                valor = ioc.get('indicator', '')
                if not valor: continue
                
                # Si se encuentran IOCs, se añaden como atributo al evento
                if 'url' in tipo or 'domain' in tipo or 'hostname' in tipo:
                    evento.add_attribute('url', valor, comment="Infraestructura maliciosa")
                elif 'ipv4' in tipo:
                    evento.add_attribute('ip-dst', valor)
                # OTX nombra estos tipos "FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256"...
                # Se distingue cada algoritmo (todos contienen "hash": no vale un 'hash' genérico).
                # Otros tipos (IMPHASH, PEHASH...) no se ingestan.
                elif 'sha256' in tipo:
                    evento.add_attribute('sha256', valor)
                elif 'sha1' in tipo:
                    evento.add_attribute('sha1', valor)
                elif 'md5' in tipo:
                    evento.add_attribute('md5', valor)
                    
            # Se añade el evento
            misp.add_event(evento)

    if hits == 0:
        print("[+] Operación completada: No se han detectado nuevos eventos.")
    else:
        print(f"\n[+] Operación completada: Se han inyectado {hits} eventos.")

if __name__ == "__main__":
    main()