#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
=============================================================================
MÓDULO DE INGESTA DE CIBERINTELIGENCIA PROACTIVA: OSINT FEEDS (RSS)
=============================================================================
Objetivo: Monitorizar canales RSS de noticias y boletines de ciberseguridad
          para identificar amenazas emergentes y campañas que apunten al
          sector logístico español.
=============================================================================
"""

import os
import re
import logging
import requests
import feedparser
import time
from pymisp import PyMISP, MISPEvent
import urllib3

# Se desactivan las advertencias de certificados SSL autofirmados
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from dotenv import load_dotenv

# ===========================================================================
# 1. SEGURIDAD OPERACIONAL (OPSEC) Y CONFIGURACIÓN INICIAL
# ===========================================================================
load_dotenv('/opt/.secrets.env')
MISP_URL = os.getenv('MISP_URL')
MISP_KEY = os.getenv('MISP_API_KEY')
MISP_VERIFYCERT = False

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
}

# Sistema de logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("OSINT")

def leer_diccionario_seguro(ruta):
    try:
        with open(ruta, 'r', encoding='utf-8') as f:
            return [line.strip().lower() for line in f if line.strip()]
    except UnicodeDecodeError:
        with open(ruta, 'r', encoding='latin-1') as f:
            return [line.strip().lower() for line in f if line.strip()]
    except FileNotFoundError:
        return []

# ===========================================================================
# 2. LÓGICA DE EVITAR DEDUPLICACIÓN DE EVENTOS
# ===========================================================================
def es_duplicado(misp_instance, info_text):
    """
    Realiza una validación cruzada en MISP usando el parámetro 'eventinfo' 
    para garantizar que el evento no se hay inyectado con anterioridad.
    """
    try:
        
        matches = misp_instance.search(controller='events', eventinfo=info_text, deleted=0)
        if isinstance(matches, list) and len(matches) > 0:
            return True
        return False
    except Exception as e:
        logger.error(f"[-] Error en consulta de duplicidad: {e}")
        return False

# ===========================================================================
# 3. CONEXIÓN A MISP
# ===========================================================================
def init_misp():
    try:
        return PyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT)
    except Exception as e:
        logger.error(f"[-] Error conectando a MISP: {e}")
        return None

def ingest_to_misp(misp, title, description, link, objetivo, amenaza_detectada, chivato):
    actor = "Sin determinar"
    info_evento = f"OSINT Feed | Objetivo: {objetivo} | Amenaza: {amenaza_detectada} | Informe: {title[:50]}..."

    if es_duplicado(misp, info_evento):
        logger.info(f"[~] OMITIDO (Ya en MISP): {title[:40]}...")
        return False

    logger.info(f"[!] ALERTA OSINT CONFIRMADA -> Objetivo: {objetivo} | Amenaza: {amenaza_detectada}")
    logger.info(f"    -> [Debug] Detectado por: '{chivato}'")

    event = MISPEvent()
    event.info = info_evento
    event.date = time.strftime('%Y-%m-%d')
    event.distribution = 0
    event.threat_level_id = 2 
    event.analysis = 2
    event.published = True

    event.add_attribute('link', link, comment="Fuente original")
    
    # Sanitización del formato HTML
    clean_desc = re.sub('<[^<]+?>', '', description)
    event.add_attribute('comment', clean_desc[:1000], comment="Abstract de la noticia")
    
    event.add_attribute('target-org', objetivo)
    event.add_attribute('threat-actor', actor)

    # Etiquetado de tags
    if "MÚLTIPLE" not in objetivo:
        event.add_tag(f"Objetivo:{objetivo}")
    event.add_tag("Sector:Logistica")
    event.add_tag("Country:ES")
    event.add_tag("Fuente:OSINT")

    try:
        misp.add_event(event)
        return True 
    except Exception as e:
        logger.error(f"[-] Error inyectando en MISP: {e}")
        return False

# ===========================================================================
# 4. LÓGICA DE FILTRADO DE FUENTES
# ===========================================================================
def scrape_feeds():
    misp = init_misp()
    if not misp: return
    
    hits = 0

    try:
        with open('/opt/fuentes.txt', 'r', encoding='utf-8') as f:
            FEEDS = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logger.error("[-] No se encontró el archivo de fuentes.txt")
        return

    empresas = leer_diccionario_seguro('/opt/empresas.txt')
    amenazas = leer_diccionario_seguro('/opt/amenazas.txt')
    terminos = leer_diccionario_seguro('/opt/terminos.txt')
    terminos.extend(['logistic', 'transport', 'supply chain', 'freight', 'shipping', 'logistics', 'transportation'])

    # Indicamos términos fijos que no pueden cambiar (ubicaciones geográficas españolas), a diferencia de los listados usados, 
    # que pueden cambiar con el tiempo por diferentes motivos
    marcadores_geo = ['spain', 'españa', 'espana', 'madrid', 'barcelona', 'valencia', 'sevilla', 'bilbao', 'malaga', 'coruña', 'nacional']

    for feed_url in FEEDS:
        logger.info(f"[*] Escaneando fuente: {feed_url}")
        try:
            response = requests.get(feed_url, headers=HEADERS, timeout=15)
            if response.status_code != 200:
                continue
                
            feed = feedparser.parse(response.content)

            if not getattr(feed, 'entries', None):
                continue

            for entry in feed.entries:
                title = entry.get('title', '')
                description = entry.get('description', '')
                link = entry.get('link', '')

                # Limpiamos el HTML ANTES de la búsqueda para evitar falsos positivos
                
                desc_limpia = re.sub('<[^<]+?>', ' ', description).lower()
                texto_completo = f"{title.lower()} {desc_limpia}"

                # -------------------------------------------------------------
                # 1. EVALUAR AMENAZA
                # -------------------------------------------------------------
                es_amenaza = False
                amenaza_str = "Desconocida"
                for am in amenazas:
                    if am and re.search(rf'\b{re.escape(am)}\b', texto_completo, re.IGNORECASE):
                        es_amenaza = True
                        amenaza_str = am.upper()
                        break
                        
                if not es_amenaza:
                    continue

                # -------------------------------------------------------------
                # 2. EVALUAR PAÍS (ESPAÑA)
                # -------------------------------------------------------------
                es_espana = False
                for marcador in marcadores_geo:
                    if re.search(rf'\b{marcador}\b', texto_completo, re.IGNORECASE):
                        es_espana = True
                        break

                # -------------------------------------------------------------
                # 3. EVALUAR OBJETIVO (EMPRESA O SECTOR LOGÍSTICO)
                # -------------------------------------------------------------
                es_empresa = False
                es_sector = False
                objetivo_final = ""
                palabra_chivato = ""

                # A) Búsqueda de Empresas
                for emp in empresas:
                    if emp and re.search(rf'\b{re.escape(emp)}\b', texto_completo, re.IGNORECASE):
                        es_empresa = True
                        objetivo_final = emp.upper()
                        palabra_chivato = emp
                        break
                        
                # B) Búsqueda de términos logísticos
                if not es_empresa and es_espana:
                    for term in terminos:
                        if term and re.search(rf'\b{re.escape(term)}\b', texto_completo, re.IGNORECASE):
                            es_sector = True
                            objetivo_final = f"MÚLTIPLE: Sector Logístico ({term.upper()})"
                            palabra_chivato = term
                            break

                # -------------------------------------------------------------
                # 4. GENERACIÓN DE ALERTA
                # -------------------------------------------------------------
                # Debe ser empresa española OR (PAIS = España AND Sector Logístico))
                if es_empresa or (es_espana and es_sector):
                    if ingest_to_misp(misp, title, description, link, objetivo_final, amenaza_str, palabra_chivato):
                        hits += 1

        except Exception as e:
            logger.error(f"[-] Fallo procesando {feed_url}: {e}")
            
    logger.info(f"============== ANÁLISIS FINALIZADO: {hits} Alertas NUEVAS Inyectadas ==============")

if __name__ == "__main__":
    scrape_feeds()