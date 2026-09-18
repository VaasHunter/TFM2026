#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
=============================================================================
MÓDULO DE INGESTA DE INTELIGENCIA ESTRATÉGICA: INCIDENTBUDDY (PROFILER)
=============================================================================
Objetivo: Extraer  los TTPs de los diferentes actores de amenazas relacionados
con el sector logístico español, mediante el uso de la API de la plataforma de
ciberinteligencia IncidentBuddy.
=============================================================================
"""

import os
import time
import requests
import urllib3
import urllib.parse
from dotenv import load_dotenv
from pymisp import PyMISP, MISPEvent

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===========================================================================
# 1. SEGURIDAD OPERACIONAL (OPSEC) Y VARIABLES DE ENTORNO
# ===========================================================================
# Carga estructurada de tokens y claves de API desde almacenamiento seguro
load_dotenv('/opt/.secrets.env')
MISP_URL = os.getenv('MISP_URL')
MISP_KEY = os.getenv('MISP_API_KEY')
IB_API = os.getenv('INCIDENTBUDDY_API')

# ===========================================================================
# 2. PERFILADO DE ACTORES DE AMENAZA
# ===========================================================================
def main():
    print("[*] Iniciando Perfilado Estratégico de Actores (IncidentBuddy)...")

    if not IB_API:
        print("[-] Error crítico: INCIDENTBUDDY_API no definida en entorno seguro.")
        return

    try:
        with open('/opt/actores.txt', 'r', encoding='utf-8') as f:
            actores = [line.strip() for line in f if line.strip()]
        print(f"[*] Cargados {len(actores)} actores de amenazas desde la lista de control.")
    except FileNotFoundError:
        print("[-] Error: Directorio de actores objetivo (/opt/actores.txt) no localizado.")
        return

    try:
        misp = PyMISP(MISP_URL, MISP_KEY, False)
    except Exception as e:
        print(f"[-] Error estableciendo comunicación con MISP: {e}")
        return

    headers = {
        "X-API-Key": IB_API,
        "Content-Type": "application/json"
    }

    hits = 0
    
    # -----------------------------------------------------------------------
    # PROCESAMIENTO DE TTPs. Extrae de la plataforma las TTPs de cada actor 
    # indicado en el listado actores.txt
    # -----------------------------------------------------------------------
    for actor in actores:
        print(f"[*] Extrayendo Inteligencia Estratégica para: {actor}...")
        
        actor_url = urllib.parse.quote(actor)
        api_url = f"https://incidentbuddy.ai/api/v1/actors/{actor_url}"
        
        try:
            # Petición a la API
            res = requests.get(api_url, headers=headers, timeout=15)
            status_code = res.status_code
            
            if status_code == 200:
                data = res.json()
                
                # Declaración del evento
                info_evento = f"IncidentBuddy - Perfil Estrategico de Amenaza: {actor.upper()}"
                
                techniques = data.get('techniques', []) or []
                aliases = data.get('aliases', []) or []
                
                existing_events = misp.search(controller='events', eventinfo=info_evento)
                existing_event = None
                existing_ttps = set()

                if isinstance(existing_events, list) and len(existing_events) > 0:
                    existing_event = existing_events[0].get('Event', {})
                    attributes = existing_event.get('Attribute', [])
                    for attr in attributes:
                        if attr.get('type') == 'comment':
                            existing_ttps.add(attr.get('value'))

                nuevas_ttps = []
                for tech in techniques:
                    tech_id = tech.get('id', 'N/A')
                    tech_name = tech.get('name', 'Desconocida')
                    tactic = tech.get('tactic', 'N/A')
                    formatted_ttp = f"Táctica: {tactic} | Técnica: {tech_id} - {tech_name}"
                    
                    if formatted_ttp not in existing_ttps:
                        nuevas_ttps.append(formatted_ttp)

                # Si el perfil ya existía en MISP y no hay nuevas TTPS, se omite
                if existing_event is not None:
                    if not nuevas_ttps:
                        print(f"    [~] Omitido: El perfil estratégico de {actor.upper()} no presenta modificaciones.")
                        continue
                    
                    event_id = existing_event['id'] 
                    
                    try:
                        # Añade nuevas TTPs como atributos
                        misp.add_attribute(event_id, {'type': 'comment', 'value': f"Actualización estratégica: {len(nuevas_ttps)} nuevas TTPs encontradas. Ver más informacion sobre el perfil y TTPs del actor en MISP"}) 
                        for ttp_line in nuevas_ttps: 
                            misp.add_attribute(event_id, {'type': 'comment', 'value': ttp_line})
                        
                        misp.add_attribute(event_id, {'type': 'link', 'value': f"{MISP_URL}/events/view/{event_id}", 'comment': "URL MISP (Actualización)"})
                        print(f"    [+] Cambios detectados: Perfil de {actor.upper()} actualizado con {len(nuevas_ttps)} nuevas TTPs.")
                        hits += 1
                    except Exception as e:
                        print(f"    [-] Error al empujar la actualización a MISP: {e}")

                # Si el perfil es nuevo, se ingesta en MISP por primera vez
                # Se añaden las etiquestas y atributos correcspondientes (nombre del actor o grupo, alias
                else:
                    event = MISPEvent()
                    event.info = info_evento
                    event.date = time.strftime('%Y-%m-%d') 
                    event.distribution = 0
                    event.threat_level_id = 3 
                    event.analysis = 2
                    event.published = True
                    
                    event.add_tag('Country:ES')
                    event.add_tag('Inteligencia CiberBuddy')
                    event.add_tag('Sector:Logistica')
                    event.add_tag('tlp:white')
                    
                    event.add_attribute('threat-actor', actor, comment="Actor Principal")
                    for alias in aliases:
                        event.add_attribute('threat-actor', alias, comment="Alias conocido")
                    
                    event.add_attribute('comment', f"Perfil Inicial: {len(nuevas_ttps)} TTPs encontradas. Ver más informacion sobre el perfil y TTPs del actor en MISP")
                    for ttp_line in nuevas_ttps:
                        event.add_attribute('comment', ttp_line)
                    
                    try:
                        respuesta = misp.add_event(event) 
                        event_id = respuesta.id if hasattr(respuesta, 'id') else respuesta['Event']['id'] 
                        
                        # Se añade la URL del evento de MISP para localizarlo en el futuro
                        misp.add_attribute(event_id, {'type': 'link', 'value': f"{MISP_URL}/events/view/{event_id}", 'comment': "URL MISP"}) 

                        print(f"    [+] Primer registro: Perfil de {actor.upper()} consolidado en MISP con {len(nuevas_ttps)} TTPs.")
                        hits += 1
                    except Exception as e:
                        print(f"    [-] Error al crear el evento en MISP: {e}")

            # Si la cuota de API se agota, se detiene el script e informa
            elif status_code == 429:
                print("    [!] ALARMA: Límite de la API alcanzado (Quota Exceeded). Se aborta la operación para proteger el histórico.")
                break
                
            elif status_code == 404:
                print(f"    [-] {actor}: No documentado en la base de datos externa.")
            else:
                print(f"    [-] Error HTTP {status_code} al consultar el perfil de {actor}.")

        except Exception as e:
            print(f"    [-] Excepción de red detectada: {e}")

        time.sleep(3)

    if hits == 0:
        print("\n[+] Operación completada: No se requieren actualizaciones en los perfiles estratégicos.")
    else:
        print(f"\n[+] Operación completada: Se han añadido o actualizado {hits} perfiles en la plataforma.")

if __name__ == '__main__':
    main()