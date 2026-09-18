#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
=============================================================================
MÓDULO DE INTELIGENCIA OSINT: MONITORIZACIÓN DE REPOSITORIOS PASTE
=============================================================================
Objetivo: Automatizar la búsqueda e identificación de posibles fugas de información
          en repositorios de texto plano públicos (Pastebin, ControlC, Paste.ee, Rentry).
          mediante el motor de búsqueda DuckDuckGo y el uso de expresiones
          y comodines de búsqueda (dorks)
=============================================================================
"""
# Se ha optado por el uso de DuckDuckGo por ser más permisivo en cuanto a consultas que otros motores
# más restrictivos como Google
from ddgs import DDGS 
import urllib3                       
from pymisp import PyMISP, MISPEvent 
import time                          
import os                            
import re                            
import requests                      
from datetime import datetime        

# Desactivación de advertencias SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from dotenv import load_dotenv

# ===========================================================================
# 1. SEGURIDAD OPERACIONAL (OPSEC) Y FUENTES
# ===========================================================================
load_dotenv('/opt/.secrets.env')
MISP_URL = os.getenv('MISP_URL')
MISP_KEY = os.getenv('MISP_API_KEY')

# Se establece un User-Agent para realizar las búsquedas
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
# Se definen los repositorios
DOMINIOS_PASTE = ["pastebin.com", "controlc.com", "paste.ee", "rentry.co"]

# ===========================================================================
# 2. FUNCIÓN DE COMPROBACIÓN DE DUPLICADOS
# ===========================================================================
def es_duplicado(misp_instance, target_url):
    """
    Verifica que un evento no exista previamente en la BBDD de MISP
    """
    try:
        matches = misp_instance.search(controller='attributes', type_attribute='url', value=target_url)
        if isinstance(matches, dict) and 'Attribute' in matches:
            return len(matches.get('Attribute', [])) > 0
        elif isinstance(matches, list) and len(matches) > 0:
            return True
        return False
    except Exception as e:
        print(f"    [-] Excepción interna en verificación de IoC: {e}")
        return False

# ===========================================================================
# 3. Validación de fecha
# ===========================================================================
def validar_fecha_pastebin(url):
    """
    Analiza los metadatos de publicación del paste (article:published_time).
    Descarta publicaciones con más de 30 días de antigüedad.
    """
    try:
        res = requests.get(url, headers=HEADERS, timeout=10)
        if res.status_code in [403, 401, 429]:
            return True # Ante bloqueos de Cloudflare, se permite el paso por precaución táctica
        if res.status_code != 200:
            return False 
            
        match = re.search(r'property="article:published_time"\s+content="([^"]+)"', res.text)
        if match:
            fecha_str = match.group(1)[:10] 
            fecha_pub = datetime.strptime(fecha_str, '%Y-%m-%d')
            dias_antiguedad = (datetime.now() - fecha_pub).days

            # Ventana de criticidad: Máximo 30 días
            if dias_antiguedad > 30:
                return False 
            return True 
        else:
            return True
    except Exception:
        return True

# ===========================================================================
# 4. CARGA DE FICHEROS
# ===========================================================================
try:
    with open('/opt/empresas.txt', 'r', encoding='utf-8') as f:
        empresas = [line.strip().lower() for line in f if line.strip()]
except FileNotFoundError:
    print("[-] Error crítico: No se localizó el diccionario /opt/empresas.txt")
    empresas = []

# Expresión regular que verifica que el término a buscar no se encuentre dentro de otras cadenas, es decir, aisla el término.
# Además, no discrimina mayúsculas de minúsculas y busca caracteres especiales como texto literal
# (por ejemplo, en la empresa AT&T, intrepretaría el carácter & como un carácter más)
PATRONES = {emp: re.compile(rf"(?<![a-zA-Z0-9_]){re.escape(emp)}(?![a-zA-Z0-9_])", re.IGNORECASE) for emp in empresas}

# ===========================================================================
# 5. LÓGICA DE BÚSQUEDA
# ===========================================================================
def search_pastebin():
    print("[*] Iniciando búsqueda de términos en Pastebin, ControlC, Paste.ee y Rentry...")
    
    if not empresas:
        print("[-] Ejecución abortada: Diccionario de activos corporativos vacío.")
        return

    try:
        misp = PyMISP(MISP_URL, MISP_KEY, False)
    except Exception as e:
        print(f"[-] Error de enlace con la infraestructura central MISP: {e}")
        return

    hits = 0
    
    # Uso de dorks para las consultas a través del motor de búsqueda DuckDuckGo (DDGS)
    with DDGS() as ddgs:
        for company in empresas:
            query = f'"{company}" (site:pastebin.com OR site:controlc.com OR site:paste.ee OR site:rentry.co)'
            print(f"[*] Ejecutando Dorking analítico para: {company.upper()}")
            
            try:
                # Se buscan resultados indexados en DuckDuckGo al último mes (timelimit='m'). 
                results_gen = ddgs.text(query, max_results=30, timelimit='m')
                results = list(results_gen) if results_gen else []
                
                if results:
                    for r in results:
                        url = r.get('href', '')
                        snippet = r.get('body', '')  
                        title = r.get('title', '')
                        
                        # Comprueba las empresas en cada sitio paste
                        es_sitio_paste = any(dominio in url for dominio in DOMINIOS_PASTE)

                        if es_sitio_paste:
                            es_valido = False
                            patron_estricto = PATRONES[company]
                            
                            if patron_estricto.search(snippet) or patron_estricto.search(title) or patron_estricto.search(url):
                                es_valido = True
                            else:
                                # Busca en la sección "RAW" de Pastebin para optimizar las búsquedas
                                # ya que viene el texto sin formatear
                                raw_url = url
                                if "pastebin.com/" in url and "/raw/" not in url:
                                    raw_url = url.replace("pastebin.com/", "pastebin.com/raw/")
                                elif "rentry.co/" in url and "/raw" not in url:
                                    raw_url = url.rstrip('/') + "/raw"
                                
                                try:
                                    res_raw = requests.get(raw_url, headers=HEADERS, timeout=10)
                                    if res_raw.status_code == 200:
                                        if patron_estricto.search(res_raw.text):
                                            es_valido = True
                                    elif res_raw.status_code in [403, 401, 429]:
                                        # Si Cloudflare bloquea la lectura u otro tipo de bloqueos (Rate limit), 
                                        # se prioriza el positivo para no perder la alerta para posteriormente analizarla.
                                        es_valido = True
                                except:
                                    pass
                            
                            if not es_valido: continue

                            # Validación de fecha para Pastebin
                            if "pastebin.com" in url:
                                if not validar_fecha_pastebin(url): continue

                            # Verificación de eventos ya existentes
                            if es_duplicado(misp, url):
                                print(f"    [~] Evento encontrado en MISP. Omitido: {url}")
                                continue

                            # =======================================================
                            # FORMATEO DE LOS EVENTOS DETECTADOS E INYECCIÓN DEL EVENTO EN MISP
                            # =======================================================
                            event = MISPEvent()
                            event.info = f"Fuga de Información: Mención en Repositorio de Texto sobre {company.upper()}"
                            event.date = time.strftime('%Y-%m-%d')
                            event.distribution = 0     # Ninvel de confidencialidad para distribución (TLP)
                            event.threat_level_id = 3  # Nivel 3: Informativo/Bajo (Requiere análisis humano posterior)
                            event.analysis = 2         # Análisis inicial completado
                            event.published = True     # Publicación del evento
                            
                            event.add_tag('Sector:Logistica')
                            event.add_tag('Country:ES')
                            event.add_tag('Fuente:PasteRepositories')
                            event.add_tag('Type:Data-Leak')
                            event.add_tag(f'Objetivo:{company.upper()}')
                            
                            # Adición de la URL de tipo paste
                            event.add_attribute('url', url, comment="Evidencia de fuga localizada: ")
                            event.add_attribute('target-org', company.upper())
                            
                            misp.add_event(event)
                            print(f"    [!] POSIBLE EXFILTRACIÓN DETECTADA: Inyectando evento en MISP -> {url}")
                            hits += 1
                            
            except Exception as e:
                error_str = str(e).lower()
                if "no results" in error_str or "not found" in error_str: pass
                elif "requesterror" in error_str or "mojeek" in error_str or "timeout" in error_str: pass
                # Evasión de CAPTCHAs con retardo de 20 segundos
                elif "rate limit" in error_str or "429" in error_str or "decodeerror" in error_str or "duckduckgo.com/html" in error_str:
                    print("    [!] Posible anti-bot detectado en el buscador. Esperando 20 segundos...")
                    time.sleep(20)
                else: 
                    print(f"    [-] Error imprevisto en ciclo de consulta: {e}")

            # Retardo operativo por buenas prácticas
            time.sleep(10) 
            
    if hits > 0:
        print(f"\n[+] Operación completada: Se han consolidado {hits} incidentes de exfiltración en MISP.")
    else:
        print("\n[+] Operación completada: Superficie corporativa segura en repositorios de texto plano.")

if __name__ == "__main__":
    search_pastebin()