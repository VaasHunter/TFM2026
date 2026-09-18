#!/usr/bin/env python3
# -*- coding: utf-8 -*-


# ===========================================================================
# 1. OBJETIVO: extraer incidentes de la plataforma ransomware.live 
#     que afecten a empresas españolas del sector logístico mediante
#     las etiquetas de "activity" y "country".
# ===========================================================================


import requests
from pymisp import PyMISP, MISPEvent
import urllib3
import os
import re
import time 

# Desactivación de advertencias SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
MISP_VERIFYCERT = False 

from dotenv import load_dotenv

# ===========================================================================
# 1. VARIABLES DE ENTORNO (OPSEC)
# ===========================================================================
# Por motivos de seguridad operativa , se han ocultado datos sensibles (API e IP) en un archivo oculto y restringido.
load_dotenv('/opt/.secrets.env')
MISP_URL = os.getenv('MISP_URL')
MISP_KEY = os.getenv('MISP_API_KEY')

def leer_diccionario(ruta):
    """
    Carga de ficheros locales de texto plano y cambia a minusculas para optimizar la busqueda    """
    try:
        with open(ruta, 'r', encoding='utf-8') as f:
            return [line.strip().lower() for line in f if line.strip()]
    except:
        return []

# Funcion para indicar la indisponibilidad de la API externa
def limpiar_texto(texto_bruto, valor_por_defecto="Desconocido"):
    t = str(texto_bruto).strip()
    t_low = t.lower()
    if not t or "not available" in t_low or "unknown" in t_low or "n/a" in t_low:
        return valor_por_defecto
    return t

# ===========================================================================
# 2. CREACION DEL COMPROBADOR DE DUPLICADOS
# ===========================================================================
def es_duplicado(misp_instance, info_text):
    
    #Busca el parámetro 'eventinfo' para localizar posibles duplicados en MIPS y evitar duplicidad
    try:
        # Consulta filtrada por el campo descriptivo principal del evento
        matches = misp_instance.search(controller='events', eventinfo=info_text) 
        
        # Si la respuesta de la API contiene registros, el evento ya está documentado
        if isinstance(matches, list) and len(matches) > 0:
            return True
        return False
    except Exception as e:
        print(f"[-] Error en el proceso de verificación de estados: {e}")
        return False

# ===========================================================================
# 3. LÓGICA DEL SCRIPT
# ===========================================================================
def main():
    print("[*] Iniciando ingestor analítico de Ransomware.live...")

    # Carga de los diccionarios
    empresas = leer_diccionario('/opt/empresas.txt')
    terminos = leer_diccionario('/opt/terminos.txt')
    
    # Como la API de Ramsonware utiliza el idioma inglés, se añaden términos en ese idioma
    terminos_base = ['logistic', 'transport', 'supply chain', 'freight', 'shipping', 'transportation/logistics']
    terminos.extend(terminos_base)

    patrones_empresas = {emp: re.compile(rf"\b{re.escape(emp)}\b", re.IGNORECASE) for emp in list(set(empresas)) if emp}

    try:
        # 
        misp = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT)

        # Se define la API de Ramsomware.live
        url_api = "https://api.ransomware.live/recentvictims"
        response = requests.get(url_api, timeout=15)

        if response.status_code != 200:
            print(f"[-] Error en la resolución de la API externa: {response.status_code}")
            return

        victimas = response.json()
        print(f"[*] Datos estructurados descargados. Aplicando reglas de filtrado analítico...")

        hits = 0
        for v in victimas:
            # Parsea los campos necesarios del JSON de la API
            pais = (v.get('country') or '').strip().upper()
            descripcion = (v.get('description') or '').lower()
            titulo = (v.get('post_title') or '').lower()
            actividad = (v.get('activity') or '').lower()
            
            grupo = limpiar_texto(v.get('group_name'), 'Desconocido')
            nombre_real = limpiar_texto(v.get('post_title'), 'Desconocido')
            actividad_limpia = limpiar_texto(v.get('activity'), 'N/A')

            # -----------------------------------------------------------------------
            # FILTRO DE PAIS (ESPAÑA)
            # -----------------------------------------------------------------------
            es_espana = False
            
            # La primera condición es que la empresa o entidad atacada tenga la sede en España
            if pais == 'ES':
                es_espana = True
            # Si el campo de país está vacío o es desconocido, se buscan términos relacionados con España en la descripción. 
            elif not pais or pais == 'N/A' or pais == 'UNKNOWN':
                if re.search(r'\b(spain|españa|espana)\b', descripcion):
                    es_espana = True

            if not es_espana:
                continue

            # -----------------------------------------------------------------------
            # FILTRO POR EMPRESAS Y SECTOR (LOGISTICO)
            # -----------------------------------------------------------------------
            match_empresa = False
            match_sector = False

            # EMPRESAS
            texto_empresa = f"{titulo} {descripcion}"
            for emp, patron in patrones_empresas.items():
                if patron.search(texto_empresa):
                    match_empresa = True
                    break

            # SECTOR
            texto_sector = f"{actividad} {descripcion}"
            for term in terminos:
                # Se verifica si el término está contenido dentro de otra cadena (ej. "port" dentro de "reports").
                if term and re.search(rf"\b{re.escape(term)}\b", texto_sector):
                    match_sector = True
                    break

            # -----------------------------------------------------------------------
            # FORMATEO DEL EVENTO PARA MISP E INYECCIÓN DEL MISMO
            # -----------------------------------------------------------------------
            # Si el país víctima es España y la empresa es española o pertenece a sector logístico, se ingesta el evento
            if match_empresa or match_sector:
                
                titulo_alerta = f"Ataque Ransomware ({grupo}) contra: {nombre_real}"
                
                # Se comprueba que no exista previamente en MISP
                if es_duplicado(misp, titulo_alerta):
                    print(f"    [~] Registro omitido de forma segura (Incidente preexistente): {nombre_real}")
                    continue
                
                hits += 1
                print(f"[!] AMENAZA CONFIRMADA: Inyectando vector crítico en la infraestructura -> {nombre_real}")

                # Construcción del evento
                event = MISPEvent()
                event.info = titulo_alerta
                event.date = time.strftime('%Y-%m-%d')
                event.distribution = 0     
                event.threat_level_id = 1  # Asignación de nivel de amenaza: Alto
                event.analysis = 2         # Estado de la investigación: Análisis Completado
                event.published = True     # Publicación automática obligatoria para su recolección posterior por el SIEM
                
                # Aplicación de TAGS para su posterior identificacion
                event.add_tag('Sector:Logistica')
                event.add_tag('Country:ES')
                event.add_tag('Fuente:RansomwareLive')
                if match_empresa: 
                    # Se añade etiqueta con la empresa o entidad víctima
                    event.add_tag(f'Objetivo:{nombre_real}')

                # Se añaden atributos (grupos de amenaza y el objetivo)
                event.add_attribute('threat-actor', grupo)
                event.add_attribute('target-org', nombre_real)
                
                
                if actividad_limpia != 'N/A':
                    event.add_attribute('comment', f"Actividad indicada por la API de origen: {actividad_limpia}")
                
                if v.get('website'):
                    event.add_attribute('link', v.get('website'), comment="Sitio web de la entidad afectada")

                # Se agrega el evento en MISP
                misp.add_event(event)

        if hits == 0:
            print("[+] Ejecución completada con éxito. No se han detectado nuevas amenazas críticas.")
        else:
            print(f"\n[+] Ejecución completada con éxito. Se han consolidado {hits} eventos en la plataforma.")

    except Exception as e:
        print(f"[-] Excepción crítica detectada en el flujo operacional: {e}")

if __name__ == '__main__':
    main()