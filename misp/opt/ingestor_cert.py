#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
=============================================================================
MÓDULO DE OBTENCIÓN DE CERTIFICADOS POTENCIALMENTE PELIGROSOS (CRT.SH)
=============================================================================
Objetivo: Monitorizar el registro de certificados en la plataforma crt.sh, 
          (concretamente para subdominios), con el fin de detectar posibles
          infraestructuras maliciosa en fase temprana (C&C,spear-phishing, etc). 
          También implementa análisis de la muestra detectada en VirusTotal.
=============================================================================
"""

import requests              
import time                  
import os                    
import tldextract  #librería utilizada para extraer las secciones que componen una URL: subdominio, dominio primario y TLD    
import re                    
from pymisp import PyMISP, MISPEvent
import urllib3               
from dotenv import load_dotenv

# Desactivación de advertencias SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===========================================================================
# 1. SEGURIDAD OPERACIONAL (OPSEC)
# ===========================================================================
load_dotenv('/opt/.secrets.env')
MISP_URL = os.getenv('MISP_URL')
MISP_KEY = os.getenv('MISP_API_KEY')
VT_API_KEY = os.getenv('VT_API_KEY')

# Se establece un límite de certificados consultados para evitar bloqueos o saturación

MAX_DOMINIOS_POR_EMPRESA = 10 

def leer_empresas(ruta):
    """
    Lee el archivo de texto con las empresas a vigilar y las formatea a minúsculas
    """
    try:
        with open(ruta, 'r', encoding='utf-8') as f:
            return [line.strip().lower() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] Error: Directorio de activos no localizado en {ruta}")
        return []

# ===========================================================================
# 2. FUNCION DE VIRUSTOTAL
# ===========================================================================
def consultar_virustotal(domain):
    """
    Se utiliza el método GET para comprobar si ya existía la muestra en la BBDD
    de VirusTotal (VT) en vez del método POST, así se reduce la huella digital y las peticiones
    a la API limitada de VT
    """
    if not VT_API_KEY:
        return False, 0
        
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        req = requests.get(url, headers=headers, timeout=10)
        
        if req.status_code == 200:
            stats = req.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            maliciosos = stats.get('malicious', 0)
            # Se requieren al menos 2 positivos para catalogarlo como posible amenaza
            return maliciosos >= 2, maliciosos
            
        elif req.status_code == 429:
            print("        [-] Aviso: Cuota de peticiones (Rate Limit) de VirusTotal excedida.")
            
    except Exception as e:
        print(f"        [-] Excepción de red al comunicar con VirusTotal: {e}")
        
    return False, 0

# ===========================================================================
# 3. FUNCIÓN DE CONSULTA DE CERTIFICADOS (CRT.SH)
# ===========================================================================
def consultar_crtsh(keyword, retries=3):
    """
    Se consulta la BBDD de certificados de crt.sh.
    """
    print(f"[*] Escaneando Certificate Transparency (crt.sh) para: {keyword.upper()}")
    url = f"https://crt.sh/?q={keyword}&output=json"
    
    for intento in range(retries):
        try:
            # Se establece un User-Agent para evitar sistemas anti-bots
            req = requests.get(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}, timeout=45)
            if req.status_code == 200:
                try: 
                    return req.json()
                except ValueError: 
                    pass
            else:
                
                time.sleep(5) 
                continue 
                
        except Exception: 
           
            time.sleep(5)
            continue 
            
    return []


# ===========================================================================
# 4. FUNCIÓN PARA EVITAR DUPLICADOS
# ===========================================================================
def es_duplicado_atributo(misp, valor_dominio):
    """
    Consulta a la BBDD de MISP que el subdominio no exista previamente
    """
    try:
        resultado = misp.search(controller='attributes', type_attribute='domain', value=valor_dominio)
        if isinstance(resultado, dict) and 'Attribute' in resultado:
            return len(resultado.get('Attribute', [])) > 0
        elif isinstance(resultado, list) and len(resultado) > 0:
            return True
        return False
    except Exception as e:
        print(f"    [-] Excepción en comprobación de atributos MISP: {e}")
        return False

# ===========================================================================
# 5. LÓGICA DEL SCRIPT - LECTURA DE FICHEROS, APLICACIÓN DE CONDICIONES E INYECCIÓN
# ===========================================================================
def scraper_certificados():
    print("[*] Iniciando detección de subdominios potencialmente maliciosos... ")
    
    empresas = leer_empresas('/opt/empresas.txt')
    if not empresas: return

    try: 
        misp = PyMISP(MISP_URL, MISP_KEY, False)
    except Exception as e: 
        print(f"[-] Error crítico de conexión al clúster MISP: {e}")
        return

    for empresa in empresas:
        certificados = consultar_crtsh(empresa)
        
        if not certificados:
            time.sleep(2)
            continue

        dominios_descubiertos = {}
        
        for cert in certificados:
            #Se extrae el ID del certificado en crt.sh.
            cert_id = cert.get('id', 'N/A') 
            dominios = cert.get('name_value', '').split('\n')
            
            for dominio in dominios:
                # Se verifica que el subdominio no esté vacío
                if ' ' in dominio.strip(): continue
                
                dominio_limpio = re.sub(r'[^a-z0-9.-]', '', dominio.strip().lower().replace('*.', '').replace('*', '')).strip('.')
                if not dominio_limpio: continue
                
                # Divide la estructura FQDN para analizar la parte el subdominio
                extracted = tldextract.extract(dominio_limpio)
                subdominio = extracted.subdomain
                dominio_raiz = extracted.domain
                
                # Se establece la cadena (nombre de empresa) para su búsqueda literal
                patron = r'\b' + re.escape(empresa) + r'\b'
                
                # Los actores o grupos de amenazas, ante el alto grado de dificultad de registar un subdominio 
                # de un dominio existente (ej. grupo.iberia.es - > lícito) , optan por registrar un subdomino 
                # de un dominio controlado por ellos (grupo.iberia.ru.es -> potencialmente peligroso). 
                
                # La cadena con el nombre de la empresa, suele ubicarse en dicho apartado de subdominio.
                if re.search(patron, subdominio) and not re.search(patron, dominio_raiz):
                    if dominio_limpio not in dominios_descubiertos:
                        #Se vincula el subdominio detectado con su respectivo ID (ID_CER).
                        dominios_descubiertos[dominio_limpio] = cert_id 

        if not dominios_descubiertos:
            time.sleep(2)
            continue
            
        print(f"    [+] Parseo completado: {len(dominios_descubiertos)} dominios sospechosos para '{empresa.upper()}'.")

        # Comprobación en BBDD de MISP para evitar duplicados
        dominios_nuevos = []
        # Se extrae por cada subdominio el ID asociado
        for dom, cid in dominios_descubiertos.items(): #Se itera extrayendo clave (dominio) y valor (ID_CERT).
            if not es_duplicado_atributo(misp, dom):
                dominios_nuevos.append((dom, cid))
                if len(dominios_nuevos) >= MAX_DOMINIOS_POR_EMPRESA: break

        if dominios_nuevos:
            
            # Se analiza el primer dominio en VirusTotal para comprobar si la campaña estaba detectada 
            vt_warning = ""
            primer_dominio, primer_id = dominios_nuevos[0]
            print(f"    [*] Extrayendo reputación heurística (VT) de la muestra: {primer_dominio}")
            es_malicioso, score = consultar_virustotal(primer_dominio)
            
            if es_malicioso:
                print(f"    [!] 🛑 DETECCIÓN EN VT: {primer_dominio} ({score} motores de detección)")
                vt_warning = f" | VT DETECT: {primer_dominio} ({score}/90)"
                time.sleep(15) # 15 segundos de retardo operacional
            
            # Se agrupa la información de los dominios
            lista_ids = [str(cid) for _, cid in dominios_nuevos]
            # Se unifican todos los IDs para el título de la alerta
            ids_str = ", ".join(lista_ids)
            info_evento = f"Phishing | Suplantación de Marca (crt.sh) - {empresa.upper()} | ID_CERT: {ids_str}{vt_warning}"
            eventos_existentes = misp.search(controller='events', eventinfo=info_evento)
            
            try:
                # Si existía un evento con el mismo titular, se agregan los datos nuevos
                if eventos_existentes and isinstance(eventos_existentes, list) and len(eventos_existentes) > 0:
                    event_id = eventos_existentes[0]['Event']['id']
                else:
                    # Si es un evento nuevo, se crea desde cero
                    event = MISPEvent()
                    event.info = info_evento
                    event.date = time.strftime('%Y-%m-%d')
                    event.distribution = 0        
                    event.threat_level_id = 2     # Nivel Medio
                    event.analysis = 2            
                    
                    event.add_tag('Country:ES')
                    event.add_tag('Sector:Logistica')
                    event.add_tag('Type:Brand-Impersonation')
                    event.add_tag('Fuente:crt.sh')
                    if es_malicioso: event.add_tag('VT:Malicious') 
                    
                    res = misp.add_event(event)
                    event_id = res.id if hasattr(res, 'id') else res['Event']['id']

                # Por cada certificado encontrado, se agrega al evento su ID y su valor
                ingestados = 0
                for dom, cid in dominios_nuevos:
                    # Adición de atributos vinculados al ID del evento padre
                    attr_res = misp.add_attribute(event_id, {'type': 'domain', 'value': dom, 'comment': f"Infraestructura de Suplantación | ID_CERT: {cid}"})
                    
                    if not (isinstance(attr_res, dict) and ('errors' in attr_res or ('saved' in attr_res and not attr_res['saved']))):
                        ingestados += 1

                # Publicación del eventos en MISP
                if ingestados > 0:
                    misp.publish(event_id)
                    print(f"    [!] INGESTA COMPLETADA: {ingestados} nuevos dominios mapeados para {empresa.upper()}.")
                
            except Exception as ex:
                print(f"    [FATAL] Excepción de inyección en repositorio central: {ex}")
        else:
            print(f"    [-] Infraestructura de {empresa.upper()} ya documentada en el ciclo anterior.")

        # Pausa entre empresa y empresa
        time.sleep(2)

    print("\n[*] Análisis de certificados completado...")

if __name__ == '__main__':
    scraper_certificados()