#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
=============================================================================
MÓDULO DE INTELIGENCIA ESTRATÉGICA: EuRepoC
Este script parsea un archivo .xlsx descargado previamente de la plaforma 
hxxps://eurepoc[.]eu/table-view. Posteriormente filtra la búsqueda con las siguientes
condiciones

  - CONDICIÓN 1: (País Receptor == Spain/España) AND (Empresa Objetivo en empresas.txt)
  - CONDICIÓN 2: (Empresa ESTÁ en empresas.txt y aparece en el campo Nombre o Descripción)
  - FILTRO FINAL: Condición 1 OR Condición 2
=============================================================================
"""

import os
import re
import time
import openpyxl
from pymisp import PyMISP, MISPEvent
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv('/opt/.secrets.env')
MISP_URL = os.getenv('MISP_URL')
MISP_KEY = os.getenv('MISP_API_KEY')

DIRECTORIO_ACTUAL = os.path.dirname(os.path.abspath(__file__))
ARCHIVO_EXCEL = os.path.join(DIRECTORIO_ACTUAL, "eurepoc.xlsx") 

def cargar_empresas():
    empresas = []
    try:
        with open('/opt/empresas.txt', 'r', encoding='utf-8') as f:
            empresas = [line.strip().lower() for line in f if line.strip()]
    except: pass
    
    patrones = {emp: re.compile(rf"\b{re.escape(emp)}\b", re.IGNORECASE) for emp in list(set(empresas)) if emp}
    return empresas, patrones

#Se establece la función para comprobar más adelante si el evento existía previamente
def es_evento_duplicado(misp, info_texto):
    try:
        resultado = misp.search(controller='events', eventinfo=info_texto)
        return isinstance(resultado, list) and len(resultado) > 0
    except: return False

def limpiar_campo_basura(texto_bruto):
    t = str(texto_bruto).strip()
    t_low = t.lower()
    if not t or "not available" in t_low or "unknown" in t_low or "n/a" in t_low:
        return "N/A"
    return t

def analizar_eurepoc_excel():
    print(f"[*] Iniciando scraper EuRepoC de fichero local ...")
    if not os.path.exists(ARCHIVO_EXCEL):
        print(f"[-] Archivo no encontrado: {ARCHIVO_EXCEL}")
        return

    lista_empresas, patrones_empresas = cargar_empresas()
    if not lista_empresas:
        print("[-] Error: El diccionario de empresas está vacío o no existe.")
        return
    
    try: misp = PyMISP(MISP_URL, MISP_KEY, False)
    except: return

    alertas_generadas = 0
    
    try:
        wb = openpyxl.load_workbook(ARCHIVO_EXCEL, data_only=True)
        hoja = wb.active
        columnas = [str(celda.value).strip().lower() if celda.value else f"col_{i}" for i, celda in enumerate(hoja[1])]
        
        # Se buscan las columnas que contienen los campos necesarios en fichero Excel
        col_id = next((c for c in columnas if c == 'id'), 'id')
        col_name = next((c for c in columnas if 'name' in c and 'receiver' not in c and 'initiator' not in c), 'name')
        col_desc = next((c for c in columnas if 'desc' in c), 'description')
        col_date = next((c for c in columnas if 'date' in c and 'start' in c), 'start_date')
        col_country = next((c for c in columnas if 'country' in c and 'receiver' in c), 'receiver_country')
        col_rec_name = next((c for c in columnas if 'name' in c and 'receiver' in c), 'receiver_name')
        col_init_name = next((c for c in columnas if 'name' in c and 'initiator' in c), 'initiator_name')
        col_type = next((c for c in columnas if 'type' in c and 'incident' in c), 'incident_type')

        for row in hoja.iter_rows(min_row=2, values_only=True):
            fila = {columnas[i]: (str(celda).strip() if celda is not None else "") for i, celda in enumerate(row)}

            #Se extran los datos relevantes de cada fila para su posterior análisis
            id_evento = fila.get(col_id, 'N/A')
            pais_receptor = fila.get(col_country, '').lower()
            empresa_objetivo = fila.get(col_rec_name, '').lower()
            descripcion_raw = fila.get(col_desc, '')
            descripcion_lower = descripcion_raw.lower()
            nombre_incidente = fila.get(col_name, '').lower()

            es_pais_spain = any(kw in pais_receptor for kw in ['spain', 'españa', 'espana'])
            match_condicion_1 = False
            
            #Se verifica la condición 1 (Pais ES España y la empresa está en el listado)
            if es_pais_spain and empresa_objetivo:
                if any(emp in empresa_objetivo for emp in lista_empresas if emp):
                    match_condicion_1 = True

            texto_contexto = f"{nombre_incidente} {descripcion_lower}"
            match_condicion_2 = False
            empresas_detectadas = []
            for empresa, patron in patrones_empresas.items():
                
            #Se verifica la condición 2 (El nombre de la empresa aparece en el título o descripción)   
                if patron.search(texto_contexto):
                    match_condicion_2 = True
                    empresas_detectadas.append(empresa.upper())

            #Se debe de cumplir una de las dos condiciones indicadas
            if match_condicion_1 or match_condicion_2:
                grupo_clean = limpiar_campo_basura(fila.get(col_init_name, ''))
                
                if match_condicion_2 and empresas_detectadas:
                    empresa_clean = empresas_detectadas[0]
                else:
                    empresa_clean = limpiar_campo_basura(fila.get(col_rec_name, ''))
                    
                tipo_clean = limpiar_campo_basura(fila.get(col_type, ''))

                raw_date = fila.get(col_date, '')[:10]
                if len(raw_date) >= 10 and '-' in raw_date:
                    partes = raw_date.split('-')
                    fecha_incidente = f"{partes[2]}-{partes[1]}-{partes[0]}" if len(partes) == 3 else raw_date
                else:
                    fecha_incidente = "N/A"

                frases = descripcion_raw.split('.')
                detalle_breve = frases[0].strip() if frases and len(frases[0].strip()) > 10 else descripcion_raw[:120].strip()
                detalle_breve = limpiar_campo_basura(detalle_breve)
                if detalle_breve != "N/A" and not detalle_breve.endswith('.'): 
                    detalle_breve += '...'
                
                
                detalle_breve = f"ID {id_evento} - {detalle_breve}"

                info_evento = f"Inteligencia Geopolítica (EuRepoC) - {empresa_clean} | Actor: {grupo_clean} | Tipo: {tipo_clean} | Resumen: {detalle_breve}"

                #Se descarta el evento si ya existía, de lo contrario
                #se inyecta con las etiquetas y atributos correspondientes
                if es_evento_duplicado(misp, info_evento): 
                    continue

                event = MISPEvent()
                event.info = info_evento
                event.date = time.strftime('%Y-%m-%d') 
                event.distribution = 0
                event.threat_level_id = 2 
                event.analysis = 2
                event.published = True
                
                event.add_tag('Fuente:EuRepoC')
                event.add_tag('Country:ES') 
                event.add_tag('Sector:Logistica') 
                event.add_tag(f'Objetivo:{empresa_clean}')                
                event.add_attribute('threat-actor', grupo_clean, comment="Grupo Criminal")
                event.add_attribute('target-org', empresa_clean, comment="Entidad Atacada")
                event.add_attribute('comment', detalle_breve, comment="Detalle Breve")
                
                if fecha_incidente != "N/A": 
                    event.add_attribute('datetime', fecha_incidente, comment="Fecha del incidente (EuRepoC)")
                
                try:
                    misp.add_event(event)
                    print(f"    [+] ÉXITO: Inyectado match en MISP -> {empresa_clean} | Actor: {grupo_clean}")
                    alertas_generadas += 1
                except: pass
                        
    except Exception as e: 
        print(f"[-] Error en el procesamiento del libro Excel: {e}")

    print(f"[*] Proceso terminado. Nuevos eventos: {alertas_generadas}")

if __name__ == '__main__':
    analizar_eurepoc_excel()