#!/bin/bash

# Fichero que recoge los eventos generados en MISP y los ingesta como eventos en WAZUH

# Carga de credenciales seguras
source /opt/.secrets.env

LOG_FILE="/var/ossec/logs/misp_alerts.json"
CACHE_FILE="/opt/.misp_cache.txt"

# 1. Asegurar persistencia de cache
touch "$CACHE_FILE"

TAGS_TO_SEARCH='"Sector:Logistica&&Country:ES&&!Telegram-Enviado"'

echo "[*] Consultando a la API de MISP (Excluyendo eventos ya notificados)..."

RESPONSE=$(curl -s -k -X POST \
  -H "Authorization: $MISP_API_KEY" \
  -H "Accept: application/json" \
  -H "Content-type: application/json" \
  -d "{\"returnFormat\": \"json\", \"last\": \"1d\", \"tags\": $TAGS_TO_SEARCH}" \
  "$MISP_URL/events/restSearch")

# ==========================================
# VALIDACIÓN INTELIGENTE (FAIL SAFE)
# ==========================================
if [ -z "$RESPONSE" ]; then
    echo "[-] Error: No hay respuesta del servidor MISP."
    exit 1
fi

if ! echo "$RESPONSE" | jq -e '.response' > /dev/null 2>&1; then
    echo "[-] Error devuelto por la API de MISP. Detalles:"
    echo "$RESPONSE" | jq -r '.message // "Desconocido"'
    exit 1
fi

NUM_EVENTOS=$(echo "$RESPONSE" | jq '.response | length')

# Primer aviso si MISP no manda absolutamente nada
if [ "$NUM_EVENTOS" -eq 0 ]; then
    echo "[+] No se han encontrado nuevos eventos pendientes en MISP."
    exit 0
fi

echo "[*] MISP ha devuelto $NUM_EVENTOS eventos. Comprobando memoria caché local..."

# Variables para el resumen final
NUEVOS_INYECTADOS=0

# Usamos < <() en lugar de tubería para no perder el valor de la variable contador
while read -r event; do

    EVENT_ID=$(echo "$event" | jq -r '.Event.id')
    EVENT_INFO=$(echo "$event" | jq -r '.Event.info')
    
    # 2. Motor de Deduplicacion Local (Cache)
    if grep -q "^${EVENT_ID}$" "$CACHE_FILE"; then
        continue
    fi

    # Identificar el Scraper (Origen) basándonos en el título del evento
    ORIGEN="Desconocido"
    if [[ "$EVENT_INFO" == *"EuRepoC"* ]]; then ORIGEN="Inteligencia EuRepoC"
    elif [[ "$EVENT_INFO" == *"crt.sh"* ]]; then ORIGEN="crt.sh (Phishing)"
    elif [[ "$EVENT_INFO" == *"OTX Pulse"* ]]; then ORIGEN="OTX AlienVault"
    elif [[ "$EVENT_INFO" == *"Ransomware"* ]]; then ORIGEN="Ransomware.live"
    elif [[ "$EVENT_INFO" == *"Shodan:"* || "$EVENT_INFO" == *"EASM UPDATE:"* ]]; then ORIGEN="Shodan EASM"
    elif [[ "$EVENT_INFO" == *"Dark Web Leak"* ]]; then ORIGEN="Dark Web (.onion)"
    elif [[ "$EVENT_INFO" == *"Fuga de Informaci"* ]]; then ORIGEN="Multi-Paste Scraper"
    elif [[ "$EVENT_INFO" == *"OSINT Feed"* ]]; then ORIGEN="OSINT RSS"
    elif [[ "$EVENT_INFO" == *"Perfil Estrategico"* ]]; then ORIGEN="IncidentBuddy Profiler"
    else ORIGEN="MISP General"
    fi

    # 3. Preparar formato para Wazuh
    wazuh_line=$(echo "$event" | jq -c '{
        event_id: .Event.id,
        integration: "proactive-misp",
        misp_info: .Event.info,
        misp_date: .Event.date,
        misp_timestamp: .Event.timestamp,
        misp_url: (first(.Event.Attribute[]? | select(.type=="link" or .type=="url") | .value) // "Sin URL")
    }')

    # 4. Enviar a Wazuh
    echo "$wazuh_line" >> "$LOG_FILE"
    echo "$EVENT_ID" >> "$CACHE_FILE"
    
    # Mostrar por pantalla lo que se está inyectando
    echo "    [+] INYECTANDO ID: $EVENT_ID | Origen: $ORIGEN | Titulo: ${EVENT_INFO:0:45}..."

    # 5. MARCADO DE ESTADO: Etiquetar en MISP como "Telegram-Enviado"
    curl -s -k -X POST \
      -H "Authorization: $MISP_API_KEY" \
      -H "Accept: application/json" \
      -H "Content-type: application/json" \
      -d "{\"tags\": [\"Telegram-Enviado\"]}" \
      "$MISP_URL/tags/attachTagToObject/$EVENT_ID/event" > /dev/null

    NUEVOS_INYECTADOS=$((NUEVOS_INYECTADOS + 1))

done < <(echo "$RESPONSE" | jq -c '.response[]')

# ==========================================
# RESUMEN FINAL
# ==========================================
echo "--------------------------------------------------------"
if [ "$NUEVOS_INYECTADOS" -eq 0 ]; then
    echo "[+] Proceso finalizado. Los $NUM_EVENTOS eventos ya estaban en caché. 0 inyectados en Wazuh."
else
    echo "[+] Proceso finalizado con éxito. Se han inyectado $NUEVOS_INYECTADOS eventos NUEVOS en Wazuh."
fi

# Limpieza de cache para que no crezca indefinidamente (guardamos los ultimos 500)
tail -n 500 "$CACHE_FILE" > "${CACHE_FILE}.tmp" && mv "${CACHE_FILE}.tmp" "$CACHE_FILE"

exit 0
