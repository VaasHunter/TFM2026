# Infraestructura CTI: MISP, Wazuh y Telegram  - AGENTE IA

El siguiente documento recoge el desarrollo y código utilizado de las siguientes herramientas:

* Una infraestructura orquestada y automatizada de recolección, filtrado, generación de inteligencia y alertado basada las plataformas MISP, Wazuh y Telegram
* Un agente desarrollado en Python que automatiza la traducción de informes de inteligencia de amenazas (CTI) en reglas de detección nativas para la plataforma Wazuh, extrayendo indicadores de compromiso (IoCs) y patrones desde documentos de texto o PDF, generando el código XML.

---

# Despliegue de Infraestructura CTI: MISP, Wazuh y Telegram

En este repositorio se encuentran los ficheros y scripts necesarios para desplegar una infraestructura de Inteligencia de Amenazas (CTI) basada en las siguientes plataformas:

* **MISP**: Plataforma open source de Inteligencia de Amenazas diseñada para la recolección, correlación y distribución estandarizada de eventos basados en Indicadores de Compromiso (IoCs).
* **WAZUH**: Plataforma unificada de seguridad *open-source* que combina capacidades de SIEM (Gestión de Eventos e Información de Seguridad) y XDR (Detección y Respuesta Extendidas).
* **Telegram**: Servicio de mensajería instantánea basado en la nube que opera sobre el protocolo criptográfico propietario cliente-servidor MTProto (con cifrado extremo a extremo en chats secretos).

---

## Flujo de Trabajo

El proceso, desde la recolección del dato en bruto hasta la alerta enviada a Telegram, es el siguiente:

1. **Recolección y Análisis**: Los diferentes scripts (*scrapers*) analizan, mediante el uso de patrones REGEX, diferentes fuentes de inteligencia en busca de cadenas contenidas en ficheros de texto (relacionadas con empresas, entidades público-privadas y terminología del sector logístico español). Estos scripts se ejecutan de forma periódica y automatizada usando *cronjobs*.
2. **Ingesta en MISP**: Si hay coincidencias, el *scraper* formatea el dato recogido para su correcta lectura por parte de MISP, lo etiqueta y lo ingesta en la plataforma.
3. **Procesamiento hacia WAZUH**: Mediante un *cronjob* en el servidor SIEM, se ejecuta un *script* en bash (`misp_ingestor.sh`) que consulta los nuevos eventos etiquetados en MISP, previene la duplicidad mediante una caché local y escribe el evento en un archivo de log local (`misp_alerts.json`).
4. **Inyección y Alerta**: WAZUH monitoriza este archivo JSON en tiempo real. Al detectar una nueva entrada, se evalúa el fichero de reglas (`local_rules.xml`) y dispara una regla personalizada de nivel crítico que invoca el módulo de integración, enviando la alerta formateada a Telegram.

---

## Tipos de Scrapers

Los *scrapers* se dividen en dos grupos principales alojados en la ruta `/opt/` de la plataforma MISP:

### 1. Scrapers Operativos
Su objetivo es encontrar inteligencia accionable basada en IoCs.

* **`ingestor_cert.py`** (Monitorización de subdominios con crt.sh): Monitoriza la emisión de certificados SSL/TLS en subdominios (*wildcards*) que contienen nombres comerciales del sector logístico. Permite detectar de forma temprana posibles infraestructuras de *phishing* o servidores C&C. El primer subdominio de cada empresa se contrasta contra VirusTotal (por restricciones de la API gratuita); si tiene históricos positivos en dos o más motores, se categoriza como malicioso.
* **`ingestor_shodan.py`** (Surface y Fugas mediante API de Shodan): Monitoriza la superficie de ataque externa (EASM). Detecta puertos críticos expuestos y alerta exclusivamente sobre vulnerabilidades confirmadas (CVEs), usando una función para evitar duplicidades.
* **`ingestor_paste.py`** (Sitios Paste): Utiliza técnicas de búsqueda avanzada (*Dorks*) para monitorizar repositorios de texto plano (Pastebin, ControlC y Rentry). Localiza fugas de información y credenciales analizando el HTML y las marcas de tiempo para descartar publicaciones obsoletas.
* **`ingestor_onion.py`** (Dark Web Tor/Onion): Rastrea foros clandestinos en la red Tor identificando posibles filtraciones de datos atribuidas a determinados actores ransomware.
* **`ingestor_otx.py`** (AlienVault OTX): Extrae informes de inteligencia (*pulses*) relativos a campañas de Ransomware, DDoS y Leaks, obteniendo IoCs de *networking* (IPs y dominios).
* **`ingestor_ransomware.py`** (Ransomware.live): Interactúa con APIs de seguimiento de grupos de Ransomware y genera alertas si una entidad logística española es publicada en esta plataforma.

### 2. Scrapers Tácticos y Estratégicos
Focalizados en tendencias, técnicas y análisis proactivo.

* **`ingestor_osint.py`**: Monitoriza canales RSS y *feeds* de diferentes fuentes, entidades y grupos de colaboración relacionados con ciberseguridad.
* **`ingestor_incidentbuddy.py`** (Inteligencia Estratégica y TTPs): Consolida las Tácticas, Técnicas y Procedimientos (TTPs) de los grupos y actores de amenazas, mapeándolos bajo el marco MITRE ATT&CK.
* **`ingestor_eurepoc.py`** (Consorcio EuRepoC): A partir de una base de datos local en `.xlsx` , previamente descargada de la plataforma Eurepoc aplicando los filtros correspondientes, extrae ,mediante patrones RegEx, diferentes campos como actores de amenazas (APTs), países de origen, tipología e IoCs. El uso de un archivo local en lugar de API responde a la negativa del consorcio Eurepoc a la petición de facilitar su API alegando que no facilitan dicha API a particulares o estudiantes.

---

## Listados Dinámicos

Para mejorar la eficiencia, optimizar recursos y facilitar el mantenimiento, los *scrapers* no utilizan *hardcoding* (términos embebidos en el código). En su lugar, leen la información desde los siguientes ficheros de texto plano:

* **`Empresas.txt`**: Listado  de las principales empresas privadas y entes públicos pertenecientes al sector logístico tanto con sede en España como empresas extranjeras con fuerte presencia en territorio español.
* **`Terminos.txt`**: Vocabulario específico del sector (español e inglés) en sus verticales terrestre, aérea y marítima.
* **`Actores.txt`**: Directorio de grupos APT y cibercriminales relacionados con el sector logístico.
* **`Amenazas.txt`**: Tipología de los vectores de ataque.
* **`Fuentes.txt`**: Repositorio de URLs de tipo OSINT.

---

## Integración, Orquestación y Respuesta

Esta infraestructura requiere un *Middleware* y configuraciones estandarizadas en WAZUH:

* **Conector y Gestor de Estado** (`/opt/misp_ingestor.sh`): Actúa como puente consultando la API de MISP para eventos recientes. Aplica doble validación (memoria caché y etiquetado API) para prevenir duplicados.
* **Script de Integración** (`/var/ossec/integrations/custom-telegram`): Invocado por `wazuh-integrator`. Normaliza y formatea los datos de la alerta para una visualización legible y accionable en Telegram.
* **Regla de Activación y Lectura de Logs**: En `/var/ossec/etc/ossec.conf` se habilita la monitorización continua (mediante la directiva  `<localfile>`) del archivo JSON generado por el middleware. Paralelamente, en `/var/ossec/etc/rules/local_rules.xml` se ha configurado una regla personalizada de criticidad máxima (Nivel 14) que reacciona ante cualquier nueva entrada en dicho log y dispara automáticamente el módulo de integración para el alertado.

---

## Seguridad Operacional (OPSEC) y Políticas de Retención

Adoptando los principios de *Security by Design* y *Least Privilege* (Mínimo Privilegio), se protege la información sensible de la infraestructura:

* **Gestión de Credenciales**: Las variables críticas (`MISP_URL`, `MISP_API_KEY`, `SHODAN_API`, `VT_API_KEY`, `TELEGRAM_TOKEN`, etc.) se alojan en archivos de entorno ocultos (`.env`).
* **Permisos Estrictos**: Estos ficheros poseen permisos `chmod 600` y `chown root:root`, garantizando que únicamente el sistema operativo tenga capacidad de lectura.
* **Plantillas en el repositorio**: los ficheros reales (`/opt/.secrets.env`) no se suben (`.gitignore`). Se incluye `.secrets.env.example` en `misp/opt/` y en `wazuh/plataformaCTI/opt/`; hay que copiarlo a `/opt/.secrets.env` en cada servidor y rellenarlo.
* **Dependencias**: los *scrapers* de MISP necesitan las librerías de `misp/opt/requirements.txt` (`pip install -r requirements.txt`).

Para sanitizar los sistemas, optimizar el rendimiento y prevenir la degradación de las bases de datos, el sistema de *Cronjobs* ejecuta dos **políticas de retención de datos**:

1. **Mantenimiento en Origen (MISP)**: Un script automatizado purga periódicamente los eventos históricos cuya vigencia supera los 30 días.
2. **Mantenimiento Local (SIEM)**: Se emplea el demonio `logrotate` (nativo de Linux) sobre el archivo de alertas (misp_alerts.json). Esto permite rotar, comprimir y purgar el histórico de forma automatizada sin interrumpir la lectura sobre ese fichero en WAZUH, garantizando un flujo continuo.



---
---
---


# Wazuh AI Rule Agent

Agente en Python que convierte informes de **inteligencia de amenazas (CTI)** en
**reglas de detección para Wazuh SIEM** de forma automática, usando el modelo
**Google Gemini**. A partir de un informe (PDF o texto), el agente extrae los
indicadores de compromiso (IOCs) y las técnicas (TTPs), genera las reglas en el
formato XML nativo de Wazuh, las valida y — tras la aprobación de un analista —
las despliega en el gestor a través de su API REST.

Desarrollado como parte de un Trabajo de Fin de Máster sobre la protección del
sector logístico frente a amenazas.

---

## ¿Qué hace?

El agente automatiza el proceso que tradicionalmente realiza un analista de forma
manual: leer el informe, extraer los indicadores, escribir las reglas y desplegarlas
en el SIEM. El flujo completo es:

1. **Análisis del informe (1 llamada a Gemini).** Clasifica el sistema operativo
   objetivo (Windows, Linux o genérico), genera una explicación técnica de la
   amenaza, produce una regla en formato **Sigma** y extrae los IOCs. La salida se
   garantiza mediante un esquema estructurado.
2. **Generación de reglas (1 llamada a Gemini).** Produce entre 2 y 4 reglas de
   detección en formato XML nativo de Wazuh, una por comportamiento o TTP.
3. **Validación local.** Un *linter* interno revisa las reglas y advierte de
   patrones que impedirían su activación (formatos de log inexistentes, indicadores
   neutralizados, descripciones imprecisas, etc.) — sin consumir llamadas al modelo.
4. **Aprobación humana.** El analista revisa las reglas y decide si las aprueba,
   corrige o rechaza. La IA propone; el analista decide.
5. **Despliegue seguro.** Sube la regla al gestor vía API REST, **valida la
   configuración antes de reiniciar** (con *rollback* automático si falla) y, tras
   el reinicio, **verifica que la regla ha quedado activa**.

### Arquitectura de validación (tres capas)

La fiabilidad se apoya en tres capas complementarias:

- **Prevención en el prompt** — instrucciones calibradas con formatos reales de log
  y ejemplos de patrones prohibidos.
- **Detección local automatizada** — el *linter* que inspecciona las reglas antes de
  la aprobación.
- **Decisión humana** — el punto de control final del analista.

---

## Requisitos

- Python 3.9 o superior
- Una clave de API de **Google Gemini** ([Google AI Studio](https://aistudio.google.com))
- Un despliegue de **Wazuh 4.x** con la API REST habilitada (probado en 4.13.1)
- Dependencias de Python (ver `requirements.txt`):
  - `google-genai`
  - `pypdf`
  - `python-dotenv`

---

## Instalación

```bash
# Clonar el repositorio
git clone https://github.com/VaasHunter/TFM2026.git
cd "TFM2026/wazuh/AGENTE IA"

# (Recomendado) crear un entorno virtual
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt
```

---

## Configuración

El agente lee sus credenciales de un fichero `.env` (que **no** se incluye en el
repositorio por seguridad). Copia la plantilla y rellénala con tus valores:

```bash
cp .env.example .env
```

Edita `.env` con tus datos:

```bash
GEMINI_API_KEY=tu_clave_de_gemini
GEMINI_MODEL=gemini-2.5-flash-lite
WAZUH_API_URL=https://TU_MANAGER:55000
WAZUH_API_USER=wazuh
WAZUH_API_PASS=tu_contraseña_de_wazuh
WAZUH_VERIFY_SSL=false
WAZUH_SSH_USER=tu_usuario
WAZUH_SSH_HOST=TU_MANAGER
```

| Variable | Descripción |
|----------|-------------|
| `GEMINI_API_KEY` | Clave de la API de Google Gemini (obligatoria). |
| `GEMINI_MODEL` | Modelo a usar. Por defecto `gemini-2.5-flash-lite`. |
| `WAZUH_API_URL` | URL de la API REST del gestor Wazuh (puerto 55000). |
| `WAZUH_API_USER` / `WAZUH_API_PASS` | Credenciales de la API de Wazuh. Si se dejan vacías, el agente genera las reglas pero no las sube automáticamente (muestra los comandos manuales). |
| `WAZUH_VERIFY_SSL` | Verificación del certificado TLS. `false` para entornos de laboratorio con certificados autofirmados. |
| `WAZUH_SSH_USER` / `WAZUH_SSH_HOST` | Usuario y host para los comandos de despliegue manual de respaldo. |

> **Nota de seguridad:** el fichero `.env` está excluido del repositorio mediante
> `.gitignore`. No lo subas nunca a un repositorio público.

---

## Uso

```bash
python3 agente.py
```

1. Coloca los informes CTI (PDF o `.txt`) en la carpeta `inputs/`.
2. Ejecuta el agente y selecciona el informe del menú.
3. Revisa las reglas generadas y los avisos del *linter*.
4. Aprueba (`s`) o rechaza (`n`). Si apruebas y las credenciales de la API de Wazuh
   están configuradas, el agente desplegará la regla automáticamente.

### Estructura de carpetas

El agente crea automáticamente las carpetas que necesita al ejecutarse:

- **`inputs/`** — coloca aquí los informes CTI de entrada (PDF o texto). El agente
  la crea si no existe.
- **`pending_review/`** — el agente guarda aquí las reglas generadas: un fichero
  `.xml` (para Wazuh) y un `.json` (con el análisis completo y la regla Sigma) por
  cada tanda.
- **`rules_repo.json`** — registro de las reglas generadas: identificadores, hash
  SHA-256 del informe (para detectar duplicados) e IOCs. Se genera y actualiza
  automáticamente.

Estas carpetas y ficheros de estado no se incluyen en el repositorio, ya que se
generan durante la ejecución.

---

## Ejemplo de flujo

Partiendo de un informe público de Microsoft sobre el malware **XorDDoS** (troyano
DDoS para Linux), el agente genera, entre otras, una regla que detecta la
modificación de `/etc/crontab` — una de las técnicas de persistencia descritas en el
informe — mediante la monitorización de integridad de ficheros (FIM) de Wazuh. La
regla puede probarse de forma segura, sin ejecutar malware real, reproduciendo el
artefacto que crea el malware:

```bash
# En el endpoint monitorizado por Wazuh:
echo "*/3 * * * * root /etc/cron.hourly/gcc.sh" | sudo tee -a /etc/crontab
```

La alerta aparece en el panel de Wazuh filtrando por el identificador de la regla
generada.

---

## Notas

- **Cuota de la API.** El nivel gratuito de Gemini está limitado en número de
  llamadas diarias. El agente usa dos llamadas por informe y reintenta
  automáticamente con espera exponencial ante indisponibilidad temporal del servicio
  (errores 503/429).
- **Dependencias del entorno de monitorización.** Las reglas solo se activan si el
  agente Wazuh monitoriza la fuente correspondiente: las reglas de integridad de
  ficheros (FIM) requieren que la ruta esté bajo `syscheck`, y las reglas de
  auditoría requieren que el endpoint tenga cargadas las reglas de `auditd`
  correspondientes.

---

## Licencia

Este proyecto se distribuye bajo la licencia MIT. Consulta el fichero `LICENSE`
para más detalles.

