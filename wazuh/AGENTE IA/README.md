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
