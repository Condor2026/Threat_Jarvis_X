# Threat Jarvis X

> Asistente de voz local para Threat Intelligence y OSINT pasivo. Cuatro personalidades,
> cero telemetría, un solo archivo.

**Threat Jarvis X — Non-Commercial Share-Alike License** © 2026 [Condor](https://github.com/Condor2026).

Uso, copia y modificación gratis para uso no comercial. Nadie puede venderlo ni
ofrecerlo como servicio de pago. Si publicas una versión modificada, su código
fuente debe ser público y estar bajo esta misma licencia. Las modificaciones
privadas no obligan a publicar nada. Ver [`LICENSE`](LICENSE).

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Local-first](https://img.shields.io/badge/local--first-100%25-success.svg)](#)
[![Ollama](https://img.shields.io/badge/LLM-Ollama-black.svg)](https://ollama.com/)
[![License: Non-Commercial Share-Alike](https://img.shields.io/badge/License-NonCommercial%20ShareAlike-orange.svg)](LICENSE)
[![GitHub issues](https://img.shields.io/github/issues/Condor2026/Threat_Jarvis_X)](https://github.com/Condor2026/Threat_Jarvis_X/issues)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-✓-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Ollama](https://img.shields.io/badge/Ollama-000000?style=for-the-badge&logo=ollama&logoColor=white)
![Local-first](https://img.shields.io/badge/Local--first-100%25-success?style=for-the-badge)
![Offline](https://img.shields.io/badge/Offline-ready-brightgreen?style=for-the-badge)
![No telemetry](https://img.shields.io/badge/No-Telemetry-blue?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-FF0000?style=for-the-badge&logo=mitre&logoColor=white)
![CVE](https://img.shields.io/badge/CVE-✓-blue?style=for-the-badge)
![CISA KEV](https://img.shields.io/badge/CISA-KEV-red?style=for-the-badge)
![VirusTotal](https://img.shields.io/badge/VirusTotal-✓-394EFF?style=for-the-badge&logo=virustotal&logoColor=white)
![AbuseIPDB](https://img.shields.io/badge/AbuseIPDB-✓-yellow?style=for-the-badge)
![AlienVault OTX](https://img.shields.io/badge/AlienVault-OTX-00A6D6?style=for-the-badge&logo=alienvault&logoColor=white)
![Stars](https://img.shields.io/github/stars/Condor2026/Threat_Jarvis_X?style=social)
![License](https://img.shields.io/github/license/Condor2026/Threat_Jarvis_X?style=for-the-badge)

**Threat Jarvis X** (o simplemente **Jarvis**) es un asistente de voz que corre íntegramente
en tu máquina. Está pensado para analistas de Threat Intelligence y OSINT que quieran
consultar CVEs, IOCs, MITRE ATT&CK, noticias, el estado de servicios, o llevar sus tareas
y notas — todo por voz o por chat, sin mandar nada a la nube.

Jarvis es **el asistente que habla**, no un dashboard. Si tienes **Nexus OSINT X** arrancado
(centro de mando OSINT con su propia API local), Jarvis se conecta a él por HTTP y te resume
lo que ha pasado en las últimas horas, o te busca por tema. Si Nexus no está, Jarvis
funciona igual.

> ⚠️ No confundir con **J.A.R.V.I.S.** (el panel de datos). **Jarvis**, sin puntos, es este
> asistente de voz.

---

## Contenido

- [Características](#características)
- [Cómo se ve](#cómo-se-ve)
- [Instalación](#instalación)
- [Uso](#uso)
- [Las cuatro personalidades](#las-cuatro-personalidades)
- [Órdenes de voz](#órdenes-de-voz)
- [Integración con Nexus OSINT X](#integración-con-nexus-osint-x)
- [Centinela](#centinela)
- [API HTTP para integración](#api-http-para-integración)
- [Configuración](#configuración)
- [Privacidad y seguridad](#privacidad-y-seguridad)
- [Contribuir](#contribuir)
- [Licencia](#licencia)

---

## Características

### 🎙️ 100 % local, sin dependencias obligatorias en la nube

| Pieza        | Motor                                         | Alternativa           |
|--------------|-----------------------------------------------|-----------------------|
| **STT**      | `faster-whisper` (int8, CPU)                  | `openai-whisper`      |
| **LLM**      | `ollama` (llama3.2, qwen2.5, mistral…)        | —                     |
| **TTS**      | `piper-tts` (voces en español, HD)            | `espeak-ng` (metálica)|

Todo se ejecuta en tu máquina. El token de la interfaz web es fijo y se guarda en
`~/.threat_jarvis_x/token`.

### 🧠 Inteligencia de amenazas pasiva

- **IOCs** — IPs, dominios, hashes, URLs, CVEs. Enriquecidos con VirusTotal, AbuseIPDB y
  AlienVault OTX. Las IPs privadas se descartan: nunca salen a servicios externos.
- **CVEs** — NVD (CVSS + vector) + EPSS (probabilidad de explotación) + CISA KEV
  (explotada activamente en la naturaleza).
- **MITRE ATT&CK** — busca técnicas (T1059), grupos (APT29), malware (Cobalt Strike) o
  herramientas. Tácticas, alias y descripción.
- **CISA KEV recientes** — últimas 8 vulnerabilidades del catálogo de explotación activa.
- **Briefing de noticias** — CISA, BleepingComputer, The Hacker News, Krebs on Security.
- **Estado de servicios** — Cloudflare, GitHub, Discord, OpenAI, Atlassian, Zoom.
- **SANS ISC INFOCON** — nivel de amenaza global.

### 👥 Cuatro personalidades intercambiables

Cada una tiene su prompt, su voz, su color y su función. Se cambia diciendo
*«activa Ultron»* o *«pásate al analista»*. Pueden hablar entre ellas:
*«pregúntale al analista qué opina de esto»* y responde la voz correspondiente.

### 📋 Gestor personal

- **Tareas** — «añade tarea revisar CVE 2024 3400», «completa la tarea 3», «mis tareas pendientes».
- **Memoria** — «recuerda que prefiero respuestas cortas», «a partir de ahora llámame señor».
- **Notas** — «apunta que el C2 se movió a 185.220.101.4» → `notas.md`.
- **Archivos** (con permiso explícito) — «te doy acceso a documentos», «lista la carpeta descargas»,
  «lee el pdf informe_q1», «busca archivos que contengan 'ransomware'», «borra informe.pdf»
  (va a `.jarvis_trash`).

### 🛰️ Centinela (opcional)

Vigila **Nexus** de fondo cada ~2 minutos sin tocar el LLM: compara el nivel de amenaza
con su media de 24 h y te avisa cuando algo se sale de lo normal, o cuando un tema que
sigues empieza a moverse (p. ej. «vigila ransomware», «vigila Rusia»). Lo que ha pasado se
cuenta cuando lo pides: *«¿algún aviso del centinela?»*.

### 🔌 Integrable

- Endpoints propios `POST /api/ask` y `POST /api/ioc` con cabecera `X-Token`.
- Iframe embebible en el panel de Nexus (configura `TJX_EMBED_ORIGINS`).

---

## Cómo se ve

Una interfaz web mínima que se abre sola en `http://127.0.0.1:8765/?t=<token>`.

- Orbe de estado (idle / pensando).
- Chat con burbujas por asistente (cada uno con su color).
- Panel de **resultados** con tarjetas: IOCs, CVEs, ATT&CK, KEV, noticias, Nexus, carpetas.
  - **Medidores** para CVSS, EPSS, VT, AbuseIPDB.
  - **Insignias** para KEV, OTX, pulso.
- Panel **IOC** para análisis manual.
- Panel **Archivos** con carpetas autorizadas.
- Panel **Ajustes**: modelo Ollama, voces Piper, claves API, Centinela.
- **Escape** corta al asistente a media frase.

---

## Instalación

### Requisitos

- Linux (probado en Ubuntu / Debian).
- Python 3.10+.
- 8 GB de RAM mínimo. Con menos, elige un modelo pequeño (`qwen2.5:3b`) y `faster-whisper` en `base`.
- Opcional: `espeak-ng` como voz de respaldo, `poppler-utils` para leer PDFs.

### Pasos

```bash
# 1) Clonar
git clone https://github.com/Condor2026/Threat_Jarvis_X.git
cd Threat_Jarvis_X

# 2) Ollama (LLM local)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2
# (o cualquier otro: qwen2.5:3b, mistral, phi3…)

# 3) Dependencias del sistema
sudo apt install espeak-ng poppler-utils

# 4) Entorno Python
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 5) Arrancar
python Threat_Jarvis_X.py
```

Al arrancar se abre el navegador con el token ya en la URL. La primera vez descarga
el modelo de voz (Piper, ~60 MB) y, si hace falta, el de Whisper.

### Claves de API (opcionales)

Sin claves funciona, pero los IOCs saldrán en gris. Defínelas en tu `.env` o en el shell:

```bash
export VT_API_KEY="..."
export ABUSEIPDB_API_KEY="..."
export OTX_API_KEY="..."
export NVD_API_KEY="..."          # opcional, sube el rate-limit de NVD
```

Copia `.env.example` a `.env` para tenerlas todas en un sitio.

---

## Uso

1. Arranca `python Threat_Jarvis_X.py`.
2. Se abre `http://127.0.0.1:8765/?t=<token>` en el navegador.
3. Pulsa el botón de micrófono y habla. O escribe en el chat.
4. Por defecto **no** hace falta decir «Jarvis» al principio (desactivable en Ajustes).
5. Para cortarlo: **Escape**, o di *«para»*, *«silencio»*, *«basta»*.

El token es fijo y se guarda en `~/.threat_jarvis_x/token`, así que puedes guardar la URL
como marcador. Solo escucha en `127.0.0.1`: no es accesible desde la red.

---

## Las cuatro personalidades

| Personaje       | Rol                                    | Voz                  | Cuándo usarlo                                  |
|-----------------|----------------------------------------|----------------------|------------------------------------------------|
| **JARVIS**      | Mayordomo digital, sereno y elegante   | Claude (MX, HD)      | Día a día, tono general                        |
| **ULTRON**      | Intelecto frío y poético               | Claude + FX grave    | Cuando quieres respuestas teatrales            |
| **ANALISTA OSINT** | Metódico, cita fuentes, marca confianza | Dave (ES)        | Análisis serio de IOCs, CVEs, briefings        |
| **GESTOR**      | Tareas, notas, archivos                | Claude               | «Organiza mi día», «lee este PDF»              |

Cambio: *«activa Ultron»*, *«pásate al analista»*, *«modo gestor»*.

Interconsulta: *«pregúntale al analista qué opina de este hash»* →
la respuesta sale con la voz del analista sin cambiar el asistente activo.

---

## Órdenes de voz

Algunos ejemplos reales (no hace falta memorizar nada, Jarvis entiende variantes):

### Inteligencia

- «Analiza 8.8.8.8, ejemplo.com y el hash 44d88612…»
- «CVE 2024 3400» / «CVE-2024-3400»
- «Busca la técnica T1059» / «qué es APT29» / «háblame de Cobalt Strike»
- «Últimas KEV» / «qué se está explotando»
- «Radar» / «panorama» / «qué está pasando»
- «Estado de servicios» / «¿está caído GitHub?»
- «Briefing» / «noticias» / «titulares»
- «Lee el portapapeles»

### Nexus OSINT X (si está arrancado)

- «Resumen de Nexus» / «qué pasa en Nexus»
- «Últimas 6 horas en Nexus»
- «Qué pasa en Rusia» / «novedades sobre ransomware»
- «Nexus sobre APT29»

### Tareas y notas

- «Añade tarea revisar logs del firewall»
- «Completa la tarea 3» / «borra la tarea de parchear»
- «Mis tareas pendientes»
- «Recuerda que prefiero respuestas cortas»
- «Apunta que el C2 se movió a 185.220.101.4»

### Archivos (con permiso previo)

- «Te doy acceso a documentos»
- «Lista la carpeta descargas»
- «Lee el pdf informe_q1»
- «Resume el archivo notas.md»
- «Busca archivos que contengan 'ransomware'»
- «Borra informe.pdf»

### Centinela

- «Vigila ransomware» / «vigila Rusia»
- «Qué vigilas»
- «Deja de vigilar Rusia»
- «¿Algún aviso del centinela?» / «¿qué ha pasado mientras no estaba?»

---

## Integración con Nexus OSINT X

Nexus es el **centro de mando OSINT** con el que Jarvis se comunica. Jarvis **no** es Nexus
y **no** lo necesita para funcionar: si Nexus no está, Jarvis sigue consultando NVD, VT,
MITRE y compañía.

Si tienes Nexus arrancado en `http://127.0.0.1:8000` (o el que sea):

```bash
export NEXUS_URL="http://127.0.0.1:8000"
```

Jarvis leerá su API (`/api/kpis`, `/api/analytics`, `/api/search`) para darte un resumen
compacto en lenguaje natural. El Centinela usará esa misma API para avisarte sin gastar
LLM.

### API propia de Jarvis (para que Nexus le pregunte)

Si Nexus quiere usar a Jarvis como backend de voz/OSINT:

```bash
curl -X POST http://127.0.0.1:8765/api/ask \
  -H "X-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"text": "analiza 8.8.8.8", "persona": "osint"}'
# -> {"reply": "..."}

curl -X POST http://127.0.0.1:8765/api/ioc \
  -H "X-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"text": "8.8.8.8 1.1.1.1 44d88612…"}'
# -> {"items": [ ... ]}
```

### Iframe en el panel de Nexus

```bash
export TJX_EMBED_ORIGINS="http://127.0.0.1:*,http://localhost:*"
```

Permite que Nexus incruste Jarvis con `<iframe src="http://127.0.0.1:8765/?t=<token>">`.

---

## Centinela

Vigilancia de fondo **sin LLM**: cada ~2 minutos (configurable) consulta Nexus y compara
el nivel de amenaza con su mediana de las últimas 24 h. Avisa cuando:

- El índice de amenaza supera la media por encima de un umbral (≈3σ, mínimo 15 puntos).
- Aparecen eventos nuevos de nivel `CRITICA` o `ALTA` de fuentes que no están en la
  rutina (Domain, Cloud, Geo, Cyber, Range…).
- Un tema de tu lista de seguimiento muestra un pico (2× la media o ≥8 eventos nuevos).

Los avisos se guardan (no se pierden si cierras el navegador) y se pueden reproducir:

- «¿Algún aviso del centinela?»
- «¿Qué ha pasado mientras no estaba?»

Configuración:

- `TJX_SENTINEL=0` lo apaga.
- `TJX_SENTINEL_SECS=300` cambia el ritmo (mínimo 30 s).

Estado persistido en `~/.threat_jarvis_x/sentinel.json`.

---

## API HTTP para integración

| Endpoint      | Método | Cabecera         | Body                                  | Respuesta       |
|---------------|--------|------------------|---------------------------------------|-----------------|
| `/api/ask`    | POST   | `X-Token: <token>` | `{"text": "...", "persona": "osint"}` | `{"reply": "..."}` |
| `/api/ioc`    | POST   | `X-Token: <token>` | `{"text": "ips, hashes, dominios..."}` | `{"items": [...]}` |

`persona` ∈ `jarvis | ultron | osint | ops`. Por defecto: la activa en el momento.

Solo escucha en `127.0.0.1`. El token está en `~/.threat_jarvis_x/token`.

---

## Configuración

Variables de entorno (todas opcionales, con valores por defecto sensatos):

| Variable             | Por defecto                     | Para qué                                           |
|----------------------|---------------------------------|----------------------------------------------------|
| `TJX_MODEL`          | `llama3.2`                      | Modelo de Ollama.                                  |
| `TJX_HISTORY`        | `10`                            | Mensajes de historial que se mandan al LLM.        |
| `TJX_KEEP_ALIVE`     | `30m`                           | Cuánto mantener el modelo en RAM.                  |
| `TJX_HOME`           | `~/.threat_jarvis_x`            | Carpeta de datos (chats, reportes, voces, token).  |
| `TJX_SENTINEL`       | `1`                             | `0` apaga el Centinela.                            |
| `TJX_SENTINEL_SECS`  | `120`                           | Ritmo del Centinela (mínimo 30 s).                 |
| `TJX_EMBED_ORIGINS`  | `http://127.0.0.1:*,http://localhost:*` | Orígenes con permiso para iframe.         |
| `NEXUS_URL`          | `http://127.0.0.1:8000`         | API de Nexus OSINT X.                              |
| `VT_API_KEY`         | —                               | VirusTotal.                                        |
| `ABUSEIPDB_API_KEY`  | —                               | AbuseIPDB.                                         |
| `OTX_API_KEY`        | —                               | AlienVault OTX.                                    |
| `NVD_API_KEY`        | —                               | Sube el rate-limit de NVD.                         |

Ver `.env.example`.

---

## Privacidad y seguridad

- **Nada sale de tu máquina** salvo las consultas explícitas que tú pides (VT, AbuseIPDB,
  OTX, NVD, CISA, MITRE, feeds RSS) y solo cuando hay clave / se ejecuta la orden.
- **Las IPs privadas** (10/8, 172.16/12, 192.168/16, 127/8, link-local) **nunca** se envían
  a servicios externos: `extract_iocs` las filtra con `ipaddress.is_global`.
- **HTTP solo en `127.0.0.1`**. No hay forma de exponerlo en red sin editar el código.
- **Token fijo** en `~/.threat_jarvis_x/token` (modo 0600). Sirve para que solo tú abras la UI.
- **Carpetas protegidas**: `.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`, `password-store`, etc.
  quedan excluidas incluso si autorizas `$HOME` (que además no se permite entero).
- **Papelera propia** (`.jarvis_trash` en la raíz autorizada) para «borra archivo»: nunca
  un `rm` de verdad.
- **Nada de intrusiones**: Jarvis solo consulta fuentes públicas. Si le pides atacar algo,
  declina en una frase (está en el prompt base).

---

## Contribuir

Cualquier ayuda es bienvenida. Antes de abrir un PR:

1. Abre un **issue** para comentar el cambio, sobre todo si toca el core (`route_intent`,
   `extract_iocs`, Centinela, prompts de personalidad).
2. Ejecuta el script en local con un modelo pequeño (`qwen2.5:3b`) para que el PR se pueda
   probar con pocos recursos.
3. Si tu PR añade una orden nueva, añádela también al bloque de [Órdenes de voz](#órdenes-de-voz).

Reporta falsos positivos del Centinela o problemas con un proveedor de IOCs usando la
[plantilla de issue](https://github.com/Condor2026/Threat_Jarvis_X/issues/new).

---

## Licencia

MIT © 2025 [Condor](https://github.com/Condor2026). Ver [`LICENSE`](LICENSE).

---

> Hecho para analistas que prefieren hablarle a su máquina antes que a un SaaS.
>
> — [Condor](https://github.com/Condor2026)
