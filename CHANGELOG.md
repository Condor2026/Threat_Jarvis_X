# Changelog

Todas las modificaciones notables de **Threat Jarvis X** se documentan en este archivo.

El formato sigue [Keep a Changelog](https://keepachangelog.com/es/1.1.0/) y el proyecto
se adhiere a [Versionado Semántico](https://semver.org/lang/es/).

---

## [Unreleased]

### Por venir
- Documentación de capturas (`docs/`).
- Plantillas de issue adicionales (bug report, feature request).

---

## [2.0.0] — 2025-XX-XX

Primera versión pública. Reescritura completa del proyecto anterior, enfocada en un
único archivo (`Threat_Jarvis_X.py`) que se pueda leer de arriba a abajo.

### Añadido

- **Asistente de voz local**: STT con `faster-whisper`, LLM con `ollama`, TTS con
  `piper-tts` y respaldo `espeak-ng`. Todo en CPU, sin dependencias en la nube.
- **Cuatro personalidades** (`jarvis`, `ultron`, `osint`, `ops`) con prompt, voz, color
  y función propios. Interconsulta entre ellas sin cambiar la activa.
- **Inteligencia de amenazas pasiva**:
  - IOCs (IPv4 públicos, dominios, hashes MD5/SHA1/SHA256, URLs, CVEs).
  - Enriquecimiento concurrente con VirusTotal, AbuseIPDB y AlienVault OTX.
  - CVEs con NVD + EPSS + CISA KEV en una sola tarjeta.
  - MITRE ATT&CK (técnicas, grupos, malware, herramientas).
  - CISA KEV recientes.
  - Briefing de noticias de CISA, BleepingComputer, The Hacker News y Krebs.
  - Estado de servicios (Cloudflare, GitHub, Discord, OpenAI, Atlassian, Zoom).
  - SANS ISC INFOCON.
- **Gestor personal**: tareas, memoria y notas en lenguaje natural.
- **Archivos con permiso explícito**: listar, leer PDF/MD/TXT, buscar por nombre y por
  contenido, crear notas, borrar a papelera propia (`.jarvis_trash`).
- **Centinela**: vigilancia de fondo de **Nexus OSINT X** sin gastar LLM, con avisos
  persistentes y seguimiento de temas («vigila ransomware»).
- **Integración con Nexus OSINT X**: lectura de `/api/kpis`, `/api/analytics`,
  `/api/search` con resúmenes compactos para el contexto corto del LLM local.
- **API HTTP propia**: `POST /api/ask` y `POST /api/ioc` con cabecera `X-Token`.
- **Iframe embebible** en el panel de Nexus (`TJX_EMBED_ORIGINS`).
- **Interfaz web** en `http://127.0.0.1:8765/?t=<token>`: orbe de estado, chat por
  asistente, panel de resultados con medidores (CVSS, EPSS, VT, AbuseIPDB) e insignias
  (KEV, OTX), panel IOC manual, panel Archivos y panel Ajustes.
- **Cortes** con **Escape** o por voz («para», «silencio», «basta»).
- **Descarga reanudable** de voces Piper con `Range` y reintentos.

### Seguridad

- HTTP solo en `127.0.0.1`. No hay forma de exponerlo en red sin editar el código.
- Token fijo (modo `0600`) en `~/.threat_jarvis_x/token`.
- IPs privadas filtradas con `ipaddress.is_global` antes de salir a servicios externos.
- Carpetas protegidas (`.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`, `password-store`,
  `.threat_jarvis_x`, `.jarvis_trash`) excluidas incluso si autorizas una raíz amplia.
- `$HOME` no se permite como carpeta autorizada entera; solo subcarpetas.
- «Borra archivo» va a papelera propia, nunca a un `rm` de verdad.
- `defusedxml` para parsear RSS/Atom.
- El modelo base declina causar daño directo a terceros (está en el prompt).

### Notas

- Los datos del usuario viven en `~/.threat_jarvis_x/` (configurable con `TJX_HOME`).
- Modelo por defecto: `llama3.2`. Con poca RAM, `qwen2.5:3b`.
- `faster-whisper` en `base` para CPUs modestas; `small` en cuanto se pueda.

---

## [1.0.0] — anterior

Versión previa del proyecto, de uso interno. No publicada en GitHub.
