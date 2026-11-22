# Política de seguridad

## Versiones soportadas

| Versión | Soporte |
|---------|---------|
| 2.x     | ✅      |
| 1.x     | ❌      |

## Cómo reportar una vulnerabilidad

**No abras un issue público.** Si encuentras un fallo de seguridad, escríbeme por
privado a través del perfil de GitHub ([@Condor2026](https://github.com/Condor2026))
o usa el botón **"Report a vulnerability"** de la pestaña *Security* del repo.

Incluye:

- Versión de Threat Jarvis X (commit o release).
- Sistema operativo y versión de Python.
- Pasos para reproducirlo.
- Impacto que crees que tiene.

Respondo en un plazo razonable (normalmente menos de 7 días). Si el fallo es grave,
publicaré un parche y un aviso en el `CHANGELOG.md` cuando esté resuelto.

## Modelo de seguridad del proyecto

Threat Jarvis X está pensado para correr **en local**, en el equipo del analista:

- Escucha **solo en `127.0.0.1`**, nunca en `0.0.0.0`.
- El token de la interfaz es fijo y vive en `~/.threat_jarvis_x/token` (modo `0600`).
- Las IPs privadas **no salen a internet**: `extract_iocs` filtra con
  `ipaddress.is_global` antes de consultar servicios externos.
- Carpetas protegidas (`.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`, `password-store`,
  `.threat_jarvis_x`, `.jarvis_trash`) quedan excluidas aunque autorices una raíz amplia.
- `$HOME` como carpeta autorizada entera **no se permite**: solo subcarpetas.
- «Borra archivo» va a una papelera propia (`.jarvis_trash`), nunca a un `rm` real.
- `defusedxml` para parsear RSS/Atom (evita XXE y bombas de entidades).

**No** está pensado para exponerse en red, ni detrás de un proxy, ni como servicio
público. Si haces eso, es tu responsabilidad.

## Alcance

Quedan **fuera** de esta política:

- Ataques que requieran acceso físico al equipo.
- Ataques de ingeniería social.
- Fallos en dependencias externas (repórtalos a upstream).
- Fallos en Ollama, Piper, Whisper o modelos de lenguaje.
