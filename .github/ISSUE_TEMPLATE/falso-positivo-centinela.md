---
name: Falso positivo del Centinela
about: El Centinela avisó de algo que no era para tanto (o de nada)
title: "[Centinela] Falso positivo: "
labels: centinela, falso-positivo
assignees: Condor2026
---

## Qué avisó el Centinela

Copia el aviso tal cual apareció en el chat:

```
<Pega aquí el texto del aviso>
```

## Qué esperabas

¿Qué debería haber hecho el Centinela en su lugar? (no avisar, agrupar mejor, subir el
umbral, ignorar esa fuente…)

## Cuándo ocurrió

- Fecha y hora aproximada:
- Zona horaria:
- ¿Cuánto tiempo llevaba corriendo Jarvis sin reiniciar?

## Estado de Nexus en ese momento

- ¿Nexus estaba arrancado? Sí / No
- Versión de Nexus OSINT X (si la sabes):
- ¿Había algún pico real esos minutos? (según el panel de Nexus)

## Configuración del Centinela

Pega el resultado de:

```bash
echo "TJX_SENTINEL=$TJX_SENTINEL"
echo "TJX_SENTINEL_SECS=$TJX_SENTINEL_SECS"
echo "NEXUS_URL=$NEXUS_URL"
```

Y si puedes, adjunta `~/.threat_jarvis_x/sentinel.json` (revisa que no tenga datos
sensibles antes).

## Temas que tenías en vigilancia

- [ ] ransomware
- [ ] <otro tema>
- [ ] Ninguno

## Notas adicionales

Cualquier detalle que ayude a reproducirlo (hora del día, eventos concurrentes en el
equipo, si el aviso llegó por voz o solo al abrir el chat, etc.).
