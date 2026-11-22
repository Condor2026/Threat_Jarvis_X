# Contribuir a Threat Jarvis X

Gracias por querer ayudar. Antes de abrir un PR, lee esto.

## Reglas

1. **Abre un issue primero** si vas a tocar el núcleo (`route_intent`, `extract_iocs`,
   Centinela, prompts de personalidad) o si el cambio es grande. Así hablamos antes de
   que te pongas a escribir código.
2. **Un PR, un tema.** No mezcles refactor con feature con fix de estilo.
3. **El código va en un único archivo** (`Threat_Jarvis_X.py`). No lo dividas en módulos.
   Es una decisión de diseño del proyecto: quien lo descarga tiene que poder leerlo
   entero en una tarde.
4. **Compatible con Python 3.10+**. Nada de `match` con guards modernos ni features raras.
5. **Dependencias opcionales, no obligatorias.** Todo lo que añadas se tiene que degradar
   con gracia si la librería no está instalada.
6. **Nada de telemetría, analytics ni llamadas a casa.**
7. **Nada de intrusiones activas.** Este proyecto es OSINT pasivo: solo fuentes públicas.

## Cómo probar

- Modelo pequeño (`qwen2.5:3b`) para que se pueda ejecutar con poca RAM.
- Sin claves API también tiene que arrancar (los IOCs saldrán en gris).
- Sin Nexus también tiene que arrancar (el Centinela se queda en silencio).
- Sin `faster-whisper` también tiene que arrancar (sin micrófono, pero chat funciona).

## Estilo

- 4 espacios, sin tabs.
- Líneas de hasta 120 caracteres.
- Nombres de funciones en `snake_case`, constantes en `MAYÚSCULAS`.
- Los prompts de personalidad van en español.
- Los comentarios, en español.

## Licencia

Al enviar un PR aceptas que tu contribución se publique bajo la misma
**Non-Commercial Share-Alike License** del proyecto (ver [`LICENSE`](LICENSE)).
No se aceptan contribuciones que obliguen a relicenciar el proyecto bajo MIT, GPL,
o cualquier otra licencia.
