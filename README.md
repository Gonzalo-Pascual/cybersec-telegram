# Bot gratuito de ciberseguridad: Telegram + GitHub Actions

1. Crea un bot con https://t.me/BotFather usando `/newbot`; copia el token (NO lo pegues en archivos del repositorio).
2. Escribe `/start` y luego `hola` al bot. Consulta `https://api.telegram.org/botTU_TOKEN/getUpdates` y copia `message.chat.id`.
3. Abre https://github.com/new y crea un repositorio **público** vacío llamado `cybersec-telegram` (sin README, sin gitignore).
4. Descomprime el ZIP en tu ordenador. En la página del repositorio entra en **Add file → Upload files** y arrastra `bot.py`, `requirements.txt`, `README.md` y `state.json`. Confirma el commit.
5. Para el archivo oculto `.github/workflows/alertas.yml`: en GitHub pulsa **Add file → Create new file**, introduce exactamente `.github/workflows/alertas.yml` como nombre, pega el contenido de ese archivo del ZIP y confirma el commit.
6. Ve a **Settings → Secrets and variables → Actions → New repository secret** y crea por separado `TELEGRAM_BOT_TOKEN` y `TELEGRAM_CHAT_ID` con sus valores. Nunca publiques el token.
7. Ve a **Actions → Alertas de ciberseguridad → Run workflow**, marca `test` y ejecuta. Comprueba el mensaje de prueba.
8. Ejecuta de nuevo **Run workflow** sin marcar `test`, para inicializar el historial de alertas. A continuación el cron lo comprobará aproximadamente cada 10 minutos.
9. En Android activa las notificaciones del bot dentro de Telegram y permite las notificaciones de Telegram en Ajustes del sistema.

## Configuración

- Frecuencia: `.github/workflows/alertas.yml`, valor `cron: '3/10 * * * *'` (aproximadamente cada 10 minutos, no tiempo real garantizado).
- Tecnologías: modifica `WATCH_KEYWORDS` en el YAML.
- Fuentes: modifica `FEEDS` y `KEV` en `bot.py`.
- Primer inicio: guarda referencias sin enviarlas para no inundar el chat.
- Estado de mensajes procesados: `state.json` (no contiene credenciales).
- Resumen de noticias: tras las 08:00 Europe/Madrid, en la primera ejecución disponible.

## Límites

GitHub Actions es gratis en repositorios públicos con runners estándar; el repositorio y el código serán públicos. Los tokens son secretos de GitHub, no visibles en el código. Los trabajos programados pueden retrasarse, saltarse y se desactivan después de 60 días sin actividad en repositorios públicos. No es un sistema de vigilancia garantizado 24/7. Revisa periódicamente la pestaña Actions. Algunas fuentes RSS pueden cambiar de dirección o bloquear solicitudes. Comprueba los logs de cada ejecución.
