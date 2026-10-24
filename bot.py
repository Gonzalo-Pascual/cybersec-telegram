"""CyberSec Telegram bot. Runs in GitHub Actions without paid services."""
import hashlib
import html
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import feedparser
import requests
from deep_translator import GoogleTranslator

TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '')
CHAT = os.getenv('TELEGRAM_CHAT_ID', '')
STATE = Path('state.json')
FEEDS = {
    'PHP oficial': 'https://www.php.net/feed.atom',
    'INCIBE CERT': 'https://www.incibe.es/incibe-cert/alerta-temprana/avisos/feed',
    'BleepingComputer': 'https://www.bleepingcomputer.com/feed/',
    'The Hacker News': 'https://feeds.feedburner.com/TheHackersNews',
}
KEV = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
WATCH = [s.strip().lower() for s in os.getenv('WATCH_KEYWORDS', 'php,linux,ubuntu,debian,apache,nginx,wordpress,docker,openssl,openssh,windows,postgresql,mysql,fortinet,cisco').split(',') if s.strip()]
KEY_TERMS = ('critical', 'critica', 'crítica', 'rce', 'remote code execution', 'ejecución remota', 'zero-day', '0-day', 'vulnerability', 'vulnerabilidad', 'security update', 'security release', 'exploit', 'ransomware', 'cve-')
CVE_PATTERN = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.I)
SESSION = requests.Session()
SESSION.headers.update({'User-Agent': 'CyberSecPersonalAlertBot/2.0 (GitHub Actions)'})


def send(text):
    if not TOKEN or not CHAT:
        raise RuntimeError('Configura TELEGRAM_BOT_TOKEN y TELEGRAM_CHAT_ID en GitHub Actions Secrets')
    resp = SESSION.post('https://api.telegram.org/bot' + TOKEN + '/sendMessage',
                        json={'chat_id': CHAT, 'text': text[:3900], 'disable_web_page_preview': True}, timeout=25)
    resp.raise_for_status()
    if not resp.json().get('ok'):
        raise RuntimeError('Error enviado mensaje Telegram')


def load():
    try:
        state = json.loads(STATE.read_text(encoding='utf-8'))
        if isinstance(state, dict):
            return state
    except (OSError, ValueError):
        pass
    return {'seen': {}, 'digest': [], 'last_digest': ''}


def normalize(text):
    return re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', html.unescape(text or ''))).strip()


def matches(text):
    value = text.lower()
    return [word for word in WATCH if re.search(r'(?<!\w)' + re.escape(word) + r'(?!\w)', value)]


def translate(text, limit=500):
    original = normalize(text)[:limit]
    if not original:
        return ''
    try:
        return GoogleTranslator(source='auto', target='es').translate(original) or original
    except Exception as exc:
        print('AVISO: traducción no disponible:', type(exc).__name__)
        return original + ' [texto original: traducción no disponible]'


def cvss_class(score):
    if score is None:
        return 'Sin CVSS disponible'
    if score >= 9:
        return 'CRÍTICA'
    if score >= 7:
        return 'ALTA'
    if score >= 4:
        return 'MEDIA'
    return 'BAJA'


def cvss_for(cve, cache):
    """NVD gives official metrics when published. Cache results; be gentle with keyless API."""
    if not cve:
        return None
    record = cache.get(cve)
    if record and time.time() - record.get('at', 0) < (86400 if record.get('score') is not None else 21600):
        return record.get('score')
    # Limit to 3 CVE lookups per run and space calls to respect NVD keyless limits.
    count = cvss_for.calls
    if count >= 3:
        return record.get('score') if record else None
    if count:
        time.sleep(7)
    cvss_for.calls += 1
    score = None
    try:
        response = SESSION.get('https://services.nvd.nist.gov/rest/json/cves/2.0', params={'cveId': cve}, timeout=18)
        response.raise_for_status()
        entries = response.json().get('vulnerabilities', [])
        if entries:
            metrics = entries[0].get('cve', {}).get('metrics', {})
            for version in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
                for metric in metrics.get(version, []):
                    candidate = metric.get('cvssData', {}).get('baseScore')
                    if candidate is not None:
                        score = float(candidate)
                        break
                if score is not None:
                    break
        cache[cve] = {'score': score, 'at': time.time()}
    except Exception as exc:
        print('AVISO: NVD no disponible:', cve, type(exc).__name__)
    return score
cvss_for.calls = 0


def short_item(source, title, url, summary='', score=None, exploited=False, cve='', watched=None):
    heading = '🔥 EXPLOTACIÓN CONFIRMADA (CISA KEV)' if exploited else ('🚨 VULNERABILIDAD CRÍTICA' if score is not None and score >= 9 else '⚠️ AVISO DE SEGURIDAD')
    score_line = f'CVSS: {score:g}/10 — {cvss_class(score)}' if score is not None else 'CVSS: No publicado o no disponible'
    product_line = ', '.join(watched or []) or 'Sin coincidencia en tu lista de tecnologías'
    return (f'{heading}\n\n{translate(title, 260)}\n\n'
            + (f'CVE: {cve}\n' if cve else '')
            + f'{score_line}\nTecnologías: {product_line}\nFuente: {source}\n'
            + (f'\n{translate(summary, 330)}\n' if summary else '')
            + f'\n🔗 {url}')


def daily_digest(digest, when):
    if not digest:
        return ''
    # Keep strongest and most recent items, and deduplicate headlines/URLs.
    ordered = sorted(digest, key=lambda x: (x.get('priority', 0), x.get('at', 0)), reverse=True)
    top, keys = [], set()
    for item in ordered:
        key = item.get('url') or item.get('id')
        if key in keys:
            continue
        keys.add(key)
        top.append(item)
        if len(top) == 8:
            break
    lines = [f'📰 RESUMEN DIARIO DE CIBERSEGURIDAD — {when:%d/%m/%Y}', '']
    for i, item in enumerate(top, 1):
        lines.append(f"{i}. {translate(item.get('title', 'Sin título'), 160)}")
        lines.append(f"   {item.get('source', 'Fuente')} · {item.get('url', '')}")
        lines.append('')
    return '\n'.join(lines)


def main():
    if '--test' in sys.argv:
        send('✅ CyberSec Bot v2: conexión con Telegram correcta.')
        if '--preview' in sys.argv:
            send(short_item('Simulación', 'Critical vulnerability in PHP (example, NOT a real advisory)',
                            'https://www.php.net/', 'Example preview of the new alert format.', 9.8, False, 'CVE-2026-00000', ['php']))
            send(daily_digest([{'title': 'Security news example for daily digest', 'source': 'Simulación',
                                'url': 'https://www.cisa.gov/', 'at': time.time(), 'priority': 1}], datetime.now(ZoneInfo('Europe/Madrid'))))
        return
    data = load()
    seen = data.setdefault('seen', {})
    digest = data.setdefault('digest', [])
    cache = data.setdefault('cvss_cache', {})
    first = not bool(seen)
    now = datetime.now(timezone.utc).timestamp()
    errors = []
    alerts = 0
    for source, url in FEEDS.items():
        try:
            result = SESSION.get(url, timeout=22)
            result.raise_for_status()
            feed = feedparser.parse(result.content)
            if feed.bozo and not feed.entries:
                raise ValueError(str(feed.bozo_exception))
            for item in feed.entries[:35]:
                title = normalize(item.get('title', 'Sin título'))
                link = item.get('link', '')
                identifier = hashlib.sha256((source + '|' + item.get('id', link or title)).encode()).hexdigest()
                if identifier in seen:
                    continue
                seen[identifier] = now
                if first:
                    continue
                summary = normalize(item.get('summary', ''))
                content = title + ' ' + summary
                watched = matches(content)
                cves = CVE_PATTERN.findall(content)
                cve = cves[0].upper() if cves else ''
                score = cvss_for(cve, cache) if cve and (watched or source in ('PHP oficial', 'INCIBE CERT')) else None
                is_critical = score is not None and score >= 9
                urgent = bool(watched and any(term in content.lower() for term in KEY_TERMS))
                official = source == 'PHP oficial' or source == 'INCIBE CERT' and (watched or is_critical)
                if is_critical or official or urgent and source in ('BleepingComputer', 'The Hacker News'):
                    send(short_item(source, title, link, summary, score, False, cve, watched))
                    alerts += 1
                if source in ('BleepingComputer', 'The Hacker News'):
                    digest.append({'id': identifier, 'title': title, 'source': source, 'url': link,
                                   'at': now, 'priority': 2 if watched else 1})
        except Exception as exc:
            errors.append(f'{source}: {type(exc).__name__}: {exc}')
    try:
        response = SESSION.get(KEV, timeout=35)
        response.raise_for_status()
        for item in response.json().get('vulnerabilities', []):
            cve = item.get('cveID', '')
            identifier = 'kev:' + cve
            if identifier in seen:
                continue
            seen[identifier] = now
            if first:
                continue
            product = (item.get('vendorProject', '') + ' ' + item.get('product', '')).strip()
            watched = matches(product + ' ' + item.get('vulnerabilityName', ''))
            # Always notify of newly confirmed exploitation; mark relevance explicitly.
            score = cvss_for(cve, cache) if watched else None
            title = cve + ' — ' + product + ' — ' + item.get('vulnerabilityName', '')
            send(short_item('CISA KEV', title, 'https://nvd.nist.gov/vuln/detail/' + cve,
                            item.get('shortDescription', ''), score, True, cve, watched))
            alerts += 1
    except Exception as exc:
        errors.append(f'CISA KEV: {type(exc).__name__}: {exc}')
    local = datetime.now(ZoneInfo('Europe/Madrid'))
    today = local.strftime('%Y-%m-%d')
    if local.hour >= 8 and data.get('last_digest', '') != today and not first:
        output = daily_digest(digest, local)
        if output:
            send(output)
            data['last_digest'] = today
            digest.clear()
    # Retain digest up to 2 days; cap state sizes to prevent uncontrolled growth.
    digest[:] = [x for x in digest if now - x.get('at', now) < 172800][-200:]
    if len(seen) > 12000:
        cutoff = sorted(seen, key=lambda k: seen[k])[-10000:]
        seen = data['seen'] = {k: seen[k] for k in cutoff}
    if len(cache) > 2000:
        cutoff = sorted(cache, key=lambda k: cache[k].get('at', 0))[-1500:]
        data['cvss_cache'] = {k: cache[k] for k in cutoff}
    STATE.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'Alertas enviadas: {alerts}; fuentes con errores: {len(errors)}; primer arranque: {first}')
    for error in errors:
        print('AVISO:', error)
    if errors and len(errors) == len(FEEDS) + 1:
        raise RuntimeError('Ninguna fuente respondió. Comprueba la conexión y los feeds.')


if __name__ == '__main__':
    main()
