import os, json, sys, time, hashlib, html
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from pathlib import Path
import requests, feedparser

TOKEN=os.environ.get('TELEGRAM_BOT_TOKEN','')
CHAT=os.environ.get('TELEGRAM_CHAT_ID','')
STATE=Path('state.json')
FEEDS={
 'PHP oficial':'https://www.php.net/feed.atom',
 'INCIBE CERT':'https://www.incibe.es/incibe-cert/alerta-temprana/avisos/feed',
 'BleepingComputer':'https://www.bleepingcomputer.com/feed/',
 'The Hacker News':'https://feeds.feedburner.com/TheHackersNews',
}
KEV='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
KEYWORDS=[x.strip().lower() for x in os.environ.get('WATCH_KEYWORDS','php,linux,apache,nginx,wordpress,docker,openssl,openssh,windows').split(',') if x.strip()]
URGENT=('critical','critica','crítica','rce','zero-day','0-day','actively exploited','explotación activa','remote code execution','ejecución remota','security release','security update')

def send(msg):
    if not TOKEN or not CHAT: raise RuntimeError('Faltan TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID en los secrets')
    r=requests.post('https://api.telegram.org/bot'+TOKEN+'/sendMessage',json={'chat_id':CHAT,'text':msg[:4000], 'disable_web_page_preview':True},timeout=25)
    r.raise_for_status()
    if not r.json().get('ok'): raise RuntimeError('Telegram rechazó el mensaje')

def load():
    try: return json.loads(STATE.read_text(encoding='utf8'))
    except (OSError,ValueError): return {'seen':{},'digest':[],'last_digest':''}

def main():
    if '--test' in sys.argv:
        send('✅ CyberSec Bot: Telegram está conectado. Prueba correcta.');return
    data=load();seen=data.setdefault('seen',{});digest=data.setdefault('digest',[])
    first=not bool(seen); now=datetime.now(timezone.utc).timestamp()
    errors=[]; fresh=0
    # Check only recent entries at first run to avoid a flood of historical alerts.
    for source,url in FEEDS.items():
        try:
            resp=requests.get(url,timeout=22,headers={'User-Agent':'CyberSecPersonalAlertBot/1.0'})
            resp.raise_for_status()
            parsed=feedparser.parse(resp.content)
            if not parsed.entries and parsed.bozo: raise RuntimeError(str(parsed.bozo_exception))
            for item in parsed.entries[:35]:
                title=item.get('title','Sin título').strip(); link=item.get('link','')
                ident=hashlib.sha256((source+'|'+item.get('id',link or title)).encode()).hexdigest()
                if ident in seen: continue
                seen[ident]=now
                if first: continue
                description=html.unescape(item.get('summary',''))
                text=(title+' '+description).lower()
                watched=any(w in text for w in KEYWORDS)
                urgent=any(w in text for w in URGENT)
                if source=='PHP oficial' or (source=='INCIBE CERT' and (watched or urgent)):
                    send('🚨 ALERTA | '+source+'\n'+title+'\n'+link);fresh+=1
                elif source in ('BleepingComputer','The Hacker News'):
                    digest.append({'id':ident,'title':title,'source':source,'url':link,'at':now})
        except Exception as e: errors.append(f'{source}: {type(e).__name__} {e}')
    try:
        resp=requests.get(KEV,timeout=30,headers={'User-Agent':'CyberSecPersonalAlertBot/1.0'});resp.raise_for_status()
        for item in resp.json().get('vulnerabilities',[]):
            cve=item.get('cveID',''); ident='kev:'+cve
            if ident in seen:continue
            seen[ident]=now
            if first:continue
            product=item.get('vendorProject','')+' '+item.get('product','')
            send('🚨 CISA KEV | Explotación conocida\n'+cve+' — '+product+'\n'+item.get('vulnerabilityName','')+'\nhttps://www.cisa.gov/known-exploited-vulnerabilities-catalog');fresh+=1
    except Exception as e:errors.append(f'CISA KEV: {type(e).__name__} {e}')
    local=datetime.now(ZoneInfo('Europe/Madrid'))
    day=local.date().isoformat()
    if not first and local.hour>=8 and data.get('last_digest')!=day:
        news=digest[-12:]
        if news:
            lines=['📰 RESUMEN DE CIBERSEGURIDAD — '+day]
            for n in news: lines.append('• '+n['title']+' ('+n['source']+')\n'+n['url'])
            send('\n\n'.join(lines)[:4000])
        data['last_digest']=day
        digest.clear()
    # Bound file size; keep 40 days of dedup history.
    data['seen']={k:v for k,v in seen.items() if now-v < 40*86400}
    data['digest']=digest[-80:]
    STATE.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    if errors:
        print('Advertencia: fuentes no disponibles: '+'; '.join(errors),file=sys.stderr)
        # Do not fail the workflow: persist successful checks and try again next time.
    print(f'OK; avisos enviados: {fresh}; noticias pendientes: {len(data["digest"])}; fuentes fallidas: {len(errors)}')

if __name__=='__main__': main()
