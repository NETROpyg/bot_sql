
import os
import cloudscraper
from bs4 import BeautifulSoup
import requests
import re
import time
import webbrowser
from urllib.parse import urlparse, unquote
from colorama import init, Fore, Style
import base64
import hashlib

init(autoreset=True)

# بيانات البوت
TOKEN = "8126269492:AAElcXAV7eypooqyi0CKTOhFZoXKWNadeik"
CHAT_ID = "7530878932"
EXTS = [".html", ".htm", ".css", ".js", ".json", ".py", ".php", ".xml", ".txt", ".env", ".config", ".log"]

if TOKEN == "TOKEN Your own":
	print("يبدو انك لم تكتب توكن بوتك 🔰 | لن تصلك الملفات") 

if CHAT_ID == "7530878932":
	print("يبدو انك لم تكتب ID حسابك الذي سوف تستقبل الملفات اليه ♻️") 
def banner():
    print(Fore.MAGENTA + """
═══════════════════════════════════════════
  ⚔️ أداة @NETRO_GZ ⚔️
     تحليل 🔎 | كشف ثغرات 🧠 | فك تشفير 🔓
═══════════════════════════════════════════
""" + Style.RESET_ALL)


def animated(text):
    for c in text:
        print(c, end="", flush=True)
        time.sleep(0.01)
    print()


def save(name, content):
    with open(name, "w", encoding="utf-8") as f:
        f.write(content)


def send(file, site_name):
    if os.path.exists(file):
        caption = f"📡 *تقرير استخراج شامل من الموقع:* `{site_name}`\n📁 *الملف:* `{file}`\n🧠 *تطوير:* @NETRO_GZ"
        with open(file, "rb") as f:
            requests.post(f"https://api.telegram.org/bot{TOKEN}/sendDocument",
                          data={"chat_id": CHAT_ID, "caption": caption, "parse_mode": "Markdown"},
                          files={"document": f})


def send_message(msg):
    requests.post(f"https://api.telegram.org/bot{TOKEN}/sendMessage",
                  data={"chat_id": CHAT_ID, "text": msg, "parse_mode": "Markdown"})


def detect_vulns(html):
    vulns = []
    if "?id=" in html or "GET" in html:
        vulns.append("🔍 احتمال SQL Injection")
    if "eval(" in html or "document.write(" in html:
        vulns.append("💥 احتمال XSS")
    if "base64" in html:
        vulns.append("🧬 احتمال وجود بيانات مشفرة Base64")
    if "config" in html or "env" in html:
        vulns.append("🔧 ملفات إعدادات حساسة")
    return vulns


def decode_urls(urls):
    results = []
    for url in urls:
        try:
            decoded = unquote(url)
            results.append(f"🧩 `{decoded}`")
            if "base64" in url:
                raw = base64.b64decode(url.split("base64,")[-1])
                results.append(f"🔓 Base64: `{raw.decode('utf-8', errors='ignore')}`")
        except:
            continue
    return results


def extract_all(url):
    banner()
    animated("| تم التحميل  ♻️ \t جـاري الفحص انتظر 🔰")

    try:
        scraper = cloudscraper.create_scraper()
        res = scraper.get(url)
        html = res.text
        soup = BeautifulSoup(html, "html.parser")
        parsed = urlparse(url)
        domain = parsed.netloc.replace(".", "_")

        files = {}
        files['site_source.html'] = html
        files['page_text.txt'] = soup.get_text(separator="\n")
        files['all_links.txt'] = "\n".join(a['href'] for a in soup.find_all('a', href=True))
        files['emails_found.txt'] = "\n".join(set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", html)))
        files['images.txt'] = "\n".join(img['src'] for img in soup.find_all('img', src=True))
        files['js_files.txt'] = "\n".join(js['src'] for js in soup.find_all('script', src=True))
        files['css_files.txt'] = "\n".join(link['href'] for link in soup.find_all('link', rel='stylesheet') if 'href' in link.attrs)

        all_sources = [tag.get('src') for tag in soup.find_all(src=True)] + \
                      [tag.get('href') for tag in soup.find_all(href=True)]
        external = [i for i in all_sources if i and any(i.endswith(ext) for ext in EXTS)]
        files['external_files.txt'] = "\n".join(set(external))

        decoded_links = decode_urls(all_sources)
        files['decoded_links.txt'] = "\n".join(decoded_links)

        # كشف ثغرات
        vulns = detect_vulns(html)
        vuln_report = "\n".join(f"* {v}" for v in vulns) if vulns else "🔐 لا يوجد ثغرات معروفة"

        # إرسال تقرير
        report_msg = f"""
📡 *تم تحليل موقع جديد بواسطة NETRO* | @NETRO_GZ
```🛰 {parsed.netloc}```

*عدد الروابط:* {len(all_sources)}
*الإيميلات:* {len(files['emails_found.txt'].splitlines())}
*الثغرات المحتملة:*
{vuln_report}
        """
        send_message(report_msg)

        # حفظ + إرسال ملفات
        for filename, content in files.items():
            filepath = f"{domain}_{filename}"
            save(filepath, content)
            send(filepath, domain)

        try:
            webbrowser.open(url)
        except:
            pass

        animated("✅ تم الاستخراج الكامل والإرسال")

    except Exception as e:
        print(Fore.RED + f"\n[!] فشل التحليل: {str(e)}" + Style.RESET_ALL)
        send_message(f"❌ فشل تحليل الموقع `{url}`\n*السبب:* `{str(e)}`")


if __name__ == "__main__":
    target = input("\n🌍 أدخل رابط الموقع المراد تحليله:\n> ")
    extract_all(target)
    
