import feedparser
import re
import sqlite3
import schedule
import time

# --- CONFIG ---

RSS_FEEDS = [
    "https://www.cisa.gov/news.xml",
    "https://www.us-cert.gov/ncas/alerts.xml",
    "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
    "https://blog.talosintelligence.com/rss/",
    "https://isc.sans.edu/rssfeed.xml",
    "https://feeds.feedburner.com/securityweek",
    "https://securelist.com/feed/",
    "https://www.bleepingcomputer.com/feed/",
    "https://threatpost.com/feed/"
    "https://krebsonsecurity.com/feed/",
    "https://thehackernews.com/feeds/posts/default",
    "https://thedfirreport.com/feed/",
    "https://www.malwarebytes.com/blog/feed",
    "https://unit42.paloaltonetworks.com/feed/",
    "https://research.checkpoint.com/feed/",
    "https://www.infosecurity-magazine.com/rss/news/",
    "https://medium.com/feed/mitre-attack",
    "https://garwarner.blogspot.com/feeds/posts/default"
]

DB_FILE = "threat_intel.db"

# --- DB SETUP ---

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS threat_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        link TEXT,
        published TEXT,
        summary TEXT,
        iocs TEXT
    )''')
    conn.commit()
    conn.close()

# --- RSS PARSER ---

def fetch_rss_entries(rss_url):
    feed = feedparser.parse(rss_url)
    entries = []
    for entry in feed.entries:
        entries.append({
            'title': entry.get('title', ''),
            'link': entry.get('link', ''),
            'published': entry.get('published', ''),
            'summary': entry.get('summary', '')
        })
    return entries

# --- IOC EXTRACTOR ---

def extract_iocs(text):
    return {
        'ips': re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text),
        'domains': re.findall(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', text),
        'hashes': re.findall(r'\b[a-fA-F0-9]{32,64}\b', text),
        'cves': re.findall(r'CVE-\d{4}-\d{4,7}', text)
    }

# --- STORE TO DB ---

def store_entry(entry, iocs):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM threat_data WHERE link = ?", (entry['link'],))
    if c.fetchone()[0] == 0:
        c.execute('''INSERT INTO threat_data (title, link, published, summary, iocs)
                     VALUES (?, ?, ?, ?, ?)''',
                  (entry['title'], entry['link'], entry['published'], entry['summary'], str(iocs)))
        print(f"[+] New threat: {entry['title']}")

    conn.commit()
    conn.close()

# --- JOB EXECUTION ---

def monitor_feeds():
    print("[*] Checking feeds...")
    for url in RSS_FEEDS:
        entries = fetch_rss_entries(url)
        for entry in entries:
            iocs = extract_iocs(entry['summary'])
            store_entry(entry, iocs)

def fetch_data():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT title, link, published, iocs, actor, detection, remediation FROM threat_data ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()

    data = []
    ioc_count = {'IP': 0, 'Domain': 0, 'Hash': 0, 'CVE': 0}

    for row in rows:
        title, link, published, iocs_str, actor, detection, remediation = row
        try:
            iocs = eval(iocs_str)
        except:
            iocs = {}

        ioc_count['IP'] += len(iocs.get('ips', []))
        ioc_count['Domain'] += len(iocs.get('domains', []))
        ioc_count['Hash'] += len(iocs.get('hashes', []))
        ioc_count['CVE'] += len(iocs.get('cves', []))

        data.append({
            'title': title,
            'link': link,
            'published': published,
            'iocs': iocs,
            'actor': actor,
            'detection': detection,
            'remediation': remediation
        })

    return data, ioc_count

# --- MAIN LOOP ---

if __name__ == "__main__":
    init_db()
    monitor_feeds()  # run once immediately
    schedule.every(60).minutes.do(monitor_feeds)

    print("[+] Threat Intel Monitor started.")
    while True:
        schedule.run_pending()
        time.sleep(10)
