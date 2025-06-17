from flask import Flask, render_template, request
import feedparser
import re
import email.utils
from datetime import datetime
from dateutil.parser import parse as parse_date
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)

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

# Cached threat data and timestamp
cached_entries = []
cached_total_threats = 0
cached_ioc_count = 0
cached_latest_date = "N/A"
last_checked = "Not yet run"

# === Utility Functions ===

def extract_iocs(text):
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    domains = re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', text)
    return list(set(ips + domains))

def get_entry_date(entry):
    for key in ["published", "updated", "created"]:
        if key in entry:
            try:
                dt = parse_date(entry[key])
                return dt.replace(tzinfo=None)
            except Exception:
                continue
    return None

def extract_actor(text):
    keywords = ["APT", "Lazarus", "TA505", "Cobalt", "FIN7", "Fancy Bear", "Anonymous", "Conti", "LockBit"]
    for word in keywords:
        if word.lower() in text.lower():
            return word
    return "Unknown"

def extract_detection(text):
    if "detected" in text.lower() or "mitre" in text.lower() or "ioc" in text.lower():
        return "Detection technique mentioned"
    return "TBD"

def extract_remediation(text):
    if "patch" in text.lower() or "update" in text.lower() or "mitigation" in text.lower():
        return "Patch or mitigation advised"
    return "TBD"

# === Scheduled Feed Monitoring Job ===

def monitor_feeds():
    global cached_entries, cached_total_threats, cached_ioc_count, cached_latest_date, last_checked

    print(f"[{datetime.now()}] 🔄 Background feed monitoring run")
    entries = []

    for feed_url in RSS_FEEDS:
        feed = feedparser.parse(feed_url)
        for entry in feed.entries:
            title = entry.get("title", "")
            summary = entry.get("summary", "")
            content = f"{title} {summary}"
            iocs = extract_iocs(content)
            parsed_date = get_entry_date(entry)

 
            try:
                published = email.utils.parsedate_to_datetime(entry.get("published", "")).strftime("%d %b %Y, %I:%M %p")
            except Exception:
                published = entry.get("published", "") or "N/A"

            entries.append({
                "title": title,
                "summary": summary,
                "link": entry.get("link", "#"),
                "published": published,
                "parsed_date": parsed_date,
                "iocs": iocs,
                "ioc_count": len(iocs),
                "actor": extract_actor(summary),
                "detection": extract_detection(summary),
                "remediation": extract_remediation(summary)
            })
    entries.sort(key=lambda e: e["parsed_date"], reverse=True)
    
    # Cache the data
    cached_entries = entries
    cached_total_threats = len(entries)
    cached_ioc_count = sum(e["ioc_count"] for e in entries)
    valid_dates = [e["parsed_date"] for e in entries if e["parsed_date"]]
    cached_latest_date = max(valid_dates).strftime("%d %b %Y") if valid_dates else "N/A"
    last_checked = datetime.now().strftime("%d %b %Y, %I:%M %p")

# === Flask Dashboard Route ===

@app.route('/')
def dashboard():
    query = request.args.get("q", "").lower()
    filtered = [e for e in cached_entries if query in (e["summary"] + e["title"]).lower()] if query else cached_entries

    return render_template("dashboard.html",
                           entries=filtered,
                           total_threats=len(filtered),
                           ioc_count=sum(e["ioc_count"] for e in filtered),
                           latest_date=cached_latest_date,
                           last_checked=last_checked,
                           query=query)

# === Start Scheduler ===

scheduler = BackgroundScheduler()
scheduler.add_job(monitor_feeds, 'interval', minutes=5)
scheduler.start()

# Run once at startup
monitor_feeds()


if __name__ == '__main__':
    app.run(debug=True)
