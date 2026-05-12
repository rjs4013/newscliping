"""
Sparrow Security Intelligence - 경쟁사·시장 월간 동향
흐름: Google News RSS 수집 → 제목 유사도 중복 제거 → 컴팩트 HTML 이메일 발송
"""

import os, re, smtplib, time
import feedparser, requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone
from bs4 import BeautifulSoup
from urllib.parse import quote

DAYS_BACK = 30
HEADERS   = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept-Language": "ko-KR,ko;q=0.9",
}

# ────────────────────────────────────────────────────────
# 검색 쿼리
# ────────────────────────────────────────────────────────
SEARCH_QUERIES = [
    {"q": "Checkmarx OR 체크막스",           "category": "SAST", "company": "Checkmarx"},
    {"q": "Fortify OR 포티파이 보안",         "category": "SAST", "company": "Fortify"},
    {"q": "에스에스알 OR SSR CODE-RAY 보안",  "category": "SAST", "company": "SSR"},
    {"q": "AppScan OR 앱스캔 보안",           "category": "DAST", "company": "AppScan"},
    {"q": "나일소프트 OR SecuGuard",          "category": "DAST", "company": "나일소프트"},
    {"q": "Theori OR Xint 보안",             "category": "DAST", "company": "Xint (Theori)"},
    {"q": "Black Duck OR 블랙덕 보안",        "category": "SCA",  "company": "Black Duck"},
    {"q": "래브라도랩스 OR Labrador Labs",    "category": "SCA",  "company": "래브라도랩스"},
    {"q": "레드팬소프트 OR XSCAN SBOM",      "category": "SCA",  "company": "레드팬소프트"},
    {"q": "SAST 정적분석 보안",               "category": "SAST", "company": None},
    {"q": "DAST 웹취약점 동적분석",           "category": "DAST", "company": None},
    {"q": "SCA 오픈소스 취약점",              "category": "SCA",  "company": None},
    {"q": "SBOM 공급망보안",                 "category": "SCA",  "company": None},
    {"q": "시큐어코딩 소프트웨어 보안",        "category": "SAST", "company": None},
    {"q": "DevSecOps 보안 자동화",           "category": "SAST", "company": None},
]

COMPANY_META = {
    "Fortify":       {"type": "외산", "badge": "🌐"},
    "Checkmarx":     {"type": "외산", "badge": "🌐"},
    "SSR":           {"type": "국내", "badge": "🇰🇷"},
    "AppScan":       {"type": "외산", "badge": "🌐"},
    "나일소프트":     {"type": "국내", "badge": "🇰🇷"},
    "Xint (Theori)": {"type": "국내", "badge": "🇰🇷"},
    "Black Duck":    {"type": "외산", "badge": "🌐"},
    "래브라도랩스":   {"type": "국내", "badge": "🇰🇷"},
    "레드팬소프트":   {"type": "국내", "badge": "🇰🇷"},
}

CATEGORY_COLORS = {"SAST": "#3B82F6", "DAST": "#10B981", "SCA": "#F59E0B"}
CATEGORY_DESC   = {
    "SAST": "정적 분석",
    "DAST": "동적 분석",
    "SCA":  "공급망 / 오픈소스",
}


# ────────────────────────────────────────────────────────
# 유틸
# ────────────────────────────────────────────────────────

def cutoff_dt():
    return datetime.now(timezone.utc) - timedelta(days=DAYS_BACK)

def is_korean(text: str) -> bool:
    return len(re.findall(r"[가-힣]", text)) >= 4

def title_key(title: str) -> str:
    """제목에서 출처(- 매체명) 제거 후 핵심 텍스트만 추출 → 유사 중복 탐지용"""
    t = re.sub(r"\s*[-–|]\s*[^-–|]{2,20}$", "", title).strip()  # 끝 '- 매체명' 제거
    t = re.sub(r"[^\w가-힣]", "", t).lower()                      # 특수문자 제거
    return t


# ────────────────────────────────────────────────────────
# 수집
# ────────────────────────────────────────────────────────

def fetch_google_news(qcfg: dict) -> list[dict]:
    url = f"https://news.google.com/rss/search?q={quote(qcfg['q'])}&hl=ko&gl=KR&ceid=KR:ko"
    items = []
    try:
        feed = feedparser.parse(url)
        for entry in feed.entries:
            pub = None
            if hasattr(entry, "published_parsed") and entry.published_parsed:
                pub = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
            if pub and pub < cutoff_dt():
                continue
            title  = entry.get("title", "").strip()
            if not is_korean(title):
                continue
            items.append({
                "title":    title,
                "link":     entry.get("link", "#"),
                "source":   entry.get("source", {}).get("title", ""),
                "published": pub.strftime("%Y-%m-%d") if pub else "날짜 미상",
                "category": qcfg["category"],
                "company":  qcfg["company"],
            })
    except Exception as e:
        print(f"  [WARN] '{qcfg['q'][:25]}': {e}")
    return items


def collect_articles() -> list[dict]:
    all_items  = []
    seen_links = set()
    seen_keys  = set()   # 제목 유사도 기반 중복 탐지

    print("\n[Google News RSS] 수집 중...")
    for qcfg in SEARCH_QUERIES:
        items = fetch_google_news(qcfg)
        added = 0
        for item in items:
            link = item["link"]
            key  = title_key(item["title"])
            # URL 중복 or 제목 핵심이 동일하면 스킵
            if link in seen_links or key in seen_keys:
                continue
            seen_links.add(link)
            seen_keys.add(key)
            all_items.append(item)
            added += 1
        print(f"  '{qcfg['q'][:28]}': {added}건")
        time.sleep(0.5)

    all_items.sort(key=lambda x: x["published"], reverse=True)
    print(f"\n  → 총 {len(all_items)}건 (중복 제거 후)")
    return all_items


# ────────────────────────────────────────────────────────
# HTML 이메일 — 컴팩트 2열 그리드 레이아웃
# ────────────────────────────────────────────────────────

def article_row(item: dict) -> str:
    """기사 한 줄 행 (제목 링크 + 출처·날짜)"""
    cat    = item["category"]
    color  = CATEGORY_COLORS.get(cat, "#6B7280")
    comp   = item.get("company") or ""
    meta   = COMPANY_META.get(comp, {"badge": ""})
    badge  = f'<span style="font-size:10px;margin-right:4px;">{meta["badge"]}</span>' if meta["badge"] else ""
    dot    = f'<span style="display:inline-block;width:6px;height:6px;background:{color};border-radius:50%;margin-right:5px;vertical-align:middle;"></span>'

    return f"""<tr>
      <td style="padding:7px 8px;border-bottom:1px solid #F1F5F9;vertical-align:top;">
        {dot}{badge}<a href="{item['link']}" style="font-size:13px;font-weight:600;color:#1E293B;text-decoration:none;line-height:1.4;">{item['title']}</a>
        <div style="font-size:11px;color:#94A3B8;margin-top:2px;">{item['source']} · {item['published']}</div>
      </td>
    </tr>"""


def build_html(articles: list[dict]) -> str:
    now         = datetime.now()
    month_label = now.strftime("%Y년 %m월")
    month_start = (now - timedelta(days=30)).strftime("%m/%d")
    month_end   = now.strftime("%m/%d")
    total       = len(articles)

    by_cat: dict[str, dict[str, list]] = {
        "SAST": {}, "DAST": {}, "SCA": {}
    }
    for item in articles:
        cat  = item.get("category", "SAST")
        comp = item.get("company") or "기타"
        if cat not in by_cat:
            continue
        by_cat[cat].setdefault(comp, []).append(item)

    # 요약 카드
    summary_cells = "".join(f"""
      <td style="width:33%;padding:4px;">
        <div style="background:#FFF;border-radius:8px;padding:12px;text-align:center;border-top:3px solid {CATEGORY_COLORS[c]};">
          <div style="font-size:20px;font-weight:700;color:{CATEGORY_COLORS[c]};">{len([a for a in articles if a['category']==c])}</div>
          <div style="font-size:11px;color:#6B7280;font-weight:600;">{c} <span style="font-weight:400;color:#9CA3AF;">· {CATEGORY_DESC[c]}</span></div>
        </div>
      </td>""" for c in ["SAST", "DAST", "SCA"])

    # 카테고리별 섹션
    cat_sections = ""
    for cat, companies in by_cat.items():
        if not companies:
            continue
        color = CATEGORY_COLORS[cat]
        cat_total = sum(len(v) for v in companies.values())

        # 회사별 테이블
        company_blocks = ""
        for comp, items in sorted(companies.items()):
            meta  = COMPANY_META.get(comp, {"type": "", "badge": "📰"})
            badge = meta["badge"]
            ctype = meta["type"]
            c_color = "#6366F1" if ctype == "국내" else "#64748B"
            type_badge = f'<span style="font-size:9px;color:{c_color};border:1px solid {c_color};padding:0 5px;border-radius:3px;margin-left:5px;">{ctype}</span>' if ctype else ""

            rows = "".join(article_row(a) for a in items[:10])
            company_blocks += f"""
            <div style="margin-bottom:16px;">
              <div style="font-size:12px;font-weight:700;color:#374151;padding:5px 0;border-bottom:1px solid #E5E7EB;margin-bottom:4px;">
                {badge} {comp}{type_badge}
                <span style="font-weight:400;color:#9CA3AF;font-size:11px;float:right;">{len(items)}건</span>
              </div>
              <table style="width:100%;border-collapse:collapse;">{rows}</table>
            </div>"""

        cat_sections += f"""
        <div style="margin-bottom:28px;">
          <div style="display:flex;align-items:center;gap:8px;padding-bottom:8px;border-bottom:2px solid {color};margin-bottom:14px;">
            <div style="width:3px;height:20px;background:{color};border-radius:2px;"></div>
            <span style="font-size:15px;font-weight:700;color:#111827;">{cat}</span>
            <span style="font-size:11px;color:#9CA3AF;">{CATEGORY_DESC[cat]} · {cat_total}건</span>
          </div>
          {company_blocks}
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#F1F5F9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
<div style="max-width:660px;margin:0 auto;padding:16px 12px;">

  <div style="background:linear-gradient(135deg,#0F172A 0%,#1E3A5F 100%);border-radius:10px;padding:22px 20px;margin-bottom:12px;text-align:center;">
    <div style="font-size:22px;margin-bottom:6px;">🦅</div>
    <h1 style="margin:0 0 3px;font-size:17px;font-weight:700;color:#FFF;">Sparrow Security Intelligence</h1>
    <p style="margin:0 0 10px;font-size:11px;color:#93C5FD;">경쟁사 · 시장 월간 동향</p>
    <span style="display:inline-block;background:rgba(255,255,255,0.12);border-radius:999px;padding:4px 12px;font-size:11px;color:#E2E8F0;">
      📅 {month_label} &nbsp;|&nbsp; {month_start}~{month_end} &nbsp;|&nbsp; 총 {total}건
    </span>
  </div>

  <table style="width:100%;border-collapse:separate;border-spacing:0;margin-bottom:12px;">
    <tr>{summary_cells}</tr>
  </table>

  <div style="background:#FFF;border-radius:10px;padding:20px 18px;">
    {cat_sections}
  </div>

  <div style="text-align:center;padding:12px;color:#94A3B8;font-size:10px;">
    Sparrow Intelligence Bot · 매월 1일 오전 9시 자동 발송 · Google News 기반
  </div>
</div>
</body></html>"""


# ────────────────────────────────────────────────────────
# 이메일 발송
# ────────────────────────────────────────────────────────

def send_email(html_body: str):
    smtp_host  = os.environ["SMTP_HOST"]
    smtp_port  = int(os.environ.get("SMTP_PORT") or "587")
    smtp_user  = os.environ["SMTP_USER"]
    smtp_pass  = os.environ["SMTP_PASS"]
    email_from = os.environ["EMAIL_FROM"]
    email_to   = os.environ["EMAIL_TO"]

    month_label = datetime.now().strftime("%Y년 %m월")
    subject = f"[Sparrow Intel] 경쟁사·시장 월간 동향 {month_label}"
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = email_from
    msg["To"]      = email_to
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    with smtplib.SMTP(smtp_host, smtp_port) as s:
        s.ehlo(); s.starttls()
        s.login(smtp_user, smtp_pass)
        s.sendmail(email_from, email_to.split(","), msg.as_string())
    print(f"[OK] 이메일 발송 → {email_to}")


# ────────────────────────────────────────────────────────
# 메인
# ────────────────────────────────────────────────────────

def main():
    print("=" * 55)
    print("Sparrow Security Intelligence")
    print("=" * 55)
    articles = collect_articles()
    html = build_html(articles)
    with open("report.html", "w", encoding="utf-8") as f:
        f.write(html)
    print("\n[OK] report.html 저장")
    send_email(html)
    print(f"\n✅ 완료! 총 {len(articles)}건")

if __name__ == "__main__":
    main()