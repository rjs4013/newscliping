"""
Sparrow Security Intelligence Crawler - 한국판
매월 SAST/DAST/SCA 경쟁사 한국 동향을 크롤링하여 이메일 발송
"""

import os, re, smtplib, time
import feedparser, requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone
from bs4 import BeautifulSoup
from urllib.parse import urljoin, quote

DAYS_BACK = 30   # 최근 30일치 수집
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "ko-KR,ko;q=0.9",
}

# ────────────────────────────────────────────────────────
# 경쟁사 키워드 (한국 미디어 검색용)
# ────────────────────────────────────────────────────────
COMPETITOR_KEYWORDS = {
    "SAST": [
        {"name": "Fortify",   "keywords": ["포티파이", "Fortify", "OpenText Fortify"]},
        {"name": "Checkmarx", "keywords": ["체크막스", "Checkmarx", "체크마르크스"]},
        {"name": "SSR",       "keywords": ["에스에스알", "SSR", "ssrinc", "CODE-RAY", "코드레이"]},
    ],
    "DAST": [
        {"name": "AppScan",       "keywords": ["앱스캔", "AppScan", "HCL AppScan"]},
        {"name": "나일소프트",     "keywords": ["나일소프트", "SecuGuard", "시큐가드"]},
        {"name": "Xint (Theori)", "keywords": ["Xint", "테오리", "Theori", "엑스인트"]},
    ],
    "SCA": [
        {"name": "Black Duck",  "keywords": ["블랙덕", "Black Duck", "BlackDuck"]},
        {"name": "래브라도랩스", "keywords": ["래브라도랩스", "Labrador Labs", "래브라도"]},
        {"name": "레드팬소프트", "keywords": ["레드팬소프트", "XSCAN", "엑스스캔", "레드팬"]},
    ],
}

# ────────────────────────────────────────────────────────
# 한국 보안 미디어 RSS
# ────────────────────────────────────────────────────────
KOREAN_MEDIA_RSS = [
    {"name": "보안뉴스",     "url": "https://www.boannews.com/rss/rss.asp"},
    {"name": "데일리시큐",   "url": "https://www.dailysecu.com/rss/allArticle.xml"},
    {"name": "아이티데일리", "url": "https://www.itdaily.kr/rss/allArticle.xml"},
    {"name": "전자신문",     "url": "https://rss.etnews.com/Section902.xml"},
    {"name": "ZDNet Korea",  "url": "https://www.zdnet.co.kr/rss/news.xml"},
    {"name": "디지털데일리", "url": "https://www.ddaily.co.kr/rss/rss.html"},
]

# ────────────────────────────────────────────────────────
# 경쟁사 공식 채널
# ────────────────────────────────────────────────────────
COMPETITOR_OFFICIAL = [
    # ── 국내 공식 채널 ──
    {
        "name": "SSR 보도자료",
        "url":  "https://www.ssrinc.co.kr/prcenter/article",
        "tag":  "SAST",
        "company": "SSR",
        # 보도자료 페이지이므로 링크 패턴 없이 모든 링크 수집
        "link_pattern": None,
        "pr_page": True,   # 보도자료 전용 페이지 → 제목 한글 필터 완화
    },
    {
        "name": "나일소프트 뉴스",
        "url":  "https://www.nilesoft.co.kr/irpr/notice/list",
        "tag":  "DAST",
        "company": "나일소프트",
        "link_pattern": None,
        "pr_page": True,
    },
    {
        "name": "래브라도랩스 블로그",
        "url":  "https://labradorlabs.ai/news/?lang=ko",
        "tag":  "SCA",
        "company": "래브라도랩스",
        "link_pattern": None,
        "pr_page": True,
    },
    {
        "name": "레드팬소프트 뉴스",
        "url":  "https://www.redpensoft.com/news",
        "tag":  "SCA",
        "company": "레드팬소프트",
        "link_pattern": None,
        "pr_page": True,
    },
    # ── 외산 국내 파트너 채널 ──
    {
        "name": "소프트와이드시큐리티 (AppScan 파트너)",
        "url":  "https://www.softwidesecu.com/news",
        "tag":  "DAST",
        "company": "AppScan",
        "link_pattern": None,
        "pr_page": True,
    },
    {
        "name": "KMS테크놀로지 (Black Duck 파트너)",
        "url":  "https://www.kmstech.co.kr/PR",
        "tag":  "SCA",
        "company": "Black Duck",
        "link_pattern": None,
        "pr_page": True,
    },
]

# Theori 블로그: 정보성 글 제외용 — 회사 동향 키워드가 있어야 수집
THEORI_PR_KEYWORDS = [
    "출시", "런칭", "런치", "계약", "수주", "파트너", "투자", "유치", "도입",
    "선정", "공급", "협약", "MOU", "레퍼런스", "고객", "제품", "업데이트",
    "버전", "출원", "특허", "인증", "수상", "어워드", "채용", "IR",
    "Xint", "엑스인트", "theori", "테오리",
]

# 회사별 메타 정보
COMPANY_META = {
    "Fortify":        {"type": "외산", "badge": "🌐"},
    "Checkmarx":      {"type": "외산", "badge": "🌐"},
    "SSR":            {"type": "국내", "badge": "🇰🇷"},
    "AppScan":        {"type": "외산", "badge": "🌐"},
    "나일소프트":      {"type": "국내", "badge": "🇰🇷"},
    "Xint (Theori)":  {"type": "국내", "badge": "🇰🇷"},
    "Black Duck":     {"type": "외산", "badge": "🌐"},
    "래브라도랩스":    {"type": "국내", "badge": "🇰🇷"},
    "레드팬소프트":    {"type": "국내", "badge": "🇰🇷"},
}


# ────────────────────────────────────────────────────────
# 유틸
# ────────────────────────────────────────────────────────

def cutoff_dt():
    return datetime.now(timezone.utc) - timedelta(days=DAYS_BACK)

def safe_get(url, timeout=12):
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout)
        r.raise_for_status()
        r.encoding = r.apparent_encoding or "utf-8"
        return r.text
    except Exception as e:
        print(f"  [WARN] GET 실패 {url[:60]}: {e}")
        return None

def parse_date(text: str):
    text = re.sub(r"\s+", " ", text.strip())
    for pat in [
        r"(\d{4})[.\-/](\d{1,2})[.\-/](\d{1,2})",
        r"(\d{4})년\s*(\d{1,2})월\s*(\d{1,2})일",
    ]:
        m = re.search(pat, text)
        if m:
            try:
                return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=timezone.utc)
            except Exception:
                pass
    return None

def is_korean_text(text: str, min_chars: int = 5) -> bool:
    """한글이 min_chars자 이상이면 True"""
    return len(re.findall(r"[가-힣]", text)) >= min_chars

def is_theori_pr_article(title: str, summary: str) -> bool:
    """Theori 블로그: 회사 동향 관련 키워드가 있을 때만 True"""
    combined = (title + " " + summary).lower()
    return any(kw.lower() in combined for kw in THEORI_PR_KEYWORDS)


# ────────────────────────────────────────────────────────
# 크롤러 1: RSS + 경쟁사 키워드 필터
# ────────────────────────────────────────────────────────

def build_flat_keyword_map():
    kmap = {}
    for cat, companies in COMPETITOR_KEYWORDS.items():
        for comp in companies:
            for kw in comp["keywords"]:
                kmap[kw.lower()] = (cat, comp["name"])
    return kmap

def crawl_rss_media(media: dict, kmap: dict) -> list[dict]:
    items = []
    try:
        feed = feedparser.parse(media["url"])
        for entry in feed.entries:
            pub = None
            if hasattr(entry, "published_parsed") and entry.published_parsed:
                pub = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
            if pub and pub < cutoff_dt():
                continue

            title = entry.get("title", "")
            summary_raw = entry.get("summary", "")
            summary = BeautifulSoup(summary_raw, "lxml").get_text()[:200]

            # 한국어 기사 필터
            if not is_korean_text(title + " " + summary):
                continue

            combined = (title + " " + summary).lower()
            matched_companies = {}
            for kw, (cat, company) in kmap.items():
                if kw in combined:
                    matched_companies[company] = cat

            if not matched_companies:
                continue

            for company, cat in matched_companies.items():
                items.append({
                    "title": title,
                    "link": entry.get("link", "#"),
                    "summary": summary,
                    "published": pub.strftime("%Y-%m-%d") if pub else "날짜 미상",
                    "source": media["name"],
                    "company": company,
                    "category": cat,
                })
    except Exception as e:
        print(f"  [WARN] RSS 실패 {media['name']}: {e}")
    return items


# ────────────────────────────────────────────────────────
# 크롤러 2: 경쟁사 공식 채널 파싱
# ────────────────────────────────────────────────────────

def crawl_official_page(source: dict) -> list[dict]:
    items = []
    html = safe_get(source["url"])
    if not html:
        return items
    soup = BeautifulSoup(html, "lxml")

    link_pattern = source.get("link_pattern")
    is_pr_page   = source.get("pr_page", False)
    is_theori    = source["company"] == "Xint (Theori)"

    seen_links = set()
    for a in soup.find_all("a", href=True)[:100]:
        title = a.get_text(strip=True)
        if len(title) < 8 or len(title) > 200:
            continue
        href = a["href"]

        # 링크 패턴 필터 (지정된 경우만)
        if link_pattern and link_pattern not in href.lower():
            continue

        # 보도자료 페이지가 아닌 경우: 뉴스성 링크 패턴 필요
        if not is_pr_page:
            if not any(p in href.lower() for p in
                       ["press", "news", "blog", "release", "notice", "article", "post"]):
                continue

        link = urljoin(source["url"], href)
        if link in seen_links or link == source["url"]:
            continue
        seen_links.add(link)

        # 한글 필터 (보도자료 페이지는 완화: 2자 이상)
        min_kr = 2 if is_pr_page else 5
        if not is_korean_text(title, min_chars=min_kr):
            continue

        # Theori: 정보성 글 제외 → 회사 동향 키워드 필수
        if is_theori and not is_theori_pr_article(title, ""):
            continue

        # 날짜 탐색
        pub = None
        node = a.parent
        for _ in range(4):
            if node:
                t = parse_date(node.get_text())
                if t:
                    pub = t
                    break
                node = node.parent
        if pub and pub < cutoff_dt():
            continue

        items.append({
            "title": title,
            "link": link,
            "summary": "",
            "published": pub.strftime("%Y-%m-%d") if pub else "날짜 미상",
            "source": source["name"],
            "company": source["company"],
            "category": source["tag"],
        })

    return items[:15]


# ────────────────────────────────────────────────────────
# 전체 수집
# ────────────────────────────────────────────────────────

def collect_all() -> dict:
    result = {
        cat: {comp["name"]: [] for comp in companies}
        for cat, companies in COMPETITOR_KEYWORDS.items()
    }
    kmap = build_flat_keyword_map()

    # RSS 미디어
    print("\n[RSS 미디어] 수집 중...")
    for media in KOREAN_MEDIA_RSS:
        items = crawl_rss_media(media, kmap)
        for item in items:
            cat, company = item["category"], item["company"]
            if cat in result and company in result[cat]:
                result[cat][company].append(item)
        print(f"  {media['name']}: {len(items)}건 매칭")
        time.sleep(0.3)

    # 공식 채널
    print("\n[공식 채널] 수집 중...")
    for source in COMPETITOR_OFFICIAL:
        items = crawl_official_page(source)
        cat, company = source["tag"], source["company"]
        if cat in result and company in result[cat]:
            result[cat][company].extend(items)
        print(f"  {source['name']}: {len(items)}건")
        time.sleep(0.4)

    # 중복 제거 & 날짜 정렬
    for cat in result:
        for company in result[cat]:
            seen = set()
            deduped = []
            for item in result[cat][company]:
                if item["link"] not in seen:
                    seen.add(item["link"])
                    deduped.append(item)
            deduped.sort(key=lambda x: x["published"], reverse=True)
            result[cat][company] = deduped

    total = sum(len(v) for cat in result.values() for v in cat.values())
    print(f"\n✅ 총 {total}건 수집 완료")
    return result


# ────────────────────────────────────────────────────────
# HTML 이메일 빌더
# ────────────────────────────────────────────────────────

CATEGORY_COLORS = {"SAST": "#3B82F6", "DAST": "#10B981", "SCA": "#F59E0B"}
CATEGORY_DESC   = {
    "SAST": "정적 애플리케이션 보안 테스트",
    "DAST": "동적 애플리케이션 보안 테스트",
    "SCA":  "소프트웨어 구성 분석",
}


def build_html(data: dict) -> str:
    now         = datetime.now()
    today       = now.strftime("%Y년 %m월 %d일")
    month_label = now.strftime("%Y년 %m월")
    month_start = (now - timedelta(days=30)).strftime("%m/%d")
    month_end   = now.strftime("%m/%d")
    total       = sum(len(v) for cat in data.values() for v in cat.values())

    categories_html = ""
    for cat, companies in data.items():
        color     = CATEGORY_COLORS[cat]
        cat_total = sum(len(v) for v in companies.values())

        company_blocks = ""
        for company, items in companies.items():
            meta    = COMPANY_META.get(company, {"type": "", "badge": ""})
            badge   = meta["badge"]
            ctype   = meta["type"]
            c_color = "#6366F1" if ctype == "국내" else "#64748B"

            if not items:
                card_html = '<p style="font-size:12px;color:#9CA3AF;margin:8px 0 0;">이번 달 새로운 소식이 없습니다.</p>'
            else:
                card_html = ""
                for item in items[:5]:
                    summary_html = (
                        f'<p style="font-size:12px;color:#6B7280;margin:4px 0 0;line-height:1.5;">'
                        f'{item["summary"][:130]}…</p>'
                    ) if item.get("summary") else ""
                    card_html += f"""
                    <div style="border-left:3px solid {color};padding:10px 12px;margin-top:10px;background:#F8FAFC;border-radius:0 6px 6px 0;">
                      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                        <span style="font-size:11px;color:#94A3B8;">{item['source']}</span>
                        <span style="font-size:11px;color:#94A3B8;">{item['published']}</span>
                      </div>
                      <a href="{item['link']}" style="font-size:13px;font-weight:600;color:#1E293B;text-decoration:none;line-height:1.45;">{item['title']}</a>
                      {summary_html}
                    </div>"""

            company_blocks += f"""
            <div style="margin-bottom:20px;">
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
                <span style="font-size:15px;">{badge}</span>
                <span style="font-size:14px;font-weight:700;color:#1E293B;">{company}</span>
                <span style="font-size:10px;font-weight:600;color:{c_color};background:{c_color}18;padding:1px 7px;border-radius:999px;">{ctype}</span>
                <span style="font-size:11px;color:#94A3B8;margin-left:auto;">{len(items)}건</span>
              </div>
              {card_html}
            </div>"""

        categories_html += f"""
        <div style="margin-bottom:36px;">
          <div style="display:flex;align-items:center;gap:10px;padding-bottom:10px;border-bottom:2px solid {color};margin-bottom:18px;">
            <div style="width:4px;height:24px;background:{color};border-radius:2px;flex-shrink:0;"></div>
            <div>
              <h2 style="margin:0;font-size:16px;font-weight:700;color:#111827;">{cat}</h2>
              <p style="margin:0;font-size:11px;color:#9CA3AF;">{CATEGORY_DESC[cat]} · {cat_total}건</p>
            </div>
          </div>
          {company_blocks}
        </div>"""

    summary_cells = "".join(f"""
      <td style="width:33%;padding:4px;">
        <div style="background:#FFF;border-radius:8px;padding:14px;text-align:center;border-top:3px solid {CATEGORY_COLORS[c]};">
          <div style="font-size:22px;font-weight:700;color:{CATEGORY_COLORS[c]};">{sum(len(v) for v in data[c].values())}</div>
          <div style="font-size:11px;color:#6B7280;font-weight:600;margin-top:2px;">{c}</div>
        </div>
      </td>""" for c in ["SAST", "DAST", "SCA"])

    return f"""<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background:#F1F5F9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
<div style="max-width:660px;margin:0 auto;padding:20px 14px;">

  <div style="background:linear-gradient(135deg,#0F172A 0%,#1E3A5F 100%);border-radius:12px;padding:28px 24px;margin-bottom:16px;text-align:center;">
    <div style="font-size:26px;margin-bottom:8px;">🦅</div>
    <h1 style="margin:0 0 4px;font-size:19px;font-weight:700;color:#FFF;">Sparrow Security Intelligence</h1>
    <p style="margin:0 0 12px;font-size:12px;color:#93C5FD;">SAST · DAST · SCA 경쟁사 월간 동향 (🌐 외산 3 + 🇰🇷 국내 6)</p>
    <span style="display:inline-block;background:rgba(255,255,255,0.12);border-radius:999px;padding:5px 14px;font-size:11px;color:#E2E8F0;">
      📅 {month_label}&nbsp;&nbsp;|&nbsp;&nbsp;{month_start} ~ {month_end} 수집&nbsp;&nbsp;|&nbsp;&nbsp;총 {total}건
    </span>
  </div>

  <table style="width:100%;border-collapse:separate;border-spacing:0;margin-bottom:16px;">
    <tr>{summary_cells}</tr>
  </table>

  <div style="background:#FFF;border-radius:12px;padding:24px 20px;">
    <div style="background:#EFF6FF;border:1px solid #BFDBFE;border-radius:8px;padding:10px 14px;margin-bottom:22px;font-size:12px;color:#1E40AF;">
      📰 <strong>수집 출처</strong>: 보안뉴스 · 데일리시큐 · 아이티데일리 · 전자신문 · ZDNet Korea · 디지털데일리 + 각사 공식 채널
    </div>
    {categories_html}
  </div>

  <div style="text-align:center;padding:14px;color:#94A3B8;font-size:11px;">
    Sparrow Intelligence Bot · 매월 1일 오전 9시 (KST) 자동 발송
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
    subject = f"[Sparrow Intel] SAST/DAST/SCA 경쟁사 월간 동향 {month_label}"
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
    print("Sparrow Security Intelligence Crawler (한국판)")
    print("=" * 55)
    data = collect_all()
    html = build_html(data)
    with open("report.html", "w", encoding="utf-8") as f:
        f.write(html)
    print("\n[OK] report.html 저장 완료")
    send_email(html)

if __name__ == "__main__":
    main()