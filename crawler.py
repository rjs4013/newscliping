"""
Sparrow Security Intelligence - 영업 활용 중심 정보 정리 자동화
─────────────────────────────────────────────────────────────
흐름:
  1. Google News RSS → 경쟁사/보안 키워드로 한국 기사 수집
  2. Gemini Flash (무료) → 영업 관점 분석 (카테고리·고객군·경쟁사·영업포인트)
  3. HTML 이메일 발송
"""

import os, re, json, smtplib, time
import feedparser, requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone
from bs4 import BeautifulSoup
from urllib.parse import quote

# ────────────────────────────────────────────────────────
# 설정
# ────────────────────────────────────────────────────────
DAYS_BACK    = 30
GEMINI_MODEL = "gemini-1.5-flash-latest"   # 무료 티어 지원
GEMINI_URL   = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept-Language": "ko-KR,ko;q=0.9",
}

# ────────────────────────────────────────────────────────
# Google News RSS 검색 쿼리
# 경쟁사명 + 보안 주제어 두 트랙으로 수집
# ────────────────────────────────────────────────────────
SEARCH_QUERIES = [
    # ── 경쟁사 트랙 ──
    {"q": "Checkmarx OR 체크막스",              "category": "SAST", "company": "Checkmarx"},
    {"q": "Fortify OR 포티파이 보안",            "category": "SAST", "company": "Fortify"},
    {"q": "에스에스알 OR SSR CODE-RAY 보안",     "category": "SAST", "company": "SSR"},
    {"q": "AppScan OR 앱스캔 보안",              "category": "DAST", "company": "AppScan"},
    {"q": "나일소프트 OR SecuGuard",             "category": "DAST", "company": "나일소프트"},
    {"q": "Theori OR Xint 보안",                "category": "DAST", "company": "Xint (Theori)"},
    {"q": "Black Duck OR 블랙덕 보안",           "category": "SCA",  "company": "Black Duck"},
    {"q": "래브라도랩스 OR Labrador Labs",        "category": "SCA",  "company": "래브라도랩스"},
    {"q": "레드팬소프트 OR XSCAN SBOM",          "category": "SCA",  "company": "레드팬소프트"},
    # ── 보안 주제어 트랙 (경쟁사 미언급 기사도 수집) ──
    {"q": "SAST 정적분석 보안",                  "category": "SAST", "company": None},
    {"q": "DAST 웹취약점 동적분석",               "category": "DAST", "company": None},
    {"q": "SCA 오픈소스 취약점",                  "category": "SCA",  "company": None},
    {"q": "SBOM 공급망보안",                     "category": "SCA",  "company": None},
    {"q": "시큐어코딩 소프트웨어 보안",            "category": "SAST", "company": None},
    {"q": "DevSecOps 보안 자동화",               "category": "SAST", "company": None},
]

# ────────────────────────────────────────────────────────
# 회사 메타
# ────────────────────────────────────────────────────────
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
    "기타":           {"type": "",     "badge": "📰"},
}

CATEGORY_COLORS = {"SAST": "#3B82F6", "DAST": "#10B981", "SCA": "#F59E0B"}
CATEGORY_DESC   = {
    "SAST": "정적 애플리케이션 보안 테스트",
    "DAST": "동적 애플리케이션 보안 테스트",
    "SCA":  "소프트웨어 구성 분석 / 공급망 보안",
}


# ────────────────────────────────────────────────────────
# 유틸
# ────────────────────────────────────────────────────────

def cutoff_dt():
    return datetime.now(timezone.utc) - timedelta(days=DAYS_BACK)

def is_korean(text: str) -> bool:
    return len(re.findall(r"[가-힣]", text)) >= 4

def parse_gnews_date(entry) -> datetime | None:
    if hasattr(entry, "published_parsed") and entry.published_parsed:
        return datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
    return None


# ────────────────────────────────────────────────────────
# 1단계: Google News RSS 수집
# ────────────────────────────────────────────────────────

def fetch_google_news(query_cfg: dict) -> list[dict]:
    """Google News RSS로 한국어 기사 수집 (API 키 불필요)"""
    q   = query_cfg["q"]
    url = f"https://news.google.com/rss/search?q={quote(q)}&hl=ko&gl=KR&ceid=KR:ko"
    items = []
    try:
        feed = feedparser.parse(url)
        for entry in feed.entries:
            pub = parse_gnews_date(entry)
            if pub and pub < cutoff_dt():
                continue

            title   = entry.get("title", "").strip()
            link    = entry.get("link", "#")
            source  = entry.get("source", {}).get("title", "")
            summary = BeautifulSoup(entry.get("summary", ""), "lxml").get_text()[:300]

            # 한국어 기사만
            if not is_korean(title + summary):
                continue

            items.append({
                "title":    title,
                "link":     link,
                "summary":  summary,
                "source":   source,
                "published": pub.strftime("%Y-%m-%d") if pub else "날짜 미상",
                "category": query_cfg["category"],
                "company":  query_cfg["company"],
                "analysis": None,   # Gemini 분석 결과 (나중에 채움)
            })
    except Exception as e:
        print(f"  [WARN] Google News 실패 '{q}': {e}")
    return items


def collect_articles() -> list[dict]:
    """전체 쿼리 실행 → 중복 제거"""
    all_items = []
    seen_links = set()

    print("\n[Google News RSS] 수집 중...")
    for qcfg in SEARCH_QUERIES:
        items = fetch_google_news(qcfg)
        for item in items:
            if item["link"] not in seen_links:
                seen_links.add(item["link"])
                all_items.append(item)
        print(f"  '{qcfg['q'][:30]}': {len(items)}건")
        time.sleep(0.5)

    all_items.sort(key=lambda x: x["published"], reverse=True)
    print(f"\n  → 총 {len(all_items)}건 (중복 제거 후)")
    return all_items


# ────────────────────────────────────────────────────────
# 2단계: Gemini Flash로 영업 관점 분석
# ────────────────────────────────────────────────────────

def build_prompt(title: str, summary: str) -> str:
    """프롬프트 생성 — JSON 중괄호를 f-string/format과 분리"""
    json_schema = (
        '{{\n'
        '  "category_tags": ["SAST, DAST, SCA, SBOM, 공급망보안, DevSecOps, 시큐어코딩, 금융보안, 공공보안 중 해당"],\n'
        '  "industry_tags": ["금융, 공공, 제조, 의료, IT서비스, 전체 중 해당"],\n'
        '  "competitor": "언급된 경쟁사명 또는 null",\n'
        '  "competitor_move": "경쟁사 움직임 한 줄 요약 (없으면 null)",\n'
        '  "sales_point": "영업 활용 포인트 1~2줄 (스패로우 관점 기회/위협)",\n'
        '  "urgency": "높음 또는 보통 또는 낮음"\n'
        '}}'
    )
    return (
        "당신은 소프트웨어 보안 솔루션 회사(스패로우)의 영업/마케팅 분석가입니다.\n"
        "스패로우는 SAST(정적분석), DAST(동적분석), SCA(오픈소스 분석) 제품을 국내에 판매합니다.\n\n"
        "아래 기사를 읽고 JSON만 반환하세요 (마크다운 코드블록 없이 순수 JSON만):\n\n"
        f"{json_schema}\n\n"
        f"기사 제목: {title}\n"
        f"기사 내용: {summary}"
    )

def analyze_with_gemini(article: dict, api_key: str) -> dict:
    """Gemini Flash로 단일 기사 분석"""
    prompt = build_prompt(
        title   = article["title"],
        summary = article["summary"] or article["title"],
    )
    try:
        resp = requests.post(
            f"{GEMINI_URL}?key={api_key}",
            headers={"Content-Type": "application/json"},
            json={"contents": [{"parts": [{"text": prompt}]}],
                  "generationConfig": {"temperature": 0.2, "maxOutputTokens": 300}},
            timeout=20,
        )
        resp.raise_for_status()
        text = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
        # JSON 파싱
        text = re.sub(r"^```json\s*|^```\s*|\s*```$", "", text, flags=re.MULTILINE).strip()
        return json.loads(text)
    except Exception as e:
        print(f"  [WARN] Gemini 분석 실패: {e}")
        return {
            "category_tags": [article["category"]],
            "industry_tags": [],
            "competitor": article["company"],
            "competitor_move": None,
            "sales_point": "분석 실패",
            "urgency": "낮음",
        }


def analyze_all(articles: list[dict]) -> list[dict]:
    """전체 기사 Gemini 분석 (분당 15건 무료 제한 대응)"""
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        print("[WARN] GEMINI_API_KEY 없음 → 분석 건너뜀")
        for a in articles:
            a["analysis"] = {
                "category_tags": [a["category"]],
                "industry_tags": [],
                "competitor": a["company"],
                "competitor_move": None,
                "sales_point": "(Gemini API 키 미설정)",
                "urgency": "낮음",
            }
        return articles

    print(f"\n[Gemini 분석] {len(articles)}건 분석 시작...")
    for i, article in enumerate(articles):
        article["analysis"] = analyze_with_gemini(article, api_key)
        urgency = article["analysis"].get("urgency", "")
        print(f"  [{i+1}/{len(articles)}] {article['title'][:40]}... → 긴급도:{urgency}")
        # 무료 티어: 분당 15건 제한 → 4초 간격
        if (i + 1) % 14 == 0:
            print("  (rate limit 대기 60초...)")
            time.sleep(60)
        else:
            time.sleep(4)
    return articles


# ────────────────────────────────────────────────────────
# 3단계: HTML 이메일 빌더
# ────────────────────────────────────────────────────────

URGENCY_COLOR = {"높음": "#EF4444", "보통": "#F59E0B", "낮음": "#10B981"}

def tag_badge(tag: str, color: str = "#6366F1") -> str:
    return f'<span style="font-size:10px;font-weight:600;color:{color};background:{color}18;padding:2px 7px;border-radius:4px;margin-right:4px;">{tag}</span>'

def build_article_card(item: dict) -> str:
    a   = item.get("analysis") or {}
    cat = item["category"]
    color = CATEGORY_COLORS.get(cat, "#6B7280")

    # 태그들
    cat_tags = "".join(tag_badge(t, color) for t in (a.get("category_tags") or [cat])[:3])
    ind_tags = "".join(tag_badge(t, "#64748B") for t in (a.get("industry_tags") or [])[:2])

    # 경쟁사 배지
    comp = a.get("competitor") or item.get("company") or ""
    meta = COMPANY_META.get(comp, {"type": "", "badge": "📰"})
    comp_badge = (
        f'<span style="font-size:10px;font-weight:700;color:#7C3AED;background:#EDE9FE;'
        f'padding:2px 8px;border-radius:4px;margin-right:6px;">'
        f'{meta["badge"]} {comp}</span>'
    ) if comp else ""

    # 긴급도
    urgency = a.get("urgency", "낮음")
    urg_color = URGENCY_COLOR.get(urgency, "#94A3B8")
    urg_badge = (
        f'<span style="font-size:10px;font-weight:700;color:{urg_color};'
        f'border:1px solid {urg_color};padding:1px 6px;border-radius:4px;">● {urgency}</span>'
    )

    # 영업 포인트
    sales = a.get("sales_point") or ""
    comp_move = a.get("competitor_move") or ""

    sales_html = ""
    if comp_move:
        sales_html += f'<div style="font-size:12px;color:#64748B;margin-top:6px;">🔍 <strong>경쟁사 동향:</strong> {comp_move}</div>'
    if sales:
        sales_html += f'<div style="font-size:12px;color:#1E40AF;margin-top:4px;background:#EFF6FF;padding:6px 8px;border-radius:4px;">💡 <strong>영업 포인트:</strong> {sales}</div>'

    # 원문 요약 (있을 때만)
    summary_text = (item.get("summary") or "").strip()
    summary_html = (
        f'<div style="font-size:12px;color:#475569;margin-top:6px;padding:8px 10px;'
        f'background:#F8FAFC;border-radius:4px;border-left:2px solid #CBD5E1;line-height:1.6;">'
        f'📄 {summary_text[:200]}{"…" if len(summary_text) > 200 else ""}'
        f'</div>'
    ) if summary_text else ""

    return f"""
    <div style="border:1px solid #E2E8F0;border-radius:8px;padding:14px 16px;margin-bottom:12px;background:#FAFAFA;">
      <div style="display:flex;flex-wrap:wrap;align-items:center;gap:4px;margin-bottom:8px;">
        {comp_badge}{cat_tags}{ind_tags}
        <span style="margin-left:auto;">{urg_badge}</span>
      </div>
      <!-- 원문 출처 & 제목 -->
      <a href="{item['link']}" style="font-size:14px;font-weight:700;color:#0F172A;text-decoration:none;line-height:1.4;display:block;margin-bottom:3px;">{item['title']}</a>
      <div style="font-size:11px;color:#94A3B8;margin-bottom:6px;">
        📰 {item['source']} · {item['published']}
        &nbsp;<a href="{item['link']}" style="color:#3B82F6;text-decoration:none;font-size:10px;">[원문 보기 →]</a>
      </div>
      {summary_html}
      {sales_html}
    </div>"""


def build_html(articles: list[dict]) -> str:
    now         = datetime.now()
    month_label = now.strftime("%Y년 %m월")
    month_start = (now - timedelta(days=30)).strftime("%m/%d")
    month_end   = now.strftime("%m/%d")
    total       = len(articles)

    # 긴급도 높음 먼저, 카테고리별 그룹
    articles_sorted = sorted(
        articles,
        key=lambda x: (
            {"높음": 0, "보통": 1, "낮음": 2}.get((x.get("analysis") or {}).get("urgency", "낮음"), 2),
            x["category"],
        )
    )

    # 카테고리별 그룹핑
    by_cat = {"SAST": [], "DAST": [], "SCA": []}
    for item in articles_sorted:
        cat = item.get("category", "SAST")
        if cat in by_cat:
            by_cat[cat].append(item)

    # 긴급도 높음 기사 따로 모음
    high_urgency = [a for a in articles if (a.get("analysis") or {}).get("urgency") == "높음"]

    # 요약 카운트
    summary_cells = "".join(f"""
      <td style="width:33%;padding:4px;">
        <div style="background:#FFF;border-radius:8px;padding:14px;text-align:center;border-top:3px solid {CATEGORY_COLORS[c]};">
          <div style="font-size:22px;font-weight:700;color:{CATEGORY_COLORS[c]};">{len(by_cat[c])}</div>
          <div style="font-size:11px;color:#6B7280;font-weight:600;margin-top:2px;">{c}</div>
        </div>
      </td>""" for c in ["SAST", "DAST", "SCA"])

    # 주목 기사 섹션
    highlight_html = ""
    if high_urgency:
        cards = "".join(build_article_card(a) for a in high_urgency[:3])
        highlight_html = f"""
        <div style="margin-bottom:32px;">
          <div style="display:flex;align-items:center;gap:10px;padding-bottom:10px;border-bottom:2px solid #EF4444;margin-bottom:16px;">
            <div style="width:4px;height:24px;background:#EF4444;border-radius:2px;"></div>
            <h2 style="margin:0;font-size:16px;font-weight:700;color:#111827;">🔥 이달의 주목 기사</h2>
          </div>
          {cards}
        </div>"""

    # 카테고리별 섹션
    cat_sections = ""
    for cat, items in by_cat.items():
        if not items:
            continue
        color = CATEGORY_COLORS[cat]
        cards = "".join(build_article_card(a) for a in items[:8])
        cat_sections += f"""
        <div style="margin-bottom:36px;">
          <div style="display:flex;align-items:center;gap:10px;padding-bottom:10px;border-bottom:2px solid {color};margin-bottom:16px;">
            <div style="width:4px;height:24px;background:{color};border-radius:2px;"></div>
            <div>
              <h2 style="margin:0;font-size:16px;font-weight:700;color:#111827;">{cat}</h2>
              <p style="margin:0;font-size:11px;color:#9CA3AF;">{CATEGORY_DESC[cat]} · {len(items)}건</p>
            </div>
          </div>
          {cards}
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#F1F5F9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
<div style="max-width:680px;margin:0 auto;padding:20px 14px;">

  <!-- 헤더 -->
  <div style="background:linear-gradient(135deg,#0F172A 0%,#1E3A5F 100%);border-radius:12px;padding:28px 24px;margin-bottom:16px;text-align:center;">
    <div style="font-size:26px;margin-bottom:8px;">🦅</div>
    <h1 style="margin:0 0 4px;font-size:19px;font-weight:700;color:#FFF;">Sparrow Security Intelligence</h1>
    <p style="margin:0 0 12px;font-size:12px;color:#93C5FD;">영업 활용 중심 경쟁사·시장 월간 동향</p>
    <span style="display:inline-block;background:rgba(255,255,255,0.12);border-radius:999px;padding:5px 14px;font-size:11px;color:#E2E8F0;">
      📅 {month_label}&nbsp;&nbsp;|&nbsp;&nbsp;{month_start}~{month_end} 수집&nbsp;&nbsp;|&nbsp;&nbsp;총 {total}건 AI 분석
    </span>
  </div>

  <!-- 요약 카드 -->
  <table style="width:100%;border-collapse:separate;border-spacing:0;margin-bottom:16px;">
    <tr>{summary_cells}</tr>
  </table>

  <!-- 범례 -->
  <div style="background:#FFF;border-radius:8px;padding:12px 16px;margin-bottom:12px;font-size:11px;color:#64748B;">
    <strong>범례</strong> &nbsp;
    <span style="color:#EF4444;">● 높음</span> 즉시 영업 활용 가능 &nbsp;|&nbsp;
    <span style="color:#F59E0B;">● 보통</span> 참고·모니터링 &nbsp;|&nbsp;
    <span style="color:#10B981;">● 낮음</span> 배경 정보 &nbsp;|&nbsp;
    💡 영업 포인트 · 🔍 경쟁사 동향
  </div>

  <!-- 본문 -->
  <div style="background:#FFF;border-radius:12px;padding:24px 20px;">
    {highlight_html}
    {cat_sections}
  </div>

  <!-- 푸터 -->
  <div style="text-align:center;padding:14px;color:#94A3B8;font-size:11px;">
    Sparrow Intelligence Bot · 매월 1일 오전 9시 자동 발송 · Powered by Google News + Gemini Flash
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
    subject = f"[Sparrow Intel] 경쟁사·시장 월간 동향 {month_label} (AI 분석)"
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
    print("Sparrow Security Intelligence (영업 활용 자동화)")
    print("=" * 55)

    # 1. 기사 수집
    articles = collect_articles()

    # 2. Gemini 분석
    articles = analyze_all(articles)

    # 3. HTML 빌드
    html = build_html(articles)
    with open("report.html", "w", encoding="utf-8") as f:
        f.write(html)
    print("\n[OK] report.html 저장")

    # 4. 이메일 발송
    send_email(html)
    print(f"\n✅ 완료! 총 {len(articles)}건 분석·발송")

if __name__ == "__main__":
    main()