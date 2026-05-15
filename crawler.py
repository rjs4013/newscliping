"""
Sparrow Security Intelligence - 경쟁사·시장 월간 동향
흐름:
  1. Google News RSS → 수집 + 제목 유사도 중복 제거
  2. Gemini API 3회 (SAST/DAST/SCA별 1회) → 카테고리 영업 인사이트 생성
  3. 컴팩트 HTML 이메일 발송
"""

import os, re, smtplib, time
import feedparser, requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

DAYS_BACK = int(os.environ.get("DAYS_BACK", "30"))
GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_URL   = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept-Language": "ko-KR,ko;q=0.9",
}

# ────────────────────────────────────────────────────────
# 검색 쿼리
# ────────────────────────────────────────────────────────
SEARCH_QUERIES = [
    {"q": "Checkmarx OR 체크막스",          "category": "SAST", "company": "Checkmarx"},
    {"q": "Fortify OR 포티파이 보안",        "category": "SAST", "company": "Fortify"},
    {"q": "에스에스알 OR SSR CODE-RAY 보안", "category": "SAST", "company": "SSR"},
    {"q": "AppScan OR 앱스캔 보안",          "category": "DAST", "company": "AppScan"},
    {"q": "나일소프트 OR SecuGuard",         "category": "DAST", "company": "나일소프트"},
    {"q": "Theori OR Xint 보안",            "category": "DAST", "company": "Xint (Theori)"},
    {"q": "Black Duck OR 블랙덕 보안",       "category": "SCA",  "company": "Black Duck"},
    {"q": "래브라도랩스 OR Labrador Labs",   "category": "SCA",  "company": "래브라도랩스"},
    {"q": "레드팬소프트 OR XSCAN SBOM",     "category": "SCA",  "company": "레드팬소프트"},
    {"q": "SAST 정적분석 보안",              "category": "SAST", "company": None},
    {"q": "DAST 웹취약점 동적분석",          "category": "DAST", "company": None},
    {"q": "SCA 오픈소스 취약점",             "category": "SCA",  "company": None},
    {"q": "SBOM 공급망보안",                "category": "SCA",  "company": None},
    {"q": "시큐어코딩 소프트웨어 보안",       "category": "SAST", "company": None},
    {"q": "DevSecOps 보안 자동화",          "category": "SAST", "company": None},
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
CATEGORY_DESC   = {"SAST": "정적 분석", "DAST": "동적 분석", "SCA": "공급망 / 오픈소스"}

CAT_CONTEXT = {
    "SAST": "스패로우 SAST는 소스코드 정적 분석 도구로, 시큐어코딩 진단·CI/CD 연동·공공 및 금융 규정 대응을 강점으로 합니다.",
    "DAST": "스패로우 DAST는 웹/API 동적 취약점 진단 도구로, 운영 환경 블랙박스 점검·자동화 스캐닝을 강점으로 합니다.",
    "SCA":  "스패로우 SCA는 오픈소스 구성 분석 도구로, SBOM 생성·라이선스 관리·공급망 보안 대응을 강점으로 합니다.",
}

period_label = "주간" if DAYS_BACK <= 7 else "월간"

# ────────────────────────────────────────────────────────
# 유틸
# ────────────────────────────────────────────────────────

def cutoff_dt():
    return datetime.now(timezone.utc) - timedelta(days=DAYS_BACK)

def is_korean(text: str) -> bool:
    return len(re.findall(r"[가-힣]", text)) >= 4

def normalize_title(title: str) -> str:
    """중복 탐지용 제목 정규화
    - 끝의 '- 매체명' 패턴 제거 (반복 적용으로 여러 단계 제거)
    - 특수문자·공백 제거 후 소문자화
    """
    t = title
    for _ in range(3):
        t2 = re.sub(r"\s*[-–―|·]\s*\S{2,15}\s*$", "", t).strip()
        if t2 == t:
            break
        t = t2
    return re.sub(r"[^\w가-힣]", "", t).lower()

def title_similarity(a: str, b: str) -> float:
    """두 정규화 제목의 공통 바이그램 비율 (0~1)"""
    def bigrams(s):
        return set(s[i:i+2] for i in range(len(s)-1)) if len(s) >= 2 else set(s)
    ba, bb = bigrams(a), bigrams(b)
    if not ba or not bb:
        return 1.0 if a == b else 0.0
    return len(ba & bb) / max(len(ba), len(bb))


# ────────────────────────────────────────────────────────
# 1단계: Google News RSS 수집
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
            title = entry.get("title", "").strip()
            if not is_korean(title):
                continue
            items.append({
                "title":     title,
                "link":      entry.get("link", "#"),
                "source":    entry.get("source", {}).get("title", ""),
                "published": pub.strftime("%Y-%m-%d") if pub else "날짜 미상",
                "category":  qcfg["category"],
                "company":   qcfg["company"],
            })
    except Exception as e:
        print(f"  [WARN] '{qcfg['q'][:25]}': {e}")
    return items


def collect_articles() -> list[dict]:
    all_items  = []
    seen_links = set()
    seen_norms = []   # 정규화 제목 리스트 (유사도 비교용)

    print("\n[Google News RSS] 수집 중...")
    for qcfg in SEARCH_QUERIES:
        items = fetch_google_news(qcfg)
        added = 0
        for item in items:
            link = item["link"]
            norm = normalize_title(item["title"])

            # 1) URL 중복
            if link in seen_links:
                continue
            # 2) 제목 유사도 중복 (바이그램 70% 이상 겹치면 동일 기사로 판단)
            is_dup = any(title_similarity(norm, s) >= 0.7 for s in seen_norms)
            if is_dup:
                continue

            seen_links.add(link)
            seen_norms.append(norm)
            all_items.append(item)
            added += 1
        print(f"  '{qcfg['q'][:28]}': {added}건")
        time.sleep(0.5)

    all_items.sort(key=lambda x: x["published"], reverse=True)
    print(f"\n  → 총 {len(all_items)}건 (중복 제거 후)")
    return all_items


# ────────────────────────────────────────────────────────
# 2단계: Gemini — 카테고리별 영업 인사이트 (총 3회 호출)
# ────────────────────────────────────────────────────────

def build_insight_prompt(cat: str, articles: list[dict]) -> str:
    headlines = "\n".join(
        f"- {a['title']} ({a.get('company') or '시장동향'})"
        for a in articles[:30]   # 최대 30개 헤드라인
    )
    return (
        f"당신은 스패로우(보안 솔루션 기업)의 영업전략 분석가입니다.\n"
        f"스패로우 제품 정보: {CAT_CONTEXT[cat]}\n\n"
        f"아래는 이번 달 '{cat}' 관련 경쟁사·시장 뉴스 헤드라인입니다:\n"
        f"{headlines}\n\n"
        f"위 기사들을 종합하여 스패로우 {cat} 영업팀이 활용할 수 있는 인사이트를 작성하세요.\n"
        f"형식:\n"
        f"1. 이달의 핵심 흐름 (2~3줄): 시장에서 무슨 일이 일어나고 있는지\n"
        f"2. 경쟁사 주요 움직임 (bullet 2~3개): 경쟁사가 왜 이런 행보를 보이는지 해석 포함\n"
        f"3. 스패로우 영업 활용 포인트 (bullet 2~3개): 위 상황을 어떤 고객에게 어떻게 연결할지\n"
        f"각 항목은 완성된 문장으로 끊기지 않게 작성하세요.\n"
        f"마크다운(**굵게**, *기울임* 등) 없이 일반 텍스트로만 작성하세요."
    )


def get_category_insight(cat: str, articles: list[dict], api_key: str) -> str:
    if not articles:
        return ""
    prompt = build_insight_prompt(cat, articles)
    for attempt in range(3):
        try:
            resp = requests.post(
                f"{GEMINI_URL}?key={api_key}",
                headers={"Content-Type": "application/json"},
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"temperature": 0.3, "maxOutputTokens": 8192},
                },
                timeout=30,
            )
            if resp.status_code == 429:
                print(f"  [429] {cat} 재시도 대기...")
                time.sleep(30 * (attempt + 1))
                continue
            resp.raise_for_status()
            return resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
        except Exception as e:
            print(f"  [WARN] {cat} 인사이트 실패 (시도 {attempt+1}): {e}")
            time.sleep(5)
    return ""


def generate_insights(by_cat: dict, api_key: str) -> dict:
    """카테고리별 영업 인사이트 생성 (Gemini 3회 호출)"""
    insights = {}
    if not api_key:
        print("[INFO] GEMINI_API_KEY 없음 → 인사이트 건너뜀")
        return insights

    print("\n[Gemini 인사이트] 카테고리별 분석 중...")
    for cat in ["SAST", "DAST", "SCA"]:
        articles = [a for items in by_cat.get(cat, {}).values() for a in items]
        if not articles:
            continue
        print(f"  {cat} ({len(articles)}건 헤드라인 전송)...")
        insights[cat] = get_category_insight(cat, articles, api_key)
        print(f"  {cat} 완료")
        time.sleep(5)  # 호출 간격

    return insights


# ────────────────────────────────────────────────────────
# 3단계: HTML 이메일
# ────────────────────────────────────────────────────────

def article_row(item: dict) -> str:
    cat   = item["category"]
    color = CATEGORY_COLORS.get(cat, "#6B7280")
    comp  = item.get("company") or ""
    badge = COMPANY_META.get(comp, {}).get("badge", "")
    dot   = f'<span style="display:inline-block;width:6px;height:6px;background:{color};border-radius:50%;margin-right:5px;vertical-align:middle;flex-shrink:0;"></span>'
    badge_html = f'<span style="margin-right:3px;font-size:11px;">{badge}</span>' if badge else ""

    return f"""<tr>
      <td style="padding:6px 4px;border-bottom:1px solid #F1F5F9;vertical-align:top;">
        <div style="display:flex;align-items:flex-start;gap:2px;">
          {dot}{badge_html}<a href="{item['link']}" style="font-size:12px;font-weight:600;color:#1E293B;text-decoration:none;line-height:1.4;">{item['title']}</a>
        </div>
        <div style="font-size:10px;color:#94A3B8;margin-top:2px;padding-left:14px;">{item['source']} · {item['published']}</div>
      </td>
    </tr>"""


def md_to_html(text: str) -> str:
    """마크다운 인라인 요소 → HTML 변환"""
    # **굵게** → <strong>
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    # *기울임* → <em>
    text = re.sub(r"\*(.+?)\*", r"<em>\1</em>", text)
    # ## 헤더 제거 (텍스트만 남김)
    text = re.sub(r"^#{1,3}\s+", "", text)
    return text

def format_insight_html(insight_text: str) -> str:
    """Gemini 텍스트를 HTML로 변환
    - 번호 항목 (1. 2. 3.) → 소제목
    - **전체가 bold** 인 줄 → 소제목 (Gemini가 번호 없이 bold 헤더 쓸 때)
    - bullet (- •) → 들여쓰기 항목
    - 나머지 → 본문
    """
    if not insight_text:
        return ""
    lines = insight_text.strip().split("\n")
    html_lines = []
    for line in lines:
        line = line.strip()
        if not line:
            html_lines.append('<div style="height:4px;"></div>')
            continue

        is_numbered = bool(re.match(r"^[1-9]\.", line))
        is_bullet   = line.startswith("-") or line.startswith("•")
        # **전체가 bold** 패턴: 줄 전체가 **...** 이거나 **...**로 시작
        is_bold_header = bool(re.match(r"^\*\*.+\*\*", line))

        line_html = md_to_html(line)

        if is_numbered or is_bold_header:
            html_lines.append(
                f'<div style="font-size:12px;font-weight:700;color:#1E40AF;'
                f'margin:10px 0 4px;">{line_html}</div>'
            )
        elif is_bullet:
            body = md_to_html(re.sub(r"^[-•]\s*", "", line))
            html_lines.append(
                f'<div style="font-size:12px;color:#374151;padding-left:10px;'
                f'margin-bottom:4px;line-height:1.6;">· {body}</div>'
            )
        else:
            html_lines.append(
                f'<div style="font-size:12px;color:#374151;'
                f'margin-bottom:4px;line-height:1.6;">{line_html}</div>'
            )
    return "\n".join(html_lines)


def build_html(articles: list[dict], insights: dict) -> str:
    now         = datetime.now()
    month_label = now.strftime("%Y년 %m월")
    month_start = (now - timedelta(days=30)).strftime("%m/%d")
    month_end   = now.strftime("%m/%d")
    total       = len(articles)

    # 카테고리 → 회사 → 기사 목록
    by_cat: dict[str, dict[str, list]] = {"SAST": {}, "DAST": {}, "SCA": {}}
    for item in articles:
        cat  = item.get("category", "SAST")
        comp = item.get("company") or "기타"
        if cat in by_cat:
            by_cat[cat].setdefault(comp, []).append(item)

    # 요약 카드
    summary_cells = "".join(f"""
      <td style="width:33%;padding:4px;">
        <div style="background:#FFF;border-radius:8px;padding:12px;text-align:center;border-top:3px solid {CATEGORY_COLORS[c]};">
          <div style="font-size:20px;font-weight:700;color:{CATEGORY_COLORS[c]};">{len([a for a in articles if a['category']==c])}</div>
          <div style="font-size:11px;color:#6B7280;font-weight:600;">{c}</div>
          <div style="font-size:10px;color:#9CA3AF;">{CATEGORY_DESC[c]}</div>
        </div>
      </td>""" for c in ["SAST", "DAST", "SCA"])

    # 카테고리별 섹션
    cat_sections = ""
    for cat, companies in by_cat.items():
        if not companies:
            continue
        color     = CATEGORY_COLORS[cat]
        cat_total = sum(len(v) for v in companies.values())

        # ── 영업 인사이트 박스 ──
        insight_html = ""
        if insights.get(cat):
            insight_html = f"""
            <div style="background:#EFF6FF;border:1px solid #BFDBFE;border-radius:8px;padding:12px 14px;margin-bottom:16px;">
              <div style="font-size:12px;font-weight:700;color:#1E40AF;margin-bottom:6px;">💡 영업 인사이트</div>
              {format_insight_html(insights[cat])}
            </div>"""

        # ── 회사별 기사 테이블 ──
        company_blocks = ""
        for comp, items in sorted(companies.items()):
            meta    = COMPANY_META.get(comp, {"type": "", "badge": "📰"})
            badge   = meta["badge"]
            ctype   = meta["type"]
            c_color = "#6366F1" if ctype == "국내" else "#64748B"
            type_badge = (
                f'<span style="font-size:9px;color:{c_color};border:1px solid {c_color};'
                f'padding:0 4px;border-radius:3px;margin-left:4px;">{ctype}</span>'
            ) if ctype else ""
            rows = "".join(article_row(a) for a in items[:8])
            company_blocks += f"""
            <div style="margin-bottom:14px;">
              <div style="font-size:12px;font-weight:700;color:#374151;padding:4px 0;
                          border-bottom:1px solid #E5E7EB;margin-bottom:2px;">
                {badge} {comp}{type_badge}
                <span style="font-weight:400;color:#9CA3AF;font-size:10px;float:right;">{len(items)}건</span>
              </div>
              <table style="width:100%;border-collapse:collapse;">{rows}</table>
            </div>"""

        cat_sections += f"""
        <div style="margin-bottom:28px;">
          <div style="display:flex;align-items:center;gap:8px;padding-bottom:8px;
                      border-bottom:2px solid {color};margin-bottom:14px;">
            <div style="width:3px;height:20px;background:{color};border-radius:2px;"></div>
            <span style="font-size:15px;font-weight:700;color:#111827;">{cat}</span>
            <span style="font-size:11px;color:#9CA3AF;">{CATEGORY_DESC[cat]} · {cat_total}건</span>
          </div>
          {insight_html}
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
    <p style="margin:0 0 10px;font-size:11px;color:#93C5FD;">경쟁사 · 시장 {period_label} 동향</p>
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
    Sparrow Intelligence Bot · 매월 1일 오전 9시 자동 발송 · Google News + Gemini
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
    subject = f"[Sparrow Intel] 경쟁사·시장 {period_label} 동향 {month_label}"
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

    # 1. 수집
    articles = collect_articles()

    # 카테고리 → 회사 그룹 (인사이트 생성에 전달)
    by_cat: dict[str, dict[str, list]] = {"SAST": {}, "DAST": {}, "SCA": {}}
    for item in articles:
        cat  = item.get("category", "SAST")
        comp = item.get("company") or "기타"
        if cat in by_cat:
            by_cat[cat].setdefault(comp, []).append(item)

    # 2. Gemini 인사이트 (3회)
    api_key  = os.environ.get("GEMINI_API_KEY", "")
    insights = generate_insights(by_cat, api_key)

    # 3. HTML 빌드
    html = build_html(articles, insights)
    with open("report.html", "w", encoding="utf-8") as f:
        f.write(html)
    print("\n[OK] report.html 저장")

    # 4. 발송
    send_email(html)
    print(f"\n✅ 완료! 총 {len(articles)}건")

if __name__ == "__main__":
    main()