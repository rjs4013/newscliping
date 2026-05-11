"""
Sparrow Security Intelligence Crawler
매주 월요일 SAST/DAST/SCA 경쟁사 최신 동향을 크롤링하여 이메일 발송
"""

import os
import smtplib
import feedparser
import requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone
from bs4 import BeautifulSoup

# ──────────────────────────────────────────────
# 경쟁사 RSS / 블로그 / 릴리즈 피드 목록
# ──────────────────────────────────────────────
COMPETITORS = {
    "SAST": [
        {
            "name": "Checkmarx",
            "url": "https://checkmarx.com/blog/feed/",
            "type": "rss",
            "tag": "SAST"
        },
        {
            "name": "Veracode",
            "url": "https://www.veracode.com/blog/feed",
            "type": "rss",
            "tag": "SAST"
        },
        {
            "name": "Semgrep",
            "url": "https://semgrep.dev/blog/rss.xml",
            "type": "rss",
            "tag": "SAST"
        },
        {
            "name": "SonarQube (Sonar)",
            "url": "https://www.sonarsource.com/blog/rss.xml",
            "type": "rss",
            "tag": "SAST"
        },
        {
            "name": "Fortify (OpenText)",
            "url": "https://www.microfocus.com/en-us/cyberres/rss",
            "type": "rss",
            "tag": "SAST"
        },
        {
            "name": "CodeQL (GitHub)",
            "url": "https://github.blog/feed/",
            "type": "rss",
            "tag": "SAST",
            "keyword": "CodeQL"
        },
    ],
    "DAST": [
        {
            "name": "Invicti (Netsparker)",
            "url": "https://www.invicti.com/blog/feed/",
            "type": "rss",
            "tag": "DAST"
        },
        {
            "name": "PortSwigger (Burp Suite)",
            "url": "https://portswigger.net/blog/rss",
            "type": "rss",
            "tag": "DAST"
        },
        {
            "name": "Bright Security (NeuraLegion)",
            "url": "https://brightsec.com/blog/feed/",
            "type": "rss",
            "tag": "DAST"
        },
        {
            "name": "OWASP ZAP",
            "url": "https://www.zaproxy.org/blog/index.xml",
            "type": "rss",
            "tag": "DAST"
        },
        {
            "name": "Rapid7 (AppSpider)",
            "url": "https://www.rapid7.com/blog/rss.xml/",
            "type": "rss",
            "tag": "DAST"
        },
    ],
    "SCA": [
        {
            "name": "Snyk",
            "url": "https://snyk.io/blog/feed/",
            "type": "rss",
            "tag": "SCA"
        },
        {
            "name": "Mend.io (WhiteSource)",
            "url": "https://www.mend.io/blog/feed/",
            "type": "rss",
            "tag": "SCA"
        },
        {
            "name": "Black Duck (Synopsys)",
            "url": "https://www.synopsys.com/blogs/software-security/feed/",
            "type": "rss",
            "tag": "SCA"
        },
        {
            "name": "FOSSA",
            "url": "https://fossa.com/blog/feed/",
            "type": "rss",
            "tag": "SCA"
        },
        {
            "name": "Sonatype",
            "url": "https://blog.sonatype.com/rss.xml",
            "type": "rss",
            "tag": "SCA"
        },
        {
            "name": "Dependabot (GitHub)",
            "url": "https://github.blog/feed/",
            "type": "rss",
            "tag": "SCA",
            "keyword": "Dependabot"
        },
    ],
}

# 최근 7일치만 수집
DAYS_BACK = 7
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SparrowIntelBot/1.0)"}


def fetch_rss_items(source: dict, cutoff: datetime) -> list[dict]:
    """RSS 피드에서 최근 항목 수집"""
    items = []
    try:
        feed = feedparser.parse(source["url"])
        keyword = source.get("keyword", "").lower()

        for entry in feed.entries:
            # 날짜 파싱
            published = None
            if hasattr(entry, "published_parsed") and entry.published_parsed:
                published = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
            elif hasattr(entry, "updated_parsed") and entry.updated_parsed:
                published = datetime(*entry.updated_parsed[:6], tzinfo=timezone.utc)

            if published and published < cutoff:
                continue

            title = entry.get("title", "No title")
            link = entry.get("link", "#")
            summary = entry.get("summary", "")

            # BeautifulSoup으로 HTML 태그 제거
            clean_summary = BeautifulSoup(summary, "lxml").get_text()[:200]

            # 키워드 필터 (e.g. GitHub 블로그에서 CodeQL 관련만)
            if keyword and keyword not in title.lower() and keyword not in clean_summary.lower():
                continue

            items.append({
                "title": title,
                "link": link,
                "summary": clean_summary,
                "published": published.strftime("%Y-%m-%d") if published else "날짜 미상",
                "source": source["name"],
                "tag": source["tag"],
            })
    except Exception as e:
        print(f"[WARN] {source['name']} 피드 수집 실패: {e}")

    return items


def collect_all_items() -> dict:
    """모든 경쟁사 피드 수집"""
    cutoff = datetime.now(timezone.utc) - timedelta(days=DAYS_BACK)
    result = {category: [] for category in COMPETITORS}

    for category, sources in COMPETITORS.items():
        for source in sources:
            items = fetch_rss_items(source, cutoff)
            result[category].extend(items)
            print(f"[OK] {source['name']}: {len(items)}개 항목")

    return result


# ──────────────────────────────────────────────
# HTML 이메일 템플릿
# ──────────────────────────────────────────────
CATEGORY_COLORS = {
    "SAST": "#3B82F6",
    "DAST": "#10B981",
    "SCA":  "#F59E0B",
}

CATEGORY_DESC = {
    "SAST": "정적 애플리케이션 보안 테스트",
    "DAST": "동적 애플리케이션 보안 테스트",
    "SCA":  "소프트웨어 구성 분석",
}


def build_html(data: dict) -> str:
    today = datetime.now().strftime("%Y년 %m월 %d일")
    week_range = (datetime.now() - timedelta(days=7)).strftime("%m/%d") + " ~ " + datetime.now().strftime("%m/%d")

    total = sum(len(v) for v in data.values())

    categories_html = ""
    for category, items in data.items():
        color = CATEGORY_COLORS[category]
        desc = CATEGORY_DESC[category]

        if not items:
            items_html = f"""
            <div style="text-align:center;padding:32px;color:#9CA3AF;">
              이번 주 새로운 소식이 없습니다.
            </div>"""
        else:
            cards = ""
            for item in items[:15]:  # 카테고리당 최대 15개
                cards += f"""
                <div style="border:1px solid #E5E7EB;border-radius:8px;padding:16px;margin-bottom:12px;background:#FAFAFA;">
                  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">
                    <span style="font-size:11px;font-weight:600;color:{color};background:{color}18;padding:2px 8px;border-radius:999px;">{item['source']}</span>
                    <span style="font-size:11px;color:#9CA3AF;">{item['published']}</span>
                  </div>
                  <a href="{item['link']}" style="font-size:14px;font-weight:600;color:#111827;text-decoration:none;line-height:1.4;display:block;margin-bottom:6px;">{item['title']}</a>
                  <p style="font-size:13px;color:#6B7280;margin:0;line-height:1.5;">{item['summary']}...</p>
                </div>"""
            items_html = cards

        categories_html += f"""
        <div style="margin-bottom:40px;">
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;padding-bottom:12px;border-bottom:2px solid {color};">
            <div style="width:4px;height:28px;background:{color};border-radius:2px;"></div>
            <div>
              <h2 style="margin:0;font-size:18px;font-weight:700;color:#111827;">{category}</h2>
              <p style="margin:0;font-size:12px;color:#9CA3AF;">{desc} · {len(items)}개 소식</p>
            </div>
          </div>
          {items_html}
        </div>"""

    return f"""
<!DOCTYPE html>
<html lang="ko">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Sparrow Security Intelligence</title></head>
<body style="margin:0;padding:0;background:#F3F4F6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <div style="max-width:680px;margin:0 auto;padding:24px 16px;">

    <!-- Header -->
    <div style="background:linear-gradient(135deg,#0F172A 0%,#1E3A5F 100%);border-radius:12px;padding:32px;margin-bottom:24px;text-align:center;">
      <div style="font-size:28px;margin-bottom:8px;">🦅</div>
      <h1 style="margin:0 0 4px;font-size:22px;font-weight:700;color:#FFFFFF;letter-spacing:-0.3px;">Sparrow Security Intelligence</h1>
      <p style="margin:0;font-size:13px;color:#93C5FD;">SAST · DAST · SCA 경쟁사 주간 동향</p>
      <div style="margin-top:16px;display:inline-block;background:rgba(255,255,255,0.1);border-radius:999px;padding:6px 16px;">
        <span style="font-size:12px;color:#E2E8F0;">📅 {today} · {week_range} 수집 · 총 {total}건</span>
      </div>
    </div>

    <!-- Summary Cards -->
    <div style="display:table;width:100%;margin-bottom:24px;border-collapse:separate;border-spacing:0;">
      <div style="display:table-row;">
        {"".join(f'''
        <div style="display:table-cell;width:33%;padding:4px;">
          <div style="background:#FFFFFF;border-radius:8px;padding:16px;text-align:center;border-top:3px solid {CATEGORY_COLORS[cat]};">
            <div style="font-size:20px;font-weight:700;color:{CATEGORY_COLORS[cat]};">{len(data[cat])}</div>
            <div style="font-size:11px;color:#6B7280;font-weight:600;">{cat}</div>
          </div>
        </div>''' for cat in ["SAST","DAST","SCA"])}
      </div>
    </div>

    <!-- Main Content -->
    <div style="background:#FFFFFF;border-radius:12px;padding:28px;">
      {categories_html}
    </div>

    <!-- Footer -->
    <div style="text-align:center;padding:20px;color:#9CA3AF;font-size:11px;">
      <p style="margin:0;">Sparrow Intelligence Bot · 매주 월요일 오전 9시 자동 발송</p>
      <p style="margin:4px 0 0;">GitHub Actions로 구동 · 데이터 수집 기간: {week_range}</p>
    </div>
  </div>
</body>
</html>"""


def send_email(html_body: str):
    """이메일 발송"""
    smtp_host = os.environ["SMTP_HOST"]
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ["SMTP_USER"]
    smtp_pass = os.environ["SMTP_PASS"]
    email_from = os.environ["EMAIL_FROM"]
    email_to = os.environ["EMAIL_TO"]

    today = datetime.now().strftime("%Y.%m.%d")
    subject = f"[Sparrow Intel] SAST/DAST/SCA 경쟁사 주간 동향 {today}"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = email_from
    msg["To"] = email_to
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.ehlo()
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(email_from, email_to.split(","), msg.as_string())

    print(f"[OK] 이메일 발송 완료 → {email_to}")


def main():
    print("=" * 50)
    print("Sparrow Security Intelligence Crawler 시작")
    print("=" * 50)

    # 1. 크롤링
    data = collect_all_items()

    # 2. HTML 리포트 생성
    html = build_html(data)

    # 3. 파일 저장 (GitHub Actions artifact용)
    with open("report.html", "w", encoding="utf-8") as f:
        f.write(html)
    print("[OK] report.html 저장 완료")

    # 4. 이메일 발송
    send_email(html)

    total = sum(len(v) for v in data.values())
    print(f"\n✅ 완료! 총 {total}개 항목 수집 및 발송")


if __name__ == "__main__":
    main()
