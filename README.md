# 🦅 Sparrow Security Intelligence

SAST / DAST / SCA 경쟁사 주간·월간 동향을 자동으로 수집하여 이메일로 발송하는 GitHub Actions 봇입니다.

## 📋 수집 대상

| 카테고리 | 경쟁사 |
|---|---|
| **SAST** | Checkmarx,  Fortify, 트리니티소프트 |
| **DAST** | AppScan, 나일소프트, Xint |
| **SCA** | BlackDuck, 래브라도랩스, 레드팬소프트 |
| **AI** | Xint, 엑스팩AI, Mitos(Anthropic) |

## 🚀 설정 방법

### 1단계: 저장소 생성

```bash
# GitHub에서 새 private 저장소 생성 후
git clone https://github.com/<your-org>/sparrow-intel.git
cd sparrow-intel

# 파일 복사
cp crawler.py .
cp -r .github .

git add .
git commit -m "init: sparrow security intelligence bot"
git push
```

### 2단계: GitHub Secrets 등록

저장소 → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**

| Secret 이름 | 값 예시 | 설명 |
|---|---|---|
| `SMTP_HOST` | `smtp.gmail.com` | SMTP 서버 주소 |
| `SMTP_PORT` | `587` | SMTP 포트 (보통 587) |
| `SMTP_USER` | `your@gmail.com` | 발신 이메일 계정 |
| `SMTP_PASS` | `xxxx xxxx xxxx xxxx` | 앱 비밀번호 |
| `EMAIL_FROM` | `your@gmail.com` | 발신자 표시 이메일 |
| `EMAIL_TO` | `team@company.com` | 수신 이메일 (여러 개: 쉼표 구분) |

### 3단계: Gmail 앱 비밀번호 발급 (Gmail 사용 시)

1. Google 계정 → **보안** → **2단계 인증** 활성화
2. **앱 비밀번호** → 앱: `메일`, 기기: `기타` → 생성
3. 생성된 16자리 비밀번호를 `SMTP_PASS`에 입력

### 4단계: 테스트 실행

저장소 → **Actions** → **Security Intelligence Weekly Report** → **Run workflow**

## ⏰ 실행 스케줄

```
매주 월요일 오전 9시 (한국시간, KST)
```

cron 표현식: `0 0 * * 1` (UTC 기준)

## 📦 결과물

- **이메일**: 매주 월요일 자동 발송
- **HTML 파일**: Actions → 해당 실행 → Artifacts에서 `weekly-report-N` 다운로드 가능 (90일 보관)

## 🔧 커스터마이징

### 경쟁사 추가/제거

`crawler.py`의 `COMPETITORS` 딕셔너리에서 수정:

```python
{
    "name": "새 경쟁사",
    "url": "https://example.com/blog/feed/",
    "type": "rss",
    "tag": "SAST"  # SAST / DAST / SCA
},
```

### 수집 기간 변경

```python
DAYS_BACK = 7  # 기본 7일, 원하는 일수로 변경
```

### 스케줄 변경

`.github/workflows/security-intel.yml`에서:

```yaml
- cron: '0 0 * * 1'  # 매주 월요일 09:00 KST
- cron: '0 0 * * 1,4'  # 월·목 두 번
- cron: '0 0 1 * *'  # 매월 1일
```

## ❓ 문제 해결

| 증상 | 원인 | 해결 |
|---|---|---|
| 이메일 미수신 | Secrets 설정 오류 | Actions 로그 확인 |
| 수집 항목 0개 | RSS URL 변경 | 경쟁사 RSS URL 직접 확인 후 수정 |
| Gmail 인증 실패 | 앱 비밀번호 미설정 | 2단계 인증 후 앱 비밀번호 재발급 |
