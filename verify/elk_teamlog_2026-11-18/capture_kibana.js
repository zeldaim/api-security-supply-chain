// Kibana 화면 캡처 + 녹화 (로컬 Chrome 을 playwright-core 로 조작)
//   npm install playwright-core@1.49.1 && npx playwright-core install ffmpeg
//   node capture_kibana.js <출력 폴더>
const { chromium } = require('playwright-core');
const path = require('path');

const OUT = process.argv[2] || 'shots';
const KB = 'http://localhost:5601';
const CHROME = 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const TIME = "time:(from:'2026-10-25T00:00:00.000Z',to:'2026-11-11T00:00:00.000Z')";
const enc = (s) => encodeURIComponent(s).replace(/'/g, '%27');

const esql = (q) => `${KB}/app/discover#/?_g=(${TIME})&_a=(query:(esql:'${enc(q)}'))`;
const kql = (dv, q, cols) =>
  `${KB}/app/discover#/?_g=(${TIME})&_a=(columns:!(${cols.join(',')}),dataSource:(dataViewId:'${dv}',type:dataView),query:(language:kuery,query:'${enc(q)}'))`;

const STEPS = [
  ['01_v1_guide_pipeline_failures',
   kql('shop-access-v1-notime', 'not api.classification:* and error.message:*', ['error.message', 'event.original']),
   '가이드 파이프라인(v1): 분류가 붙지 않은 줄 — 밀리초 시각에서 날짜 단계 실패'],
  ['02_v1_classification',
   esql('FROM shop-access-v1 | STATS lines = COUNT(*) BY api.classification | SORT lines DESC'),
   'v1 분류 결과 (시간 범위 안 — 실패한 줄은 @timestamp 가 없어 여기서 빠진다)'],
  ['03_v2_classification',
   esql('FROM shop-access-v2 | STATS lines = COUNT(*) BY api.classification | SORT lines DESC'),
   '고친 파이프라인(v2): 전 줄 분류, API 범위 밖은 non_api'],
  ['04_v2_shadow_success_endpoints',
   esql('FROM shop-access-v2 | WHERE api.classification == "shadow" AND http.response.status_code >= 200 AND http.response.status_code < 300 | STATS hits = COUNT(*), sources = COUNT_DISTINCT(source.ip) BY api.endpoint_key | SORT hits DESC | LIMIT 15'),
   'Shadow API 중 실제로 성공 응답(2xx)한 엔드포인트'],
  ['05_v2_shadow_events',
   kql('shop-access-v2', 'api.classification:shadow and http.response.status_code >= 200 and http.response.status_code < 300',
       ['source.ip', 'http.request.method', 'url.original', 'http.response.status_code', 'api.endpoint_key', 'api.classification']),
   'Shadow 성공 응답 이벤트 원문'],
];

(async () => {
  const browser = await chromium.launch({ executablePath: CHROME, headless: true });
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ko-KR',
    recordVideo: { dir: OUT, size: { width: 1440, height: 900 } } });
  const page = await ctx.newPage();
  await page.goto(`${KB}/app/home`, { waitUntil: 'networkidle', timeout: 120000 });
  for (const [name, url, note] of STEPS) {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 120000 });
    await page.waitForLoadState('networkidle', { timeout: 120000 }).catch(() => {});
    await page.waitForTimeout(6000);
    // 처음 뜨는 안내 팝업·투어 닫기
    for (const sel of ['button:has-text("Dismiss")', 'button:has-text("Close tour")', 'button:has-text("Skip")', 'button[aria-label="Close"]']) {
      const b = page.locator(sel).first();
      if (await b.isVisible().catch(() => false)) await b.click().catch(() => {});
    }
    await page.waitForTimeout(1500);
    for (const sel of ['button:has-text("Dismiss")', 'button:has-text("Got it")']) {
      const b = page.locator(sel).first();
      if (await b.isVisible().catch(() => false)) { await b.click().catch(() => {}); await page.waitForTimeout(800); }
    }
    await page.screenshot({ path: path.join(OUT, `${name}.png`) });
    console.log(`${name}.png — ${note}`);
  }
  const video = page.video();
  await ctx.close();
  await browser.close();
  if (video) console.log('video:', await video.path());
})();
