// 실시간 대시보드 녹화 (playwright-core, 로컬 Chrome) — node record_live.js <출력 폴더> <초>
const { chromium } = require('playwright-core');
const OUT = process.argv[2] || 'video'; const SEC = +(process.argv[3] || 600);
(async () => {
  const b = await chromium.launch({ executablePath: 'C:/Program Files/Google/Chrome/Application/chrome.exe', headless: true });
  const ctx = await b.newContext({ viewport: { width: 1600, height: 1000 }, recordVideo: { dir: OUT, size: { width: 1600, height: 1000 } } });
  const p = await ctx.newPage();
  await p.goto('http://localhost:3001/d/live-demo?orgId=1&refresh=5s&from=now-15m&to=now&kiosk', { waitUntil: 'load' });
  const t0 = Date.now();
  while (Date.now() - t0 < SEC * 1000) {
    const el = (Date.now() - t0) / 1000;
    // 화면 아래 표도 보이게 30초마다 천천히 내렸다 올린다
    if (Math.floor(el) % 60 === 30) { await p.mouse.wheel(0, 700); await p.waitForTimeout(8000); await p.mouse.wheel(0, -700); }
    await p.waitForTimeout(1000);
  }
  await ctx.close(); await b.close(); console.log('녹화 끝');
})();
