// Grafana 대시보드 캡처 (로컬 Chrome 을 playwright-core 로 조작)
// Grafana 는 실시간 연결(websocket)이 계속 열려 있어 networkidle 을 기다리면 끝나지 않는다 → load 후 9초 대기
//   npm install playwright-core@1.49.1 && node capture_grafana.js <출력 폴더>
const { chromium } = require('playwright-core');
const path = require('path');
const OUT = process.argv[2] || 'screenshots';
const G = 'http://localhost:3000/d/dvra-detection';
const CHROME = 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const T = 'from=2026-11-18T07:35:00.000Z&to=2026-11-18T08:55:00.000Z';
const SHOTS = [
  ['01_dashboard_full', `${G}?orgId=1&${T}&kiosk`, false],
  ['02_attack_window', `${G}?orgId=1&from=2026-11-18T08:30:00.000Z&to=2026-11-18T08:40:00.000Z&kiosk`, false],
];
(async () => {
  const b = await chromium.launch({ executablePath: CHROME, headless: true });
  const p = await b.newPage({ viewport: { width: 1600, height: 1450 }, deviceScaleFactor: 1 });
  for (const [name, url, full] of SHOTS) {
    await p.goto(url, { waitUntil: 'load' });
    await p.waitForTimeout(20000);
    await p.screenshot({ path: path.join(OUT, `${name}.png`), fullPage: full });
    console.log('저장', name);
  }
  await b.close();
})();
