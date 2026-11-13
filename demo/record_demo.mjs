// Records a ~2.5 minute walkthrough of the live dashboard as a backup demo video.
// Usage (dashboard must already be running, e.g. `docker compose up`):  npm run record
// Options (env vars):  URL=http://localhost:8000   HEADED=1 (watch it happen)   SLOW=1.3 (slower pacing)
import { chromium } from 'playwright'
import fs from 'node:fs'
import path from 'node:path'

const URL = process.env.URL || 'http://localhost:8000'
const HEADED = process.env.HEADED === '1'
const SLOW = Number(process.env.SLOW || 1)
const OUT = path.resolve('out')
const wait = (s) => new Promise((r) => setTimeout(r, s * 1000 * SLOW))

fs.mkdirSync(OUT, { recursive: true })
const browser = await chromium.launch({ headless: !HEADED })
const context = await browser.newContext({
  viewport: { width: 1440, height: 810 },
  recordVideo: { dir: OUT, size: { width: 1440, height: 810 } },
})
const page = await context.newPage()

// 1. Known starting state: simulation stopped, so pressing play starts a fresh run.
try { await page.request.post(`${URL}/api/stop`) }
catch (e) { console.warn('Could not reach the dashboard at', URL, '-', e.message) }

await page.goto(URL)
await page.getByText('Live', { exact: true }).waitFor({ timeout: 30000 }).catch(() => console.warn('WARN: never saw "Live"'))

// 2. Overlay: caption bar (bottom, above the control dock, so it covers no buttons) + visible cursor.
await page.evaluate(() => {
  const cap = document.createElement('div')
  cap.id = '__cap'
  cap.style.cssText = 'position:fixed;left:50%;bottom:84px;transform:translateX(-50%);max-width:50%;padding:10px 20px;border-radius:12px;background:rgba(10,13,12,.9);border:1px solid rgba(126,224,180,.5);color:#fff;font:600 17px system-ui,sans-serif;z-index:99999;text-align:center;pointer-events:none'
  document.body.appendChild(cap)
  const cur = document.createElement('div')
  cur.style.cssText = 'position:fixed;width:18px;height:18px;border-radius:50%;background:rgba(255,116,102,.85);border:2px solid #fff;z-index:100000;pointer-events:none;left:-50px;top:-50px;transform:translate(-50%,-50%)'
  document.body.appendChild(cur)
  document.addEventListener('mousemove', (e) => { cur.style.left = e.clientX + 'px'; cur.style.top = e.clientY + 'px' }, true)
})
const caption = (t) => page.evaluate((t) => { document.getElementById('__cap').textContent = t }, t)

// A failed step is logged and skipped so one changed label never ruins the whole take.
async function step(label, fn) {
  try { await fn() } catch (e) { console.warn(`WARN step "${label}" failed:`, e.message.split('\n')[0]) }
}
async function click(locator) {
  const box = await locator.boundingBox({ timeout: 5000 })
  if (!box) throw new Error('no bounding box')
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 25 })
  await wait(0.3)
  await locator.click({ timeout: 5000 })
}
const waitIdle = () => page.locator('#loading').waitFor({ state: 'hidden', timeout: 60000 }).catch(() => {})

// ---- Scene 1: intro ----
await caption('QuantumShield Grid: post-quantum secure handshakes for Bengaluru EV chargers, solar inverters and batteries')
await wait(5)

// ---- Scene 2: start the live network ----
await step('play', async () => {
  await caption('Press play: real ML-KEM-768 / ML-DSA-65 handshakes between simulated devices and the gateway')
  await click(page.locator('#play'))
  await waitIdle()
})
await wait(8)

// ---- Scene 3: packet X-ray ----
await step('xray', async () => {
  await caption('Packet X-Ray: the latest handshake broken into its network packets')
  await click(page.locator('.tabs2 button[data-p=pXray]'))
})
await wait(6)

// ---- Scene 4: optimizations ----
for (const [label, msg] of [
  ['Certificate caching', 'Optimization 1: certificate caching. Returning devices send a fingerprint, not their certificates'],
  ['Chain-transmission optimization', 'Optimization 2: skip CA certificates the gateway already trusts'],
  ['Gateway-assisted validation', 'Optimization 3: gateway-assisted validation. All three combined'],
]) {
  await step(label, async () => {
    await caption(msg)
    await click(page.getByText(label, { exact: true }))
    await wait(1.5)
    await click(page.locator('#start'))
    await waitIdle()
  })
  await wait(7)
}

// ---- Scene 5: network presets ----
const presets = page.locator('#presets button')
const count = await presets.count().catch(() => 0)
for (const i of [1, 2, 0].filter((i) => i < count)) {
  await step(`preset ${i}`, async () => {
    const name = (await presets.nth(i).innerText()).trim()
    await caption(`Network preset: ${name}. Latency and retransmissions change with the link`)
    await click(presets.nth(i))
    await waitIdle()
  })
  await wait(6)
}

// ---- Scene 6: gateway failover ----
await step('crash', async () => { await caption('Gateway failure: crash the primary gateway'); await click(page.locator('#crash')) })
await wait(6)
await step('alerts', async () => { await click(page.locator('.tabs2 button[data-p=pAlerts]')) })
await wait(4)
await step('recover', async () => { await caption('The backup gateway takes over; recover the primary'); await click(page.locator('#recover')) })
await wait(5)

// ---- Scene 7: attacks ----
await step('attacks', async () => {
  await caption('Threat simulator: every attack runs for real against the current settings')
  await click(page.locator('#openThreat'))
})
await wait(3)
await step('run all', async () => { await click(page.locator('#runAll')) })
await wait(10)
await step('close threats', async () => { await click(page.locator('#closeThreat')) })
await wait(2)

// ---- Scene 8: experiment lab ----
await step('lab', async () => {
  await caption('Experiment Lab: charts generated from the benchmark CSVs')
  await click(page.locator('#navLab'))
})
await wait(10)

// ---- Outro ----
await step('outro', async () => { await click(page.locator('#navLive')) })
await caption('Backup recording. Run live with: docker compose up --build')
await wait(4)

const video = page.video()
await context.close() // flushes the video to disk
await browser.close()
const target = path.join(OUT, 'quantumshield-demo.webm')
fs.renameSync(await video.path(), target)
console.log('\nSaved', target)
console.log('Convert to MP4 for slides/WhatsApp:  ffmpeg -i out/quantumshield-demo.webm -c:v libx264 -pix_fmt yuv420p out/quantumshield-demo.mp4')