import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { spawn, spawnSync } from 'node:child_process'
import { dataPath, getConfig } from './config.js'
import { logger } from '../host/index.js'
import { proxyForHost } from './adapters/common.js'
import { assertSafeRequestUrl } from './url-security.js'
import {
  POINTER_WINDOWS,
  commandLineUsesProfile,
  isOrphanProcess,
  killProcessTree,
  listProcesses,
  nativeClick,
  nativeMouseLocation,
  nativePointerUnavailable,
  nativeWindowGeometry,
  pointerDisplayFor
} from './native.js'

// 真实指针相关的平台差异都在 models/native.js，这里只保留原有导出名以免调用方跟着改
export { pointerDisplayFor }

/**
 * 浏览器工具：用于过阿里云 WAF（AnyRouter 系）、Cloudflare Turnstile 与 NewAPI POW 挑战。
 * puppeteer 惰性加载（复用 Yunzai 根目录依赖，缺失时仅浏览器功能不可用，不影响插件加载）。
 *
 * 无头实例按代理模式复用；可见实例按站点、代理和浏览器内核隔离，并使用持久用户档案。
 * 这样直连站与代理站可同时进行，任何站点都不会被迫用错的网络模式访问
 * （带账密代理的认证走 page.authenticate，chromium 的 --proxy-server 不接受账密）。
 */

// Map<poolKey, { instance, activeTasks, idleTimer, launching, interactive }>
const pools = new Map()

function getPool(poolKey, interactive = false) {
  if (!pools.has(poolKey)) {
    pools.set(poolKey, { instance: null, activeTasks: 0, idleTimer: null, launching: null, interactive })
  }
  return pools.get(poolKey)
}

const PROFILE_SCHEMA_VERSION = 'turnstile-system-browser-v2'

function profileFingerprint(profileKey, proxyServer = '', executablePath = '') {
  return crypto.createHash('sha256')
    .update(`${PROFILE_SCHEMA_VERSION}\n${String(profileKey).toLowerCase()}\n${proxyServer || 'direct'}\n${executablePath || 'default'}`)
    .digest('hex')
    .slice(0, 20)
}

/**
 * 导出纯逻辑辅助函数供冒烟测试验证池隔离和档案路径稳定性。
 */
export function browserPoolKey({ interactive = false, proxyServer = '', profileKey = '', executablePath = '' } = {}) {
  const route = proxyServer || 'direct'
  return interactive
    ? `interactive|${profileFingerprint(profileKey, route, executablePath)}`
    : `headless|${route}`
}

export function interactiveProfilePath(profileKey, proxyServer = '', executablePath = '') {
  return path.join(dataPath(), 'browser-profile', profileFingerprint(profileKey, proxyServer || 'direct', executablePath))
}

/**
 * 全局页面并发闸门：定时任务多用户并发时，浏览器页面是最吃内存的资源
 * （每页数十 MB），超过上限的任务排队等待，避免拖垮服务器。
 * 排队有上限时间，超时即放弃并从队列摘除，避免调用方已超时放弃、
 * 任务却在稍后拿到槽位继续跑（结果与用户看到的提示相反）
 */
let pageSlotsUsed = 0
const pageWaiters = []

async function acquirePageSlot() {
  const cfg = getConfig().browser
  const max = Math.max(1, Math.min(cfg.maxConcurrentPages || 2, 10))
  if (pageSlotsUsed < max) {
    pageSlotsUsed++
    return
  }
  // Number 转换与 clamp 区间需与 checkin.js 的 hangBudgetMs 保持一致
  const waitMs = Math.max(30, Math.min(Number(cfg.slotWaitSec) || 120, 600)) * 1000
  logger.info(`[relay-checkin-plugin] 浏览器页面已达上限 ${max}，排队等待中（当前队列 ${pageWaiters.length + 1}）`)
  await new Promise((resolve, reject) => {
    const waiter = { settled: false, timer: null }
    waiter.grant = () => {
      if (waiter.settled) return false
      waiter.settled = true
      clearTimeout(waiter.timer)
      resolve()
      return true
    }
    waiter.timer = setTimeout(() => {
      if (waiter.settled) return
      waiter.settled = true
      const i = pageWaiters.indexOf(waiter)
      if (i >= 0) pageWaiters.splice(i, 1)
      reject(new Error(`等待浏览器空闲超过 ${waitMs / 1000} 秒，请稍后重试`))
    }, waitMs)
    pageWaiters.push(waiter)
  })
}

/**
 * 释放槽位：有等待者时直接交接（不减计数），避免空窗期被插队导致短暂超出上限
 */
function releasePageSlot() {
  while (pageWaiters.length) {
    const next = pageWaiters.shift()
    if (next.grant()) return
  }
  pageSlotsUsed = Math.max(0, pageSlotsUsed - 1)
}

async function getPuppeteer() {
  try {
    return (await import('puppeteer')).default
  } catch {
    throw new Error('未找到 puppeteer 依赖，无法使用浏览器方案')
  }
}

/**
 * Turnstile 会拒绝过旧 Chromium。TRSS-Yunzai 内置 Puppeteer 可能数年未更新，
 * 因此优先使用机器上持续更新的 Chrome/Edge，找不到时才回退 Puppeteer 自带内核。
 */
export function browserExecutableVersion(executablePath, {
  platform = process.platform,
  spawn = spawnSync
} = {}) {
  try {
    let result
    if (platform === 'win32') {
      const escapedPath = String(executablePath).replaceAll("'", "''")
      const command = `(Get-Item -LiteralPath '${escapedPath}').VersionInfo.ProductVersion`
      const encodedCommand = Buffer.from(command, 'utf16le').toString('base64')
      result = spawn('powershell.exe', [
          '-NoProfile',
          '-NonInteractive',
          '-EncodedCommand',
          encodedCommand
        ], { encoding: 'utf8', windowsHide: true, timeout: 5000 })
    } else {
      result = spawn(executablePath, ['--version'], { encoding: 'utf8', windowsHide: true, timeout: 5000 })
    }
    const output = `${result?.stdout || ''}\n${result?.stderr || ''}`
    return output.match(/\b(\d+(?:\.\d+){1,3})\b/)?.[1] || ''
  } catch {
    return ''
  }
}

function compareBrowserVersions(a, b) {
  const left = String(a || '').split('.').map(Number)
  const right = String(b || '').split('.').map(Number)
  for (let i = 0; i < Math.max(left.length, right.length); i++) {
    const diff = (left[i] || 0) - (right[i] || 0)
    if (diff) return diff
  }
  return 0
}

export function resolveBrowserExecutable(configured = '', {
  platform = process.platform,
  env = process.env,
  exists = fs.existsSync,
  versionOf = executablePath => browserExecutableVersion(executablePath, { platform })
} = {}) {
  const explicit = String(configured || '').trim()
  if (explicit) {
    const resolved = path.resolve(explicit)
    if (!exists(resolved)) throw new Error(`配置的浏览器程序不存在: ${resolved}`)
    return resolved
  }

  const candidates = []
  if (platform === 'win32') {
    if (env.PROGRAMFILES) candidates.push(path.join(env.PROGRAMFILES, 'Google', 'Chrome', 'Application', 'chrome.exe'))
    if (env['PROGRAMFILES(X86)']) {
      candidates.push(path.join(env['PROGRAMFILES(X86)'], 'Google', 'Chrome', 'Application', 'chrome.exe'))
      candidates.push(path.join(env['PROGRAMFILES(X86)'], 'Microsoft', 'Edge', 'Application', 'msedge.exe'))
    }
    if (env.LOCALAPPDATA) candidates.push(path.join(env.LOCALAPPDATA, 'Google', 'Chrome', 'Application', 'chrome.exe'))
    if (env.PROGRAMFILES) candidates.push(path.join(env.PROGRAMFILES, 'Microsoft', 'Edge', 'Application', 'msedge.exe'))
  } else if (platform === 'darwin') {
    candidates.push(
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge'
    )
  } else {
    candidates.push(
      '/usr/bin/google-chrome-stable',
      '/usr/bin/google-chrome',
      '/usr/bin/chromium',
      '/usr/bin/chromium-browser',
      '/snap/bin/chromium'
    )
  }
  const installed = [...new Set(candidates)].filter(candidate => exists(candidate))
  if (installed.length <= 1) return installed[0] || null
  return installed
    .map((executablePath, index) => ({ executablePath, version: versionOf(executablePath), index }))
    .sort((a, b) => compareBrowserVersions(b.version, a.version) || a.index - b.index)[0]
    ?.executablePath || null
}

// 反自动化检测：各项独立保护，任一项失败都不影响其余初始化。
const STEALTH_SCRIPT = `
  try { Object.defineProperty(navigator, 'webdriver', { get: () => undefined }) } catch (e) {}
  try { window.chrome = window.chrome || { runtime: {} } } catch (e) {}
  try { Object.defineProperty(navigator, 'languages', { get: () => ['zh-CN', 'zh', 'en'] }) } catch (e) {}
  try {
    const origQuery = window.navigator.permissions?.query
    if (origQuery) {
      window.navigator.permissions.query = parameters =>
        parameters.name === 'notifications'
          ? Promise.resolve({ state: globalThis.Notification?.permission || 'default' })
          : origQuery.call(window.navigator.permissions, parameters)
    }
  } catch (e) {}
`

/**
 * 给 puppeteer 调用套硬性超时：个别环境下 launch/newPage/goto 可能永不 resolve，
 * 没有这层兜底会让整个签到流程静默挂起
 */
function withTimeout(promise, ms, msg) {
  let timer = null
  return Promise.race([
    promise.finally(() => clearTimeout(timer)),
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(msg)), ms)
    })
  ])
}

/**
 * 打开页面并带超时：超时后底层调用仍可能产出 Page，
 * 挂个兜底回调把晚到的页面关掉，避免数十 MB 常驻泄漏
 */
export async function newPageSafe(browser, ms, { reuseBlank = false } = {}) {
  if (reuseBlank && typeof browser.pages === 'function') {
    try {
      const pages = await withTimeout(browser.pages(), ms, '读取浏览器初始页面超时')
      const blank = pages.find(page => page?.url?.() === 'about:blank')
      if (blank) return blank
    } catch {
      // 读取初始页失败时回退到新建页面，不能阻断签到。
    }
  }
  const pending = browser.newPage()
  try {
    return await withTimeout(pending, ms, '打开页面超时')
  } catch (err) {
    pending.then(pg => pg?.close?.().catch(() => {})).catch(() => {})
    throw err
  }
}

function isBrowserAlive(inst) {
  if (!inst) return false
  // puppeteer v20+ 为 connected 属性，老版本为 isConnected()
  return inst.connected ?? inst.isConnected?.() ?? false
}

async function browserUserAgent(browser) {
  const configured = String(getConfig().request.userAgent || '')
  try {
    const native = String(await browser.userAgent())
    if (/(?:Headless)?Chrome\/[\d.]+/.test(native)) {
      // 沿用 Chromium 实际操作系统和版本，仅去掉无头专用标记，避免 UA 与
      // navigator.platform 在 Linux 部署时出现 Windows/Linux 自相矛盾。
      return native.replace(/HeadlessChrome\//, 'Chrome/')
    }
  } catch {
    // 老版本 Puppeteer 取不到 userAgent 时再回落到配置值
  }
  try {
    const version = await browser.version()
    const runtime = String(version).match(/(?:Chrome|Chromium)\/([\d.]+)/)?.[1]
    if (runtime && /Chrome\/[\d.]+/.test(configured)) {
      return configured.replace(/Chrome\/[\d.]+/, `Chrome/${runtime}`)
    }
  } catch {
    // 读取内核版本失败时沿用用户配置
  }
  return configured
}

/**
 * 解析代理地址：chromium 的 --proxy-server 不支持带账密，账密拆出来走 page.authenticate
 */
function parseProxy(proxyUrl) {
  if (!proxyUrl) return null
  try {
    const u = new URL(proxyUrl)
    return {
      server: `${u.protocol}//${u.host}`,
      auth: (u.username || u.password)
        ? { username: decodeURIComponent(u.username), password: decodeURIComponent(u.password) }
        : null
    }
  } catch {
    logger.warn(`[relay-checkin-plugin] 代理地址格式不正确，已忽略: ${proxyUrl}`)
    return null
  }
}

/**
 * 取该模式的浏览器实例（不存在则启动）。同模式并发任务共享同一次启动过程，
 * 不再因模式不同而互相关闭实例
 */
async function getBrowser(pool, proxy, { interactive = false, profileKey = '', executablePath = null } = {}) {
  if (isBrowserAlive(pool.instance)) return pool.instance
  if (!pool.launching) {
    pool.launching = (async () => {
      // 无桌面的 Linux 服务器：不直接放弃可见模式，先拉一个 Xvfb 虚拟屏顶上。
      // Turnstile 在纯无头下会静默卡死，有真实显示环境（哪怕是虚拟屏）才稳定出 token；
      // 装不上 Xvfb 时 ensureVirtualDisplay 自己抛出可读原因。
      let virtualDisplay = null
      if (interactive && process.platform === 'linux' && !process.env.DISPLAY && !process.env.WAYLAND_DISPLAY) {
        virtualDisplay = await ensureVirtualDisplay()
      }
      if (interactive) warnWindowsHeadlessSession()
      const puppeteer = await getPuppeteer()
      const args = [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-blink-features=AutomationControlled',
        '--disable-features=TranslateUI,BackForwardCache',
        '--lang=zh-CN',
        '--no-first-run',
        '--no-default-browser-check'
      ]
      if (interactive) {
        // 虚拟屏没有窗口管理器，--start-maximized 不生效，窗口尺寸只认 --window-size；
        // 这里比虚拟屏分辨率留一圈余量，让 innerWidth/screen.width 的关系与真实桌面一致。
        args.push('--window-size=1600,1000')
        // 无桌面服务器（Xvfb）上没有 GPU：Chrome 136+ 默认不给软件渲染的 WebGL，
        // 于是 canvas/WebGL 指纹整块缺失，Cloudflare 会把这种环境判成机器人。
        // 显式打开 SwiftShader 软渲染，让 WebGL 至少能返回真实上下文。
        args.push('--enable-unsafe-swiftshader')
        // Wayland 桌面上默认走 Wayland 后端，xdotool 驱动不了真实指针；改走 XWayland
        if (!virtualDisplay && process.env.WAYLAND_DISPLAY && process.env.DISPLAY) {
          args.push('--ozone-platform=x11')
        }
      } else {
        // 无头 WAF 页面会持续执行挑战脚本，限制单实例资源占用。
        args.push(
          '--disable-gpu',
          '--disable-extensions',
          '--disable-background-networking',
          '--renderer-process-limit=1',
          '--js-flags=--max-old-space-size=256'
        )
      }
      if (proxy?.server) {
        args.push(`--proxy-server=${proxy.server}`)
        // 让 Chrome 到代理自身（本机回环）的连接不再经过代理，
        // 避免 Clash 等开启 TUN/系统代理时形成环路把请求打进黑洞
        args.push('--proxy-bypass-list=<-loopback>')
      }
      // protocolTimeout 给所有 CDP 调用兜底（setCookie/evaluate 等在浏览器无响应时
      // 会永久挂起且不受 launch 的 timeout 约束）；timeout 管启动连接本身
      const launchOptions = {
        headless: interactive ? false : 'new',
        args,
        timeout: 60000,
        // solveTurnstile 的 page.evaluate 会一直等到 token 或配置超时；CDP 超时必须
        // 高于允许的等待上限，否则默认 120 秒的可见验证会在 90 秒被提前掐断。
        protocolTimeout: interactive ? 660000 : 150000
      }
      if (virtualDisplay) launchOptions.env = { ...process.env, DISPLAY: virtualDisplay }
      if (executablePath) {
        launchOptions.executablePath = executablePath
        logger.info(`[relay-checkin-plugin] 使用系统浏览器内核: ${executablePath}`)
      } else {
        logger.warn('[relay-checkin-plugin] 未找到系统 Chrome/Edge，将使用 Puppeteer 自带 Chromium；Turnstile 可能拒绝过旧内核')
      }
      if (interactive) {
        const userDataDir = interactiveProfilePath(
          profileKey,
          proxy?.server,
          executablePath || 'puppeteer-bundled'
        )
        fs.mkdirSync(userDataDir, { recursive: true })
        // pm2 restart / 崩溃会把上次的可见浏览器留成孤儿，它占着同一档案目录，
        // 本次启动会被 Chrome 直接转交给它然后静默退出
        reapProfileHolders(userDataDir, { orphanOnly: true, label: '可见浏览器' })
        logger.info(`[relay-checkin-plugin] 可见浏览器隔离档案: ${userDataDir}`)
        launchOptions.userDataDir = userDataDir
        launchOptions.defaultViewport = null
        launchOptions.ignoreDefaultArgs = ['--enable-automation']
      }
      return await puppeteer.launch(launchOptions)
    })().then(inst => {
      pool.instance = inst
      pool.launching = null
      // 调用方可能已因启动超时放弃：此时无人持有也无回收排期，
      // 补一次空闲回收，避免 chromium 进程孤儿常驻
      if (pool.activeTasks === 0 && !pool.idleTimer) scheduleIdleClose(pool)
      return inst
    }).catch(err => {
      pool.launching = null
      throw err
    })
  }
  return await pool.launching
}

function scheduleIdleClose(pool, idleMs = null) {
  // 定时器回调内不再取配置：getConfig 可能读盘/建 watcher 并抛错，
  // 而 async 回调里的异常无人接管会触发 unhandledRejection 直接退进程
  let ms = idleMs
  if (ms === null) {
    try {
      ms = (getConfig().browser.idleCloseSec || 300) * 1000
    } catch {
      ms = 300000
    }
  }
  if (pool.idleTimer) clearTimeout(pool.idleTimer)
  pool.idleTimer = setTimeout(async () => {
    try {
      pool.idleTimer = null
      // 仍有任务在用浏览器时不回收，等最后一个任务结束再调度
      if (pool.activeTasks > 0) return
      // 启动中（调用方已超时放弃）时不能提前置空，否则实例落地后无人回收
      if (pool.launching) {
        scheduleIdleClose(pool, ms)
        return
      }
      const inst = pool.instance
      pool.instance = null
      await inst?.close()
      // 常驻可见浏览器关掉后，为它拉起的虚拟显示也该跟着回收
      scheduleVirtualDisplayRelease()
    } catch (err) {
      logger.error(`[relay-checkin-plugin] 浏览器回收异常: ${err?.message || err}`)
    }
  }, ms)
}

/**
 * 打开一个已注入 stealth 的页面执行任务，自动关闭页面并调度浏览器空闲回收
 * @param {string} host 目标站点 host（用于判断是否走代理）
 */
/**
 * 浏览器方案熔断：某站点连续失败达到阈值后临时停用一段时间。
 * 打不开的站点会让 Chrome 反复重试并可能拖慢宿主机，熔断可避免定时任务
 * 每天在同一个站上白耗资源、影响其他站点与机器人本身
 */
const breaker = new Map() // host -> { fails, until }
const BREAK_THRESHOLD = 3
const BREAK_MS = 30 * 60 * 1000

function checkBreaker(host) {
  const b = breaker.get(host)
  if (!b?.until) return
  if (Date.now() < b.until) {
    const mins = Math.ceil((b.until - Date.now()) / 60000)
    throw new Error(`该站点浏览器方案连续失败已暂停，约 ${mins} 分钟后自动恢复`)
  }
  breaker.delete(host)
}

function noteResult(host, ok) {
  if (ok) {
    breaker.delete(host)
    return
  }
  const b = breaker.get(host) || { fails: 0, until: 0 }
  b.fails++
  if (b.fails >= BREAK_THRESHOLD) {
    b.until = Date.now() + BREAK_MS
    b.fails = 0
    logger.warn(`[relay-checkin-plugin] ${host} 浏览器方案连续失败 ${BREAK_THRESHOLD} 次，暂停 ${BREAK_MS / 60000} 分钟`)
  }
  breaker.set(host, b)
}

function browserResultOk(out) {
  return !out?.wafBlocked && !out?.turnstileFailed && !out?.powFailed && out?.status !== 0
}

/**
 * 浏览器会自动跟随 30x；拦截每个导航请求并重新校验目标，防止重定向绕过 SSRF 防护。
 */
async function installNavigationGuard(page) {
  await withTimeout(page.setRequestInterception(true), 15000, '启用浏览器地址校验超时')
  page.on('request', request => {
    const url = request.url()
    if (!request.isNavigationRequest() || url === 'about:blank') {
      request.continue().catch(() => {})
      return
    }
    assertSafeRequestUrl(url).then(() => {
      request.continue().catch(() => {})
    }).catch(err => {
      logger.warn(`[relay-checkin-plugin] 已阻止浏览器访问不安全地址 ${url}: ${err?.message || err}`)
      request.abort('blockedbyclient').catch(() => {})
    })
  })
}

function pageCdpClient(page) {
  try {
    return typeof page?._client === 'function' ? page._client() : page?._client
  } catch {
    return null
  }
}

/**
 * Puppeteer 新版提供 Page.setBypassServiceWorker，TRSS-Yunzai 内置的旧版通常只有
 * Page._client()。两者最终调用同一个 CDP 命令；都不可用时允许继续，Service Worker
 * 绕过只用于避免持久档案命中旧缓存，不应阻断浏览器签到。
 */
export async function bypassServiceWorkerCompat(page) {
  if (typeof page?.setBypassServiceWorker === 'function') {
    try {
      await page.setBypassServiceWorker(true)
      return 'page-api'
    } catch (err) {
      logger.warn(`[relay-checkin-plugin] Puppeteer Service Worker API 调用失败，尝试旧版兼容方式: ${err?.message || err}`)
    }
  }

  try {
    const client = pageCdpClient(page)
    if (client && typeof client.send === 'function') {
      await client.send('Network.setBypassServiceWorker', { bypass: true })
      return 'cdp'
    }
  } catch (err) {
    logger.warn(`[relay-checkin-plugin] 旧版 Puppeteer 无法禁用 Service Worker，继续浏览器签到: ${err?.message || err}`)
  }

  return 'unsupported'
}

/**
 * Puppeteer 20 之前没有 Frame.frameElement()。旧版仍暴露 frame id 与页面 CDP
 * 客户端，可由 DOM.getFrameOwner 取得跨域 iframe 的真实屏幕坐标。
 */
export async function legacyFrameOwnerBox(page, frame, { timeoutMs = 5000 } = {}) {
  const frameId = frame?._id || frame?._frameId || (typeof frame?.id === 'function' ? frame.id() : null)
  const client = pageCdpClient(page)
  if (!frameId || !client || typeof client.send !== 'function') return null

  const owner = await withTimeout(
    client.send('DOM.getFrameOwner', { frameId }),
    timeoutMs,
    '旧版 Puppeteer 定位 Turnstile frame 超时'
  )
  const node = owner?.backendNodeId
    ? { backendNodeId: owner.backendNodeId }
    : owner?.nodeId
      ? { nodeId: owner.nodeId }
      : null
  if (!node) return null

  const result = await withTimeout(
    client.send('DOM.getBoxModel', node),
    timeoutMs,
    '旧版 Puppeteer 读取 Turnstile 坐标超时'
  )
  const quad = result?.model?.border || result?.model?.content
  if (!Array.isArray(quad) || quad.length < 8 || quad.some(value => !Number.isFinite(value))) return null
  const xs = quad.filter((_, index) => index % 2 === 0)
  const ys = quad.filter((_, index) => index % 2 === 1)
  const left = Math.min(...xs)
  const right = Math.max(...xs)
  const top = Math.min(...ys)
  const bottom = Math.max(...ys)
  return { x: left, y: top, width: right - left, height: bottom - top }
}

/**
 * Turnstile 的复选框位于关闭的 Shadow DOM，普通选择器无法观察其加载状态。
 * Chrome 无障碍树会在控件真正可交互后暴露 checkbox 节点；其坐标相对 iframe，
 * 加上 frame owner 坐标即可得到页面鼠标所需的精确位置。
 */
export async function turnstileCheckboxPoint(page, frame, ownerBox, { timeoutMs = 5000 } = {}) {
  const frameId = frame?._id || frame?._frameId || (typeof frame?.id === 'function' ? frame.id() : null)
  let client = null
  try {
    client = typeof frame?._client === 'function' ? frame._client() : frame?._client
  } catch {
    client = null
  }
  client ||= pageCdpClient(page)
  if (!frameId || !client || typeof client.send !== 'function') {
    return { supported: false, point: null }
  }

  const tree = await withTimeout(
    client.send('Accessibility.getFullAXTree', { frameId }),
    timeoutMs,
    '等待 Turnstile 复选框可交互超时'
  )
  const checkbox = tree?.nodes?.find(node => node?.role?.value === 'checkbox' && !node.ignored)
  if (!checkbox?.backendDOMNodeId) return { supported: true, point: null }

  const result = await withTimeout(
    client.send('DOM.getBoxModel', { backendNodeId: checkbox.backendDOMNodeId }),
    timeoutMs,
    '读取 Turnstile 复选框坐标超时'
  )
  const quad = result?.model?.border || result?.model?.content
  if (!Array.isArray(quad) || quad.length < 8 || quad.some(value => !Number.isFinite(value))) {
    return { supported: true, point: null }
  }
  const xs = quad.filter((_, index) => index % 2 === 0)
  const ys = quad.filter((_, index) => index % 2 === 1)
  const left = Math.min(...xs)
  const right = Math.max(...xs)
  const top = Math.min(...ys)
  const bottom = Math.max(...ys)
  const width = right - left
  return {
    supported: true,
    point: {
      // AX 节点同时覆盖方框与文字，左侧约 22px 是复选框中心。
      x: ownerBox.x + left + Math.min(22, width / 2),
      y: ownerBox.y + top + (bottom - top) / 2
    },
    name: checkbox?.name?.value || ''
  }
}

async function withPage(host, fn, { interactive = false, profileKey = host, trackResult = true } = {}) {
  checkBreaker(host)
  await acquirePageSlot()
  // 外层只负责槽位：内部任何异常（含取配置/解析代理失败）都不会漏掉释放
  try {
    const proxy = parseProxy(proxyForHost(host, true))
    const executablePath = resolveBrowserExecutable(getConfig().browser.executablePath)
    const poolKey = browserPoolKey({
      interactive,
      proxyServer: proxy?.server,
      profileKey,
      executablePath: executablePath || 'puppeteer-bundled'
    })
    const pool = getPool(poolKey, interactive)
    if (pool.idleTimer) {
      clearTimeout(pool.idleTimer)
      pool.idleTimer = null
    }
    pool.activeTasks++
    let page = null
    try {
      logger.info(`[relay-checkin-plugin] ${interactive ? '可见' : '无头'}浏览器方案启动: ${host}${proxy ? ` (代理 ${proxy.server})` : ' (直连)'}`)
      const browser = await withTimeout(
        getBrowser(pool, proxy, { interactive, profileKey, executablePath }),
        70000,
        `${interactive ? '可见' : '无头'}浏览器启动超时（检查 puppeteer 与图形桌面是否可用）`
      )
      const engineVersion = typeof browser.version === 'function'
        ? await withTimeout(browser.version(), 5000, '读取浏览器内核版本超时').catch(() => '')
        : ''
      if (engineVersion) logger.info(`[relay-checkin-plugin] 浏览器内核版本: ${engineVersion}`)
      page = await newPageSafe(browser, 30000, {
        // Chrome 启动时已有 about:blank；直接复用可避免可见窗口多出一个白屏标签页。
        reuseBlank: interactive && pool.activeTasks === 1
      })
      logger.info('[relay-checkin-plugin] 浏览器页面就绪，开始初始化')
      // 以下都是本地 CDP 调用，正常都是毫秒级；浏览器无响应时必须超时而不是静默挂死
      if (proxy?.auth) await withTimeout(page.authenticate(proxy.auth), 15000, '设置代理认证超时')
      // 可见接管（只用于 Turnstile）刻意不做任何 CDP 覆盖：真实 headful Chrome 本身
      // 就有正常的 UA / 视口 / navigator，再叠 Emulation 视口覆盖、UA 覆盖、navigator 补丁
      // 和请求拦截只会留下自动化痕迹——实测 Cloudflare 会直接回 600010（检测到 bot 行为）。
      if (!interactive) {
        await withTimeout(page.setViewport({ width: 1365, height: 900, deviceScaleFactor: 1 }), 15000, '设置浏览器窗口超时')
        const userAgent = await withTimeout(browserUserAgent(browser), 15000, '读取浏览器版本超时')
        await withTimeout(page.setUserAgent(userAgent), 15000, '设置 UA 超时（浏览器无响应）')
        await withTimeout(page.setExtraHTTPHeaders({ 'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8' }), 15000, '设置浏览器语言超时')
      }
      const serviceWorkerMode = await withTimeout(
        bypassServiceWorkerCompat(page),
        15000,
        '禁用页面 Service Worker 超时'
      ).catch(err => {
        logger.warn(`[relay-checkin-plugin] 禁用页面 Service Worker 超时，继续浏览器签到: ${err?.message || err}`)
        return 'unsupported'
      })
      if (serviceWorkerMode === 'cdp') {
        logger.info('[relay-checkin-plugin] 已使用旧版 Puppeteer 兼容方式禁用页面 Service Worker')
      } else if (serviceWorkerMode === 'unsupported') {
        logger.warn('[relay-checkin-plugin] 当前 Puppeteer 不支持禁用页面 Service Worker，已跳过该可选优化')
      }
      if (interactive) {
        await withTimeout(page.bringToFront(), 15000, '显示浏览器窗口超时')
      } else {
        await withTimeout(page.evaluateOnNewDocument(STEALTH_SCRIPT), 15000, '注入初始化脚本超时（浏览器无响应）')
        await installNavigationGuard(page)
      }
      logger.info('[relay-checkin-plugin] 页面初始化完成')
      const out = await fn(page)
      if (trackResult) noteResult(host, browserResultOk(out))
      return out
    } catch (err) {
      if (trackResult) noteResult(host, false)
      throw err
    } finally {
      // 关闭也可能挂起（挑战页忙循环等），必须带超时否则计数永久失衡
      if (page) await withTimeout(page.close(), 15000, '关闭页面超时').catch(() => {})
      pool.activeTasks--
      // 可见窗口完成后尽快退出；用户档案已经落盘，下次仍能复用信任状态。
      scheduleIdleClose(pool, interactive ? 1000 : null)
    }
  } finally {
    releasePageSlot()
  }
}

/**
 * 在页面上下文内发起 fetch（自动携带页面 cookie，可附加请求头）
 * 页面导航中（WAF 挑战自动刷新）evaluate 会抛异常，统一吞掉返回 status 0 由调用方重试；
 * 页内 fetch 带 AbortSignal 超时，避免代理隧道挂起时无限等待
 * @returns {Promise<{status: number, json: object|null}>}
 */
async function pageFetch(page, url, { method = 'GET', headers = {}, timeoutMs: override = null } = {}) {
  const timeoutMs = override ?? (getConfig().request.timeout || 15) * 1000
  try {
    await assertSafeRequestUrl(url)
    const evaluating = page.evaluate(async ({ url, method, headers, timeoutMs }) => {
      // 用 AbortController 而非 AbortSignal.timeout：后者要 Chrome 103+，
      // 内置 Chromium 偏旧时会直接抛 TypeError 使每次请求都失败
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), timeoutMs)
      try {
        const res = await fetch(url, {
          method,
          headers,
          credentials: 'include',
          signal: controller.signal
        })
        let json = null
        try {
          json = await res.json()
        } catch {
          // 非 JSON（WAF 拦截页等）
        }
        return { status: res.status, json }
      } catch (err) {
        return { status: 0, json: null, error: String(err) }
      } finally {
        clearTimeout(timer)
      }
    }, { url, method, headers: browserRequestHeaders(headers), timeoutMs })
    // evaluate 自身也可能不返回（挑战页导航中/渲染器卡住），外层再兜一层超时，
    // 否则单轮探测就能吃掉整个 WAF 预算且不留任何日志
    return await withTimeout(evaluating, timeoutMs + 5000, '页内请求无响应')
  } catch (err) {
    return { status: 0, json: null, error: String(err?.message || err) }
  }
}

function browserRequestHeaders(headers = {}) {
  const out = {}
  for (const [key, value] of Object.entries(headers || {})) {
    // Cookie/Host/Content-Length 是浏览器禁止脚本设置的受限请求头。
    if (/^(?:cookie|host|content-length)$/i.test(key)) continue
    if (value !== undefined && value !== null) out[key] = String(value)
  }
  return out
}

async function injectSessionCookies(page, host, headers = {}) {
  const cookieEntry = Object.entries(headers || {}).find(([key]) => /^cookie$/i.test(key))
  if (!cookieEntry?.[1] || typeof page?.setCookie !== 'function') return
  const cookies = String(cookieEntry[1]).split(';').map(part => part.trim()).filter(Boolean)
  for (const item of cookies) {
    const separator = item.indexOf('=')
    if (separator <= 0) continue
    const name = item.slice(0, separator).trim()
    const value = item.slice(separator + 1).trim()
    if (!name || !value) continue
    await withTimeout(
      page.setCookie({ name, value, domain: host, path: '/', secure: true }),
      10000,
      `注入 ${name} cookie 超时`
    )
  }
}

/**
 * 在目标站点页面内完成 NewAPI POW-Shield 校验并提交签到。
 * 该流程对应站点公开前端 POWCaptcha：挑战接口 → SHA-256 nonce → 指纹/风险信息
 * → pow_token 查询参数。所有步骤都在同一个浏览器页和出口内完成。
 */
export async function powCheckin(account, { checkinPath, headers = {}, validationHeaders = headers, timeoutSec = null } = {}) {
  const cfg = getConfig()
  const host = new URL(account.baseUrl).hostname
  const timeout = Math.max(15, Math.min(Number(timeoutSec ?? cfg.browser.powTimeoutSec ?? 120) || 120, 300))
  const challengeUrl = new URL('/api/user/self/pow/challenge', `${account.baseUrl}/`).toString()
  const checkinUrl = new URL(checkinPath, `${account.baseUrl}/`).toString()
  const requestHeaders = browserRequestHeaders(headers)
  const checkinHeaders = browserRequestHeaders(validationHeaders)
  const cookieHeaders = headers

  return await withPage(host, async page => {
    await injectSessionCookies(page, host, cookieHeaders)
    await navigateForTurnstile(page, account.baseUrl)

    const evaluating = page.evaluate(async ({ challengeUrl, checkinUrl, requestHeaders, checkinHeaders, timeoutMs }) => {
      const textOf = value => value == null ? '' : String(value)
      const parseResponse = async response => {
        let text = ''
        let json = null
        try {
          text = await response.text()
          try { json = JSON.parse(text) } catch { /* 非 JSON */ }
        } catch {
          // 连接中断时保留空响应，由外层给出明确错误
        }
        return {
          status: response.status,
          json,
          textSnippet: json ? '' : text.slice(0, 512)
        }
      }
      const hashText = async value => {
        const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
        return Array.from(new Uint8Array(digest)).map(byte => byte.toString(16).padStart(2, '0')).join('')
      }
      const legacyHash = value => {
        let result = 0
        for (let i = 0; i < value.length; i++) result = (result << 5) - result + value.charCodeAt(i) | 0
        return result >>> 0
      }
      const canvasFingerprint = () => {
        try {
          const canvas = document.createElement('canvas')
          canvas.width = 200
          canvas.height = 50
          const context = canvas.getContext('2d')
          context.textBaseline = 'top'
          context.font = '14px Arial'
          context.fillStyle = '#f60'
          context.fillRect(50, 0, 80, 30)
          context.fillStyle = '#069'
          context.fillText('POW-Shield', 2, 15)
          context.fillStyle = 'rgba(102,204,0,0.7)'
          context.fillText('captcha.fp', 4, 35)
          context.globalCompositeOperation = 'multiply'
          context.fillStyle = 'rgb(255,0,255)'
          context.beginPath()
          context.arc(50, 25, 20, 0, Math.PI * 2)
          context.fill()
          return legacyHash(canvas.toDataURL())
        } catch {
          return 0
        }
      }
      const webglFingerprint = () => {
        try {
          const canvas = document.createElement('canvas')
          const context = canvas.getContext('webgl') || canvas.getContext('experimental-webgl')
          if (!context) return 0
          const debug = context.getExtension('WEBGL_debug_renderer_info')
          const renderer = debug ? context.getParameter(debug.UNMASKED_RENDERER_WEBGL) : ''
          const vendor = debug ? context.getParameter(debug.UNMASKED_VENDOR_WEBGL) : ''
          return legacyHash([
            context.getParameter(context.MAX_TEXTURE_SIZE),
            context.getParameter(context.MAX_RENDERBUFFER_SIZE),
            context.getParameter(context.MAX_VERTEX_ATTRIBS),
            renderer,
            vendor
          ].join('|'))
        } catch {
          return 0
        }
      }
      const automationSignals = () => {
        const signals = []
        if (navigator.webdriver) signals.push('webdriver')
        if (/HeadlessChrome/.test(navigator.userAgent)) signals.push('headless')
        if (navigator.webdriver_evaluate) signals.push('webdriver_evaluate')
        if (!window.chrome && /Chrome/.test(navigator.userAgent)) signals.push('fake_chrome')
        if (navigator.plugins.length === 0 && !/Mobile|Android/i.test(navigator.userAgent)) signals.push('no_plugins')
        if (screen.width === 0 || screen.height === 0) signals.push('zero_screen')
        return { signals, score: signals.length }
      }
      const behavior = { score: 20, moveCount: 0, totalDist: 0 }
      const encode = value => {
        const json = JSON.stringify(value)
        try { return btoa(json) } catch { return btoa(unescape(encodeURIComponent(json))) }
      }
      const randomId = () => globalThis.crypto?.randomUUID
        ? globalThis.crypto.randomUUID()
        : `${Date.now()}-${Math.random().toString(16).slice(2)}-${Math.random().toString(16).slice(2)}`
      const storageGet = (storage, key) => {
        try { return storage?.getItem(key) || '' } catch { return '' }
      }
      const storageSet = (storage, key, value) => {
        try { storage?.setItem(key, value) } catch { /* 隐私模式可能禁用存储 */ }
      }
      const withPageIntegrityHeaders = async headers => {
        const hasGameHeaders = Object.keys(headers || {}).some(key => /^x-game-/i.test(key))
        if (!hasGameHeaders) return headers
        const out = { ...headers }
        const sessionKey = 'newapi_game_integrity_session_v1'
        const seqKey = 'newapi_game_integrity_seq_v1'
        const sessionId = storageGet(sessionStorage, sessionKey) || randomId()
        const savedSeq = Number(storageGet(sessionStorage, seqKey) || '0')
        const seq = (Number.isFinite(savedSeq) ? savedSeq : 0) + 1
        storageSet(sessionStorage, sessionKey, sessionId)
        storageSet(sessionStorage, seqKey, String(seq))
        const timezone = (() => {
          try { return Intl.DateTimeFormat().resolvedOptions().timeZone || '' } catch { return '' }
        })()
        const fingerprint = await hashText([
          navigator.userAgent || '',
          navigator.language || '',
          navigator.platform || '',
          timezone,
          String(navigator.hardwareConcurrency || ''),
          String(navigator.deviceMemory || '')
        ].join('|'))
        out['X-Game-Action-Id'] = randomId()
        out['X-Game-Client-Ts'] = String(Date.now())
        out['X-Game-Session-Id'] = sessionId
        out['X-Game-Client-Seq'] = String(seq)
        out['X-Game-Client-Fingerprint'] = fingerprint
        out['X-Game-Body-SHA256'] = await hashText('')
        return out
      }

      let postStarted = false
      try {
        const deadline = Date.now() + timeoutMs
        const challengeResponse = await fetch(challengeUrl, {
          headers: requestHeaders,
          credentials: 'include',
          cache: 'no-store'
        })
        const challengeResult = await parseResponse(challengeResponse)
        const challengeData = challengeResult.json?.success ? challengeResult.json.data : null
        if (!challengeData?.enabled) {
          return {
            powFailed: true,
            message: '站点的安全验证没给出题目呀，晚点再试试~',
            detail: challengeResult
          }
        }
        const challenge = textOf(challengeData.challenge)
        const difficulty = Number(challengeData.difficulty)
        if (!challenge || !Number.isInteger(difficulty) || difficulty < 1 || difficulty > 8) {
          return { powFailed: true, message: '站点的安全验证题目嘟嘟看不懂呀，晚点再试试~', detail: challengeResult }
        }

        const automation = automationSignals()
        let risk = 0
        if (automation.score >= 2) risk += 40
        risk += automation.score * 5
        if (behavior.score < 30) risk += 30
        risk = Math.min(100, risk)
        if (risk >= 70) {
          return { powFailed: true, message: '站点不认这个浏览器环境呀，晚点再试试~', detail: { risk, automation } }
        }

        const prefix = '0'.repeat(difficulty)
        const batchSize = 500
        const startedAt = performance.now()
        let nonce = 0
        let hash = ''
        while (!hash) {
          if (Date.now() >= deadline) return { powFailed: true, message: '安全验证算太久啦，晚点再试试~' }
          const hashes = await Promise.all(Array.from({ length: batchSize }, (_, offset) => hashText(challenge + (nonce + offset))))
          const hit = hashes.findIndex(value => value.startsWith(prefix))
          if (hit >= 0) {
            nonce += hit
            hash = hashes[hit]
            break
          }
          nonce += batchSize
        }

        const tokenPayload = {
          challenge,
          pow: { nonce, hash, time: Number(((performance.now() - startedAt) / 1000).toFixed(2)) },
          fingerprint: { canvas: canvasFingerprint(), webgl: webglFingerprint() },
          behavior,
          automation: automation.signals,
          risk,
          ts: Date.now(),
          path: challengeData.path || '',
          purpose: challengeData.purpose || '',
          body_hash: challengeData.body_hash || challengeData.bodyHash || ''
        }
        const token = encode(tokenPayload)
        const url = new URL(checkinUrl)
        url.searchParams.set('pow_token', token)
        postStarted = true
        const checkinResponse = await fetch(url.toString(), {
          method: 'POST',
          headers: await withPageIntegrityHeaders(checkinHeaders),
          credentials: 'include',
          cache: 'no-store'
        })
        return await parseResponse(checkinResponse)
      } catch (error) {
        return { powFailed: true, uncertain: postStarted, message: textOf(error?.message || error) }
      }
    }, {
      challengeUrl,
      checkinUrl,
      requestHeaders,
      checkinHeaders,
      timeoutMs: timeout * 1000
    })
    return await withTimeout(evaluating, (timeout + 15) * 1000, 'POW 页面请求无响应')
  }, {
    interactive: turnstileBrowserMode(cfg.browser) === 'interactive',
    profileKey: host,
    trackResult: false
  })
}

/**
 * 打印当前页面状态：是否还停在 WAF 挑战页、拿到了哪些 WAF cookie
 */
async function logPageState(page) {
  try {
    const [url, title, cookies] = await Promise.all([
      Promise.resolve(page.url()),
      withTimeout(page.title(), 8000, '取标题超时').catch(() => '?'),
      withTimeout(page.cookies(), 8000, '取 cookie 超时').catch(() => [])
    ])
    const names = cookies.map(c => c.name)
    const waf = names.filter(n => /^acw_|^cdn_sec_tc$|^_c_WBKFRo$/i.test(n))
    logger.info(`[relay-checkin-plugin] 页面状态: url=${url} title=${JSON.stringify(title)} WAFcookie=[${waf.join(', ') || '无'}] 全部cookie=[${names.join(', ') || '无'}]`)
  } catch (err) {
    logger.info(`[relay-checkin-plugin] 取页面状态失败: ${err?.message || err}`)
  }
}

/**
 * Turnstile 只需要目标源上存在可注入组件的页面主体，不要求站点所有资源都完成加载。
 * 某些 SPA/统计脚本会让 DOMContentLoaded 长时间不结束；导航超时后若同源 body 已可用，
 * 停止剩余加载并继续。错误页、跨域页和空白页仍按真实导航失败处理。
 */
export async function navigateForTurnstile(page, targetUrl) {
  try {
    await withTimeout(
      page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 30000 }),
      40000,
      '打开站点页面超时（网络或代理不通）'
    )
    const finalUrl = page.url()
    if (new URL(finalUrl).origin !== new URL(targetUrl).origin) {
      throw new Error(`站点跳转到了不同域名 ${new URL(finalUrl).origin}，请使用该最终地址重新绑定`)
    }
    return { partial: false }
  } catch (err) {
    const detail = err?.message || String(err)
    const recoverableNavigation = /timeout|超时|ERR_ABORTED/i.test(detail)
    let sameOrigin = false
    try {
      sameOrigin = new URL(page.url()).origin === new URL(targetUrl).origin
    } catch {
      sameOrigin = false
    }

    if (recoverableNavigation && sameOrigin) {
      const body = await withTimeout(
        page.waitForSelector('body', { timeout: 5000 }),
        7000,
        '等待页面主体超时'
      ).catch(() => null)
      if (body) {
        try {
          if (body.dispose) await withTimeout(body.dispose(), 5000, '释放页面主体句柄超时')
        } catch {
          // 页面导航中句柄可能已经失效，不影响后续 window.stop
        }
        await withTimeout(page.evaluate(() => window.stop()), 5000, '停止页面剩余加载超时').catch(() => {})
        logger.warn(`[relay-checkin-plugin] 站点导航未完整结束但同源页面已可用，停止剩余加载并继续 Turnstile: ${detail}`)
        return { partial: true, detail }
      }
    }

    if (/timeout|超时/i.test(detail)) {
      throw new Error('打开站点页面超时：30 秒内未加载出可用页面，请检查站点或代理网络')
    }
    throw new Error(`打开站点页面失败：${detail}`)
  }
}


/**
 * 打开站点让阿里云 WAF 挑战通过，取出 WAF cookie。
 * 参考实现（dctx-team/Regular-inspection）同样是「浏览器只负责过 WAF 拿 cookie，
 * 之后用普通 HTTP 调接口」——页内 fetch 受 CDP 与页面导航时序影响，不如这条路稳。
 * session 属于具体用户，不能进入按 host 共享的缓存；调用方应自行拼接当前账号的 session。
 * @returns {Promise<{cookieHeader: string}|{wafBlocked: true}>}
 */
export async function fetchWafCookies(account) {
  const cfg = getConfig()
  const host = new URL(account.baseUrl).hostname
  return await withPage(host, async page => {
    await withTimeout(
      page.setCookie({ name: 'session', value: account.token, domain: host, path: '/' }),
      15000, '注入 session cookie 超时（浏览器无响应）'
    )
    logger.info(`[relay-checkin-plugin] 正在打开 ${account.baseUrl}（取 WAF cookie）`)
    await withTimeout(
      page.goto(account.baseUrl, { waitUntil: 'domcontentloaded', timeout: 30000 }),
      40000, '打开站点页面超时（网络或代理不通）'
    )

    // 等 WAF 的 acw_sc__v2 出现（挑战 JS 执行完的标志）
    const deadline = Date.now() + (cfg.browser.wafTimeoutSec || 60) * 1000
    let cookies = []
    while (Date.now() < deadline) {
      try {
        cookies = await withTimeout(page.cookies(), 8000, '取 cookie 超时')
      } catch {
        cookies = []
      }
      if (cookies.some(c => /^acw_sc__v2$/i.test(c.name))) break
      await new Promise(r => setTimeout(r, 1000))
    }
    await logPageState(page)

    if (!cookies.some(c => /^acw_sc__v2$/i.test(c.name))) return { wafBlocked: true }
    // 只缓存 WAF cookie。浏览器档案/页面可能残留其他用户的 session，
    // 把它放入按 host 共享的缓存会导致后续用户携带错 session。
    const wafCookies = cookies.filter(c => /^(?:acw_|cdn_sec_tc$|_c_WBKFRo$)/i.test(String(c.name || '')))
    const cookieHeader = wafCookies.map(c => `${c.name}=${c.value}`).join('; ')
    if (!cookieHeader) return { wafBlocked: true }
    logger.info(`[relay-checkin-plugin] 已取得 ${wafCookies.length} 个 WAF cookie，改用普通 HTTP 调用接口`)
    return { cookieHeader }
  })
}

async function setTurnstilePanelStatus(page, text) {
  await withTimeout(
    page.evaluate(value => {
      const el = document.getElementById('relay-checkin-turnstile-status')
      if (el) el.textContent = value
    }, text),
    5000,
    '更新 Turnstile 页面状态超时'
  ).catch(() => {})
}

/**
 * 等到关闭 Shadow DOM 内真正出现可交互 checkbox 后再点击。仅在旧内核无法读取
 * 无障碍树时，才对稳定显示超过 3 秒的 iframe 使用兼容坐标。
 */
export async function autoClickTurnstileCheckbox(page, timeoutSec, shouldStop) {
  const deadline = Date.now() + Math.min(timeoutSec * 1000, 20000)
  const fallbackSeen = new Map()
  let lastError = ''
  let announcedWaiting = false
  while (!shouldStop() && Date.now() < deadline) {
    let iframe = null
    try {
      let target = null
      const challengeFrames = typeof page.frames === 'function'
        ? page.frames().filter(frame => /challenges\.cloudflare\.com|turnstile/i.test(String(frame.url?.() || '')))
        : []

      for (const frame of challengeFrames) {
        let candidate = null
        try {
          let ownerBox = null
          if (frame?.frameElement) {
            candidate = await withTimeout(frame.frameElement(), 5000, '从 frame tree 定位 Turnstile iframe 超时')
            ownerBox = await withTimeout(candidate.boundingBox(), 5000, '读取 Turnstile frame 坐标超时')
          } else {
            ownerBox = await legacyFrameOwnerBox(page, frame)
          }
          if (!ownerBox || ownerBox.width < 200 || ownerBox.height < 50) continue

          let ready
          try {
            ready = await turnstileCheckboxPoint(page, frame, ownerBox)
          } catch (err) {
            lastError = err?.message || String(err)
            ready = { supported: false, point: null }
          }
          if (ready.point) {
            iframe = candidate
            target = ready.point
            candidate = null
            break
          }

          if (!ready.supported) {
            const key = String(frame?._id || frame?._frameId || frame.url?.() || 'turnstile')
            const firstSeen = fallbackSeen.get(key) || Date.now()
            fallbackSeen.set(key, firstSeen)
            if (Date.now() - firstSeen >= 3000) {
              iframe = candidate
              target = {
                x: ownerBox.x + Math.min(30, ownerBox.width * 0.1),
                y: ownerBox.y + Math.min(35, ownerBox.height * 0.5)
              }
              candidate = null
              break
            }
          }
        } finally {
          if (candidate?.dispose) {
            await withTimeout(candidate.dispose(), 5000, '释放隐藏 Turnstile frame 句柄超时').catch(() => {})
          }
        }
      }

      if (!target && challengeFrames.length === 0) {
        iframe = await withTimeout(
          page.$(
            '#relay-checkin-turnstile iframe[src*="challenges.cloudflare.com"], ' +
            '#relay-checkin-turnstile iframe[src*="turnstile"]'
          ),
          5000,
          '从页面 DOM 定位 Turnstile iframe 超时'
        )
        const ownerBox = iframe
          ? await withTimeout(iframe.boundingBox(), 5000, '读取 Turnstile 坐标超时')
          : null
        if (ownerBox && ownerBox.width >= 200 && ownerBox.height >= 50) {
          const firstSeen = fallbackSeen.get('dom-fallback') || Date.now()
          fallbackSeen.set('dom-fallback', firstSeen)
          if (Date.now() - firstSeen >= 3000) {
            target = {
              x: ownerBox.x + Math.min(30, ownerBox.width * 0.1),
              y: ownerBox.y + Math.min(35, ownerBox.height * 0.5)
            }
          }
        }
      }

      if (!target && !announcedWaiting && challengeFrames.length > 0) {
        announcedWaiting = true
        await setTurnstilePanelStatus(page, '验证组件加载中，等待复选框可点击...')
        logger.info('[relay-checkin-plugin] Turnstile iframe 已出现，等待内部复选框可交互')
      }
      if (target && !shouldStop()) {
        // 复选框刚可交互就点会被判成脚本行为（Cloudflare 回 600010「检测到 bot」）：
        // 真人从看到组件到勾选普遍要几秒，这里随机停顿一下再动鼠标。
        const dwellMs = 3500 + Math.floor(Math.random() * 3000)
        await new Promise(resolve => setTimeout(resolve, dwellMs))
        if (shouldStop()) return false
        let how = '系统真实指针'
        if (!await nativePointerClick(page, target)) {
          how = 'CDP 注入事件'
          const startX = Math.max(1, target.x - 90)
          const startY = Math.max(1, target.y + 35)
          await withTimeout(page.mouse.move(startX, startY), 5000, '移动鼠标到 Turnstile 前超时')
          await withTimeout(page.mouse.move(target.x, target.y, { steps: 14 }), 5000, '移动鼠标到 Turnstile 超时')
          await withTimeout(page.mouse.click(target.x, target.y, { delay: 120 }), 5000, '点击 Turnstile 超时')
        }
        await setTurnstilePanelStatus(page, '已自动点击验证，等待 Cloudflare 确认...')
        logger.info(`[relay-checkin-plugin] 已在复选框可交互后等待 ${(dwellMs / 1000).toFixed(1)} 秒并用${how}点击 Turnstile（x=${target.x.toFixed(1)}, y=${target.y.toFixed(1)}）`)
        return true
      }
    } catch (err) {
      lastError = err?.message || String(err)
      // iframe 正在重建时继续短暂轮询
    } finally {
      try {
        if (iframe?.dispose) await withTimeout(iframe.dispose(), 5000, '释放 Turnstile iframe 句柄超时')
      } catch {
        // iframe 在验证过程中会重建，旧句柄失效属正常情况
      }
    }
    await new Promise(resolve => setTimeout(resolve, 350))
  }

  if (!shouldStop()) {
    await setTurnstilePanelStatus(page, '自动验证未完成，请手动勾选上方“请验证您是真人”')
    logger.warn(`[relay-checkin-plugin] Turnstile 自动操作未完成，请在可见窗口中手动点击${lastError ? `：${lastError}` : ''}`)
  }
  return false
}

/**
 * 附着模式下用真实指针点击：先问页面自己在屏幕上的位置，再把视口坐标换算成屏幕坐标。
 * 平台差异（xdotool / PowerShell）在 models/native.js 里，取不到指针时返回 false，
 * 由调用方退回 CDP 点击。
 */
async function nativePointerClick(page, target) {
  const display = pointerDisplayFor(xvfbProc?.display)
  if (!display || nativePointerUnavailable()) return false
  let geom = null
  try {
    geom = await withTimeout(page.evaluate(() => ({
      screenX: window.screenX,
      screenY: window.screenY,
      frameW: window.outerWidth - window.innerWidth,
      frameH: window.outerHeight - window.innerHeight
    })), 5000, '读取浏览器窗口位置超时')
  } catch {
    return false
  }
  return await nativeClick(display, ...viewportToScreen(geom, target.x, target.y))
}

/**
 * 视口坐标 → 屏幕坐标：窗口位置 + 左右边框的一半 + 标签栏/地址栏高度。
 * 实测（Xvfb 1920x1080 + Chrome 147）换算误差为 0。
 */
function viewportToScreen(geom, x, y) {
  return [
    Math.round(geom.screenX + Math.max(0, geom.frameW / 2) + x),
    Math.round(geom.screenY + Math.max(0, geom.frameH) + y)
  ]
}

/**
 * 用系统实测的窗口几何 + 页面自报的视口尺寸，算出视口原点的屏幕坐标。
 * 数据不全或明显不合理时返回 null，由调用方退回 Chrome 自报的换算。
 *
 * 两个平台给的矩形不同，但都能套进同一个算式：Linux 给窗口外框（于是左右各有一半边框，
 * frameW 才要除以 2），Windows 给客户区（左边就是视口左边，frameW 约为 0，
 * frameH 正好是标签栏 + 地址栏的高度）。
 */
export function detachedClickOrigin(geom, windowGeom) {
  if (!windowGeom || !geom?.innerHeight || !geom?.innerWidth) return null
  const frameH = windowGeom.height - geom.innerHeight
  const frameW = Math.max(0, Math.round((windowGeom.width - geom.innerWidth) / 2))
  // 标签栏 + 地址栏在 200px 以内才算可信；超出说明找到的不是那个窗口
  if (frameH < 0 || frameH > 200) return null
  return { x: windowGeom.x + frameW, y: windowGeom.y + frameH }
}

/**
 * 日志里怎么描述当前的指针环境：Windows 的 display 是个哨兵值，原样打出来没人看得懂。
 */
function describePointerEnv(virtualDisplay, pointerDisplay) {
  if (virtualDisplay) return `虚拟屏 ${virtualDisplay}`
  const occupies = '（勾选时会短暂占用鼠标指针）'
  return pointerDisplay === POINTER_WINDOWS
    ? `Windows 桌面${occupies}`
    : `本机桌面 ${pointerDisplay}${occupies}`
}

let warnedWindowsSession = false

/**
 * Windows 上把 Yunzai 跑成服务或计划任务（session 0）时没有交互式桌面：
 * 有头 Chrome 起不来、真实指针也无处可点，可用户看到的只是一句「浏览器启动超时」。
 * SESSIONNAME（Console / RDP-Tcp#n）是判断交互式会话最便宜的启发式，只提醒不阻断。
 */
function warnWindowsHeadlessSession() {
  if (warnedWindowsSession || process.platform !== 'win32' || process.env.SESSIONNAME) return
  warnedWindowsSession = true
  logger.warn('[relay-checkin-plugin] 当前进程似乎不在 Windows 交互式桌面会话中（SESSIONNAME 为空）：'
    + '人机验证需要真实桌面，作为服务运行时浏览器会起不来，建议在已登录的用户下启动 Yunzai')
}

async function turnstileRetrySequence(page) {  return await withTimeout(
    page.evaluate(() => Number(document.getElementById('relay-checkin-turnstile-status')?.dataset.retry || 0)),
    5000,
    '读取 Turnstile 重试状态超时'
  ).catch(() => 0)
}

/**
 * 首次点击后只监听页面端明确发出的 reset 序号；序号递增才重新等待 checkbox 并点击，
 * 避免挑战仍在处理时重复点击。
 */
async function autoClickTurnstileWithRetries(page, timeoutSec, shouldStop) {
  const deadline = Date.now() + timeoutSec * 1000
  let retrySequence = await turnstileRetrySequence(page)
  let clicked = await autoClickTurnstileCheckbox(
    page,
    Math.max(1, Math.ceil((deadline - Date.now()) / 1000)),
    shouldStop
  )

  while (!shouldStop() && Date.now() < deadline) {
    let nextSequence = retrySequence
    while (!shouldStop() && Date.now() < deadline && nextSequence <= retrySequence) {
      await new Promise(resolve => setTimeout(resolve, 350))
      nextSequence = await turnstileRetrySequence(page)
    }
    if (shouldStop() || nextSequence <= retrySequence) break
    retrySequence = nextSequence
    logger.info(`[relay-checkin-plugin] Turnstile 组件已重置，开始第 ${retrySequence + 1} 次自动点击`)
    const didClick = await autoClickTurnstileCheckbox(
      page,
      Math.max(1, Math.ceil((deadline - Date.now()) / 1000)),
      shouldStop
    )
    clicked ||= didClick
  }
  return clicked
}


/**
 * 在站点页面上下文内渲染 Cloudflare Turnstile 挑战并获取 token
 * @returns {Promise<{token: string|null, stage: string, reason: string, errorCode?: string, detail?: string}>}
 */
export async function solveTurnstile(page, siteKey, timeoutSec, { interactive = false, host = '' } = {}) {
  try {
    const evaluating = page.evaluate(async ({ siteKey, timeoutSec, interactive, host }) => {
      const deadline = Date.now() + timeoutSec * 1000
      const wait = ms => new Promise(resolve => setTimeout(resolve, ms))
      const responseInput = () => document.querySelector('input[name="cf-turnstile-response"]')?.value || ''
      // 可见模式始终渲染自己的组件，确保用户看到的是当前签到所需的验证；
      // 无头模式优先复用站点组件，保留站点可能附带的 action / cData。
      const existingWidget = interactive ? null : document.querySelector('.cf-turnstile, [data-sitekey]')

      // 优先等待站点自己的组件，以保留 action / cData 等站点参数。
      if (existingWidget) {
        while (Date.now() < deadline) {
          const token = responseInput()
          if (token) return { token, stage: 'site-widget', reason: 'token' }
          await wait(500)
        }
        return { token: null, stage: 'site-widget', reason: 'timeout' }
      }

      try {
        const waitForApi = async () => {
          while (Date.now() < deadline) {
            if (window.turnstile?.render) return true
            await wait(100)
          }
          return false
        }
        if (!window.turnstile?.render) {
          // 页面被 window.stop() 截断时可能残留一个永远不会完成的 script 标签。
          // API 尚未就绪就移除残留并重新加载，避免继续等到总超时。
          document.querySelectorAll('script[src*="challenges.cloudflare.com/turnstile/v0/api.js"]')
            .forEach(script => script.remove())
          const script = document.createElement('script')
          script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'
          script.async = true
          script.defer = true
          document.head.appendChild(script)
          if (!await waitForApi()) {
            return { token: null, stage: 'script', reason: 'load-timeout' }
          }
        }

        let el = null
        let statusEl = null
        if (interactive) {
          const overlay = document.createElement('div')
          overlay.id = 'relay-checkin-turnstile'
          overlay.style.cssText = [
            'position:fixed', 'inset:0', 'z-index:2147483647', 'display:grid',
            'place-items:center', 'background:#f3f1ea', 'color:#18231d',
            'font-family:"Microsoft YaHei","PingFang SC",sans-serif'
          ].join(';')
          const panel = document.createElement('main')
          panel.style.cssText = [
            'width:min(520px,calc(100vw - 40px))', 'box-sizing:border-box',
            'padding:34px 38px', 'background:#fff', 'border:1px solid #cad0c8',
            'box-shadow:0 18px 50px rgba(30,42,35,.16)', 'text-align:center'
          ].join(';')
          const title = document.createElement('h1')
          title.textContent = '中转站签到验证'
          title.style.cssText = 'margin:0 0 10px;font-size:24px;font-weight:700;letter-spacing:0'
          const site = document.createElement('div')
          site.textContent = host
          site.style.cssText = 'margin-bottom:18px;color:#587063;font-size:14px;word-break:break-all'
          const tip = document.createElement('p')
          tip.textContent = `插件会先自动尝试下方验证；若复选框仍停留，请在 ${timeoutSec} 秒内手动勾选。通过后会立即提交签到并关闭窗口。`
          tip.style.cssText = 'margin:0 0 24px;line-height:1.7;font-size:15px;color:#303b35'
          el = document.createElement('div')
          el.style.cssText = 'min-height:70px;display:grid;place-items:center'
          statusEl = document.createElement('p')
          statusEl.id = 'relay-checkin-turnstile-status'
          statusEl.dataset.retry = '0'
          statusEl.textContent = '正在加载验证组件...'
          statusEl.style.cssText = 'margin:20px 0 0;color:#6a746e;font-size:13px'
          panel.append(title, site, tip, el, statusEl)
          overlay.appendChild(panel)
          document.body.appendChild(overlay)
          document.title = `请完成签到验证 - ${host}`
        } else {
          el = document.createElement('div')
          el.style.minHeight = '70px'
          el.style.display = 'grid'
          el.style.placeItems = 'center'
          document.body.appendChild(el)
        }
        el.scrollIntoView({ block: 'center', inline: 'center' })

        const left = Math.max(1000, deadline - Date.now())
        return await new Promise(resolve => {
          let settled = false
          let widgetId = null
          let retryCount = 0
          let lastErrorCode = ''
          let retryTimer = null
          let retryPending = false
          const finish = result => {
            if (settled) return
            settled = true
            clearTimeout(timer)
            clearTimeout(retryTimer)
            resolve(result)
          }
          const timer = setTimeout(() => finish(lastErrorCode
            ? {
                token: null,
                stage: 'explicit-widget',
                reason: 'error-callback',
                errorCode: lastErrorCode,
                retries: retryCount
              }
            : { token: null, stage: 'explicit-widget', reason: 'timeout' }), left)
          const retryableError = code => /^(?:110600|110620|200500|3\d{5}|6\d{5})$/.test(code)
          const handleError = code => {
            const errorCode = code == null ? '' : String(code)
            lastErrorCode = errorCode
            if (retryPending) return
            if (retryableError(errorCode) && retryCount < 2 && Date.now() + 2000 < deadline) {
              retryCount++
              retryPending = true
              if (statusEl) {
                statusEl.textContent = `验证暂未通过（错误码 ${errorCode}），正在重置后重试 ${retryCount}/2...`
              }
              retryTimer = setTimeout(() => {
                try {
                  window.turnstile.reset(widgetId)
                  retryPending = false
                  if (statusEl) {
                    statusEl.dataset.retry = String(retryCount)
                    statusEl.textContent = `验证已重置，等待第 ${retryCount + 1} 次自动点击...`
                  }
                } catch (err) {
                  finish({
                    token: null,
                    stage: 'explicit-widget',
                    reason: 'render-error',
                    errorCode,
                    detail: String(err)
                  })
                }
              }, 1200)
              return
            }
            finish({
              token: null,
              stage: 'explicit-widget',
              reason: 'error-callback',
              errorCode,
              retries: retryCount
            })
          }
          try {
            widgetId = window.turnstile.render(el, {
              sitekey: siteKey,
              theme: 'light',
              callback: token => {
                if (statusEl) statusEl.textContent = '验证通过，正在提交签到...'
                finish({ token, stage: 'explicit-widget', reason: 'token' })
              },
              'error-callback': handleError,
              'expired-callback': () => finish({ token: null, stage: 'explicit-widget', reason: 'expired' }),
              'timeout-callback': () => handleError('110620')
            })
          } catch (err) {
            finish({ token: null, stage: 'explicit-widget', reason: 'render-error', detail: String(err) })
          }
        })
      } catch (err) {
        return { token: null, stage: 'script', reason: 'exception', detail: String(err) }
      }
    }, { siteKey, timeoutSec, interactive, host })

    let stopAutoClick = false
    const autoClick = interactive
      ? autoClickTurnstileWithRetries(page, timeoutSec, () => stopAutoClick)
      : null
    try {
      return await evaluating
    } finally {
      stopAutoClick = true
      if (autoClick) await autoClick.catch(() => {})
    }
  } catch (err) {
    return { token: null, stage: 'page', reason: 'evaluate-error', detail: String(err?.message || err) }
  }
}

/**
 * 脱离 CDP 的验证面板在页面里的固定位置。主进程断开调试连接后无法再查询元素坐标，
 * 只能把组件钉死在这里，再按窗口几何换算出屏幕坐标去点。
 * 复选框位于 widget 左上角内约 (22, 32)；实际位置优先从渲染后的容器读取。
 */
const DETACHED_WIDGET = { left: 240, top: 300, width: 300, height: 65, boxX: 22, boxY: 32 }

/**
 * 计算 widget 内复选框中心的视口坐标。真实矩形来自页面时优先使用它，固定面板则作为回退。
 */
export function detachedWidgetClickPoint(widget = null) {
  const box = widget || DETACHED_WIDGET
  if (widget?.point && Number.isFinite(widget.point.x) && Number.isFinite(widget.point.y)) {
    return { x: widget.point.x, y: widget.point.y }
  }
  const x = Number.isFinite(box.x) ? box.x : box.left
  const y = Number.isFinite(box.y) ? box.y : box.top
  const width = Number.isFinite(box.width) ? box.width : DETACHED_WIDGET.width
  const height = Number.isFinite(box.height) ? box.height : DETACHED_WIDGET.height
  return {
    x: x + Math.min(box.boxX ?? DETACHED_WIDGET.boxX, width / 2),
    y: y + Math.min(box.boxY ?? DETACHED_WIDGET.boxY, height / 2)
  }
}

/**
 * 页面内自治的「过码 + 签到」脚本，在 document-start 注入。
 *
 * 主进程会在导航后断开 CDP（Cloudflare 能感知调试会话，attach 期间挑战必被判 bot），
 * 之后就无法再操作页面，所以重试、提交、状态提示全部由这段脚本自己完成，
 * 结果写在 window.__relayCheckin 上，等挑战结束后主进程重连 CDP 取回。
 */
function detachedTurnstilePageScript(cfg) {
  const state = { round: 0, log: [], result: null, widget: null }
  window.__relayCheckin = state
  const log = (step, extra) => state.log.push({ at: Date.now(), step, ...(extra || {}) })

  const start = () => {
    // 固定标题：断开 CDP 后只能靠 xdotool 按标题找回这个窗口（读几何、抬到最前）
    try { document.title = cfg.windowTag } catch (err) { /* 少数站点锁死 title */ }
    const overlay = document.createElement('div')
    overlay.style.cssText = 'position:fixed;inset:0;z-index:2147483646;background:#f4f2ec;'
      + 'font-family:"Microsoft YaHei","PingFang SC",sans-serif;color:#1d2b23'
    const tip = document.createElement('div')
    tip.style.cssText = `position:fixed;left:${cfg.left}px;top:${cfg.top - 92}px;max-width:520px;`
      + 'font-size:17px;line-height:1.7;z-index:2147483647'
    tip.textContent = `${cfg.title}：请勾选下方的「我是人类」，验证通过后会自动提交签到。`
    const status = document.createElement('div')
    status.style.cssText = `position:fixed;left:${cfg.left}px;top:${cfg.top + 90}px;max-width:520px;`
      + 'font-size:15px;line-height:1.7;color:#4b6152;z-index:2147483647'
    status.textContent = '正在加载验证组件...'
    const holder = document.createElement('div')
    holder.id = 'relay-checkin-turnstile-holder'
    holder.style.cssText = `position:fixed;left:${cfg.left}px;top:${cfg.top}px;z-index:2147483647`
    overlay.append(tip, holder, status)
    document.body.appendChild(overlay)

    const recordWidget = () => {
      const iframe = [...holder.querySelectorAll('iframe')].find(item => {
        try { return /challenges\.cloudflare\.com|turnstile/i.test(item.src || '') } catch { return false }
      })
      const rect = (iframe || holder).getBoundingClientRect()
      if (rect.width < 1 || rect.height < 1) return
      state.widget = {
        source: iframe ? 'iframe' : 'holder',
        x: Math.round(rect.x),
        y: Math.round(rect.y),
        width: Math.round(rect.width),
        height: Math.round(rect.height)
      }
    }

    const submit = async token => {
      log('token', { len: token.length })
      status.textContent = '验证通过，正在提交签到...'
      try {
        const url = cfg.checkinUrl + (cfg.checkinUrl.includes('?') ? '&' : '?')
          + 'turnstile=' + encodeURIComponent(token)
        const res = await fetch(url, { method: 'POST', headers: cfg.headers, credentials: 'include' })
        const text = await res.text()
        let json = null
        try { json = JSON.parse(text) } catch (err) { json = null }
        state.result = { status: res.status, json, body: json ? '' : text.slice(0, 300) }
        status.textContent = json?.message || `签到请求已完成（HTTP ${res.status}）`
        log('submitted', { status: res.status })
      } catch (err) {
        state.result = { status: 0, json: null, error: String(err?.message || err).slice(0, 200) }
        status.textContent = '签到请求发送失败'
        log('submit-failed')
      }
    }

    let widgetId = null
    let retries = 0
    const giveUp = code => {
      state.result = { status: 0, json: null, turnstileError: code }
      status.textContent = `验证未通过（${code}），已放弃`
    }
    const onFail = code => {
      log('challenge-failed', { code })
      if (retries >= cfg.maxRetries) return giveUp(code)
      retries++
      status.textContent = `验证未通过（${code}），正在重试 ${retries}/${cfg.maxRetries}...`
      // round 自增让主进程知道组件已复位、需要再点一次复选框
      setTimeout(() => {
        try {
          window.turnstile.reset(widgetId)
          state.round++
        } catch (err) {
          giveUp(code)
        }
      }, 1500)
    }
    const render = () => {
      try {
        widgetId = window.turnstile.render(holder, {
          sitekey: cfg.siteKey,
          theme: 'light',
          callback: submit,
          'error-callback': code => onFail(String(code)),
          'timeout-callback': () => onFail('timeout'),
          'expired-callback': () => onFail('expired')
        })
        state.round = 1
        recordWidget()
        requestAnimationFrame(recordWidget)
        setTimeout(recordWidget, 250)
        status.textContent = '请勾选复选框完成验证'
      } catch (err) {
        giveUp('render-error')
      }
    }

    if (window.turnstile?.render) return render()
    const s = document.createElement('script')
    s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'
    s.onload = () => {
      log('api-loaded')
      render()
    }
    s.onerror = () => giveUp('api-load-failed')
    document.head.appendChild(s)
  }

  if (document.readyState === 'loading') addEventListener('DOMContentLoaded', start)
  else start()
}

/**
 * 用户可见的过码失败原因：只说「怎么了 + 能怎么办」，
 * 错误码、超时秒数、无头/可见这些排障信息一律留在日志里。
 */
function turnstileFailureMessage(result, interactive = false) {
  if (result?.reason === 'error-callback') {
    if (/^[36]\d{5}$/.test(result.errorCode || '')) {
      return '站点的人机验证不放行呀，换个网络或者晚点再试~'
    }
    return '站点的人机验证没通过呀，晚点再试试~'
  }
  if (result?.stage === 'script') return '站点的人机验证没加载出来，晚点再试呀~'
  if (result?.reason === 'render-error' || result?.reason === 'evaluate-error') return '人机验证出岔子啦，晚点再试呀~'
  if (result?.reason === 'expired') return '验证过期啦，再来一次试试~'
  return interactive
    ? '人机验证没做完呀，要在机器人那台电脑上点一下哦'
    : '人机验证没过去呀'
}

const waitMs = ms => new Promise(resolve => setTimeout(resolve, ms))

/**
 * 找出正在占用某个浏览器档案目录的进程。
 *
 * Chrome 发现同一 --user-data-dir 已有实例时，会把命令行交给旧实例后自己静默退出
 * （stderr 只有一行「正在现有的浏览器会话中打开」）。而 Puppeteer 13 用 readline 收
 * stderr 却在进程 exit 时就 reject，那行输出往往还没被读到，于是只剩一句
 * "Failed to launch the browser process!"，无从判断原因。所以这里自己找持有者。
 * @param {string} userDataDir 档案目录
 * @param {boolean} orphanOnly 只算拉起它的进程已经消失的（pm2 restart / 崩溃留下的孤儿）
 */
export function profileHolderPids(userDataDir, { orphanOnly = false, platform = process.platform } = {}) {
  const processes = listProcesses({ platform })
  if (!processes.length) return []
  const alive = orphanOnly ? new Set(processes.map(item => item.pid)) : null
  const pids = []
  for (const item of processes) {
    if (item.pid === process.pid) continue
    if (orphanOnly && !isOrphanProcess(item, alive, platform)) continue
    if (!commandLineUsesProfile(item.command, userDataDir, platform)) continue
    pids.push(item.pid)
  }
  return pids
}

/**
 * 清掉占用档案目录的残留浏览器。一次性档案（#detached）只服务单次流程，启动前不该有
 * 任何持有者；池化档案只回收孤儿，避免动到同机另一个 Yunzai 实例正在用的窗口。
 * @returns {number} 实际清理掉的进程数
 */
export function reapProfileHolders(userDataDir, { orphanOnly = false, label = '浏览器' } = {}) {
  let killed = 0
  for (const pid of profileHolderPids(userDataDir, { orphanOnly })) {
    if (killProcessTree(pid)) killed++
  }
  if (killed) {
    logger.info(`[relay-checkin-plugin] 已清理占用${label}档案的残留进程（${killed} 个）：`
      + '这类残留会让 Chrome 把新窗口交给旧实例后静默退出，导致此后每次启动都失败')
  }
  return killed
}

/**
 * 重连 CDP 读一次页面里的自治状态。读完立刻断开，尽量缩短 attach 时间：
 * 挑战已经结束时 attach 无害，但仍在等待时被 attach 会直接判 bot。
 */
async function probeDetachedState(ws, host) {
  let browser = null
  try {
    const puppeteer = await getPuppeteer()
    browser = await withTimeout(
      puppeteer.connect({ browserWSEndpoint: ws, defaultViewport: null }),
      15000, '重连浏览器超时'
    )
    const pages = await withTimeout(browser.pages(), 15000, '读取页面列表超时')
    const page = pages.find(p => {
      try { return new URL(p.url()).hostname === host } catch { return false }
    }) || pages[0]
    if (!page) return null
    return await withTimeout(page.evaluate(() => {
      const s = window.__relayCheckin
      return s ? { round: s.round, result: s.result, log: s.log } : null
    }), 15000, '读取验证状态超时')
  } catch {
    return null
  } finally {
    try { browser?.disconnect() } catch { /* 已断开 */ }
  }
}

async function closeDetachedBrowser(ws, proc) {
  try {
    const puppeteer = await getPuppeteer()
    const browser = await withTimeout(
      puppeteer.connect({ browserWSEndpoint: ws }), 10000, '重连浏览器超时'
    )
    await withTimeout(browser.close(), 15000, '关闭浏览器超时')
    return
  } catch { /* 连不上就直接杀进程 */ }
  // 连整棵进程树一起收：只杀主进程会留下渲染子进程继续占着一次性档案目录
  if (proc?.pid) killProcessTree(proc.pid)
}

/**
 * 在仍保持 attach 的短窗口里读取实际 Turnstile 容器尺寸。自治脚本把组件放在固定
 * holder 中，组件若藏在 closed shadow root，holder 仍会反映真实布局尺寸；取不到时
 * 调用方继续使用固定回退坐标。
 */
async function readDetachedWidget(page, timeoutMs = 6000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const remaining = deadline - Date.now()
    const exact = await readDetachedCheckboxPoint(page, Math.min(1200, remaining))
    if (exact) return exact
    const holder = await withTimeout(page.evaluate(() => {
      const holder = document.getElementById('relay-checkin-turnstile-holder')
      if (!holder) return null
      const iframe = [...holder.querySelectorAll('iframe')].find(item => {
        try { return /challenges\.cloudflare\.com|turnstile/i.test(item.src || '') } catch { return false }
      })
      const rect = (iframe || holder).getBoundingClientRect()
      if (rect.width < 1 || rect.height < 1) return null
      return {
        source: iframe ? 'iframe' : 'holder',
        x: Math.round(rect.x),
        y: Math.round(rect.y),
        width: Math.round(rect.width),
        height: Math.round(rect.height)
      }
    }), Math.min(1000, Math.max(1, deadline - Date.now())), '读取 Turnstile 容器坐标超时').catch(() => null)
    if (holder) return holder
    await waitMs(250)
  }
  return null
}

/**
 * 在断开 CDP 前借助无障碍树读取 Turnstile iframe 内真实 checkbox 的视口坐标。
 * iframe 往往藏在 closed shadow root，页面 DOM 看不到它，但 frame tree/AX tree 仍可见。
 */
async function readDetachedCheckboxPoint(page, timeoutMs = 1200) {
  const deadline = Date.now() + timeoutMs
  const frames = typeof page.frames === 'function'
    ? page.frames().filter(frame => /challenges\.cloudflare\.com|turnstile/i.test(String(frame.url?.() || '')))
    : []
  for (const frame of frames) {
    const remaining = deadline - Date.now()
    if (remaining <= 0) break
    let owner = null
    try {
      let ownerBox = null
      if (typeof frame?.frameElement === 'function') {
        owner = await withTimeout(frame.frameElement(), Math.min(700, remaining), '定位 Turnstile iframe 超时')
        ownerBox = owner
          ? await withTimeout(owner.boundingBox(), Math.min(700, Math.max(1, deadline - Date.now())), '读取 Turnstile iframe 坐标超时')
          : null
      } else {
        ownerBox = await legacyFrameOwnerBox(page, frame, {
          timeoutMs: Math.min(700, Math.max(1, deadline - Date.now()))
        })
      }
      if (!ownerBox || ownerBox.width < 200 || ownerBox.height < 50) continue
      const ready = await turnstileCheckboxPoint(page, frame, ownerBox, {
        timeoutMs: Math.min(700, Math.max(1, deadline - Date.now()))
      })
      if (ready?.point) {
        return {
          source: 'ax-checkbox',
          x: Math.round(ownerBox.x),
          y: Math.round(ownerBox.y),
          width: Math.round(ownerBox.width),
          height: Math.round(ownerBox.height),
          point: {
            x: Math.round(ready.point.x),
            y: Math.round(ready.point.y)
          }
        }
      }
    } catch {
      // iframe/AX 树在重建时会短暂失效，交给下一轮轮询或 holder 回退
    } finally {
      try { await owner?.dispose?.() } catch { /* frame 可能已经重建 */ }
    }
  }
  return null
}

/**
 * 断开状态下的失败几乎没有可观测性：主进程没接管页面，也没人在窗口前看着。
 * 超时收尾时重连 CDP 留一份现场（这时挑战已经废了，attach 不再有副作用）：
 * 页面自治脚本的步骤日志、Turnstile 组件的实际位置、token 是否签发、指针最终落点，
 * 再存一张截图。远端用户只要把这几行日志发回来就能定性。
 * @param {object} diagnostic 本轮原生点击尝试与最后一次系统指针落点
 */
export async function dumpDetachedFailure(ws, host, display, diagnostic = {}) {
  let browser = null
  try {
    const puppeteer = await getPuppeteer()
    browser = await withTimeout(
      puppeteer.connect({ browserWSEndpoint: ws, defaultViewport: null }),
      15000, '重连浏览器超时'
    )
    const pages = await withTimeout(browser.pages(), 15000, '读取页面列表超时')
    const page = pages.find(item => {
      try { return new URL(item.url()).hostname === host } catch { return false }
    }) || pages[0]
    if (!page) return

    const snapshot = await withTimeout(page.evaluate(() => {
      const state = window.__relayCheckin
      const holder = document.getElementById('relay-checkin-turnstile-holder')
      const iframe = [...(holder?.querySelectorAll('iframe') || [])].find(item => {
        try { return /challenges\.cloudflare\.com|turnstile/i.test(item.src || '') } catch { return false }
      })
      const node = iframe || holder
      const rect = node?.getBoundingClientRect()
      const input = document.querySelector('input[name="cf-turnstile-response"]')
      return {
        round: state?.round ?? null,
        steps: (state?.log || []).map(item => (item.code ? `${item.step}(${item.code})` : item.step)),
        title: document.title,
        iframe: rect
          ? `${iframe ? 'iframe' : 'holder'} ${Math.round(rect.width)}x${Math.round(rect.height)} @视口(${Math.round(rect.x)},${Math.round(rect.y)})`
          : '未渲染',
        tokenLen: input?.value?.length || 0
      }
    }), 15000, '读取验证现场超时')

    const mouse = await nativeMouseLocation(display)
    const lastClick = diagnostic.lastClick
    const clickSummary = lastClick
      ? `｜点击尝试=${diagnostic.clickAttempts || 0}｜最后点击=${lastClick.clicked ? '命令成功' : '命令失败'}`
        + ` 目标=(${lastClick.x}, ${lastClick.y})｜落点=${lastClick.pointer || '未知'}`
      : `｜点击尝试=${diagnostic.clickAttempts || 0}｜最后点击=无`
    logger.warn(`[relay-checkin-plugin] ${host} 验证现场: 挑战轮次=${snapshot.round}`
      + `｜页面步骤=[${snapshot.steps.join(' → ') || '无'}]`
      + `｜Turnstile 组件=${snapshot.iframe}｜token 长度=${snapshot.tokenLen}`
      + `｜指针停在=${mouse || '未知'}｜标题=${snapshot.title}${clickSummary}`)

    const dir = path.join(dataPath(), 'turnstile-debug')
    fs.mkdirSync(dir, { recursive: true })
    const file = path.join(dir, `${Date.now()}-${host}.png`)
    await withTimeout(page.screenshot({ path: file }), 20000, '截图超时')
    logger.warn(`[relay-checkin-plugin] 现场截图已保存: ${file}`)
    // 只留最近 5 张，文件名以时间戳开头，字典序即时间序
    const shots = fs.readdirSync(dir).filter(name => name.endsWith('.png')).sort()
    for (const name of shots.slice(0, Math.max(0, shots.length - 5))) {
      try { fs.unlinkSync(path.join(dir, name)) } catch { /* 已被清理 */ }
    }
  } catch (err) {
    logger.warn(`[relay-checkin-plugin] 取回 ${host} 验证现场失败: ${err?.message || err}`)
  } finally {
    try { browser?.disconnect() } catch { /* 已断开 */ }
  }
}

function detachedResultToOutcome(result, timeoutSec) {
  if (result.turnstileError) {
    return {
      turnstileFailed: true,
      message: turnstileFailureMessage(
        { reason: 'error-callback', errorCode: result.turnstileError }, true
      ),
      detail: result
    }
  }
  if (!result.status) {
    return {
      turnstileFailed: true,
      message: '验证过了但签到没发出去呀，晚点再试试~',
      detail: result
    }
  }
  return { status: result.status, json: result.json }
}

/**
 * Puppeteer 13（TRSS-Yunzai 内置的版本）在启动失败时会把 Chrome 的 stderr 一起丢掉，
 * 只留一句 "Failed to launch the browser process!"。这里用同一套参数亲手跑一次 Chrome，
 * 把第一行真实错误抓出来，让远端日志能给出可读原因。探测进程最多活 6 秒。
 * @returns {Promise<string>} 可读原因，抓不到时为空串
 */
export function probeChromeLaunchStderr(executablePath, args, env) {
  return new Promise(resolve => {
    if (!executablePath) {
      resolve('')
      return
    }
    let proc = null
    try {
      const probeArgs = [...args, '--remote-debugging-port=0', 'about:blank']
      // Windows 上 Chrome 默认什么都不往 stderr 写，不显式打开日志就永远探不到原因
      if (process.platform === 'win32') probeArgs.unshift('--enable-logging=stderr', '--log-level=0')
      // 独立进程组：Chrome 真起来了要连渲染子进程一起收掉，否则探测自己就变成新的占用者
      proc = spawn(executablePath, probeArgs, {
        stdio: ['ignore', 'ignore', 'pipe'], env, detached: true, windowsHide: true
      })
    } catch (err) {
      resolve(String(err?.message || err))
      return
    }
    let text = ''
    let settled = false
    const finish = () => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      // Chrome 真起来了要连渲染子进程一起收掉，否则探测自己就变成新的档案占用者。
      // Linux 上探测进程独占一个进程组，负 pid 一次收整组；Windows 没有进程组信号，
      // 交给 killProcessTree 里的 taskkill /T
      try { process.kill(-proc.pid, 'SIGKILL') } catch { killProcessTree(proc.pid) }
      const lines = text.split('\n').map(item => item.trim()).filter(Boolean)
      resolve(
        lines.find(item => !item.startsWith('[') && !item.startsWith('DevTools listening'))
        || lines.find(item => /:(ERROR|FATAL):/.test(item))
        || ''
      )
    }
    const timer = setTimeout(finish, 6000)
    proc.stderr.on('data', chunk => {
      text += String(chunk)
      // 起得来会先打 DevTools listening，起不来则第一行就是原因，两种情况都不用等满 6 秒
      if (text.includes('\n')) setTimeout(finish, 300)
    })
    proc.once('error', err => {
      text += String(err?.message || err)
      finish()
    })
    proc.once('exit', () => setTimeout(finish, 200))
  })
}

/**
 * 启动一次性可见浏览器。这一步失败只能退回附着 CDP 的旧模式，而那条路在 Turnstile
 * 站点几乎必然被判机器人（用户要白等一个完整超时），所以宁可在这里多花几秒：
 * 启动前先清掉占用档案的残留实例，失败后探明真实原因、再清一次、重试一次。
 */
export async function launchDetachedBrowser(puppeteer, launchOptions, { host, executablePath }) {
  const userDataDir = launchOptions.userDataDir
  const label = `${host} 的一次性`
  reapProfileHolders(userDataDir, { label })
  let lastErr = null
  for (let attempt = 1; attempt <= 2; attempt++) {
    const launching = puppeteer.launch(launchOptions)
    try {
      return await withTimeout(launching, 70000, '浏览器启动超时（检查 Chrome 与虚拟显示是否可用）')
    } catch (err) {
      lastErr = err
      // 超时只是本进程放弃等待，Chrome 可能随后才起来：不收掉它，档案目录就被永久占住，
      // 之后每次启动都会静默失败——这正是「某次超时之后再也起不来」的成因
      launching.then(browser => browser.close().catch(() => {})).catch(() => {})
      if (attempt === 2) break
      const reason = await probeChromeLaunchStderr(
        executablePath,
        [...launchOptions.args, `--user-data-dir=${userDataDir}`],
        launchOptions.env || process.env
      )
      if (reason) logger.warn(`[relay-checkin-plugin] Chrome 启动失败的真实原因: ${reason}`)
      const cleaned = reapProfileHolders(userDataDir, { label })
      logger.info(`[relay-checkin-plugin] 重试启动 ${host} 的可见浏览器（第 2 次）`)
      await waitMs(cleaned ? 1500 : 500)
    }
  }
  throw lastErr
}

/**
 * 在浏览器与主进程断开连接的状态下过 Turnstile 并提交签到。
 *
 * 关键结论（实测 kktoken.cc / New API rc.25）：只要 CDP 处于 attach 状态，同一环境下
 * Turnstile 一律回 600010（检测到 bot 行为）——出口 IP、UA、stealth 脚本、点击方式都不是主因；
 * 一旦 browser.disconnect()，同样的页面立刻签发 token。所以这里把流程拆成三段：
 * ① attach 状态下注入自治脚本并导航（此时还没有挑战在跑）；
 * ② 断开 CDP，用系统级真实指针点复选框，页面自己完成挑战并提交签到；
 * ③ 挑战结束后重连 CDP 取回结果。
 *
 * 没有可用指针（macOS、缺 xdotool / PowerShell）时不自动点击，
 * 退化为「用户在弹出的窗口里手动勾选」。
 */
async function detachedTurnstileCheckin(account, { checkinPath, headers, validationHeaders, siteKey }, timeoutSec) {
  const cfg = getConfig()
  const safeUrl = await assertSafeRequestUrl(account.baseUrl)
  const host = safeUrl.hostname
  const checkinUrl = new URL(checkinPath, `${account.baseUrl}/`)
  await assertSafeRequestUrl(checkinUrl.toString())

  checkBreaker(host)
  await acquirePageSlot()
  let ws = ''
  let chromeProc = null
  try {
    const display = await ensureVirtualDisplay()
    const pointerDisplay = pointerDisplayFor(display)
    warnWindowsHeadlessSession()
    const puppeteer = await getPuppeteer()
    const proxy = parseProxy(proxyForHost(host, true))
    const executablePath = resolveBrowserExecutable(cfg.browser.executablePath)
    // 与 Sub2API 同一套「干净配方」：不加任何额外伪装或降级开关
    const args = [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-blink-features=AutomationControlled',
      '--lang=zh-CN',
      '--no-first-run',
      '--no-default-browser-check',
      // 虚拟屏没有窗口管理器，窗口尺寸只认 --window-size；留一圈余量让
      // innerWidth/screen.width 的关系与真实桌面一致
      '--window-size=1600,1000',
      // Xvfb 无 GPU，软件光栅化 WebGL（否则 WebGL 探针直接失败）
      '--enable-unsafe-swiftshader'
    ]
    if (!display && process.env.WAYLAND_DISPLAY && pointerDisplay) {
      // Wayland 桌面：默认会走 Wayland 后端，xdotool 驱动不了；改走 XWayland 才能自动勾选
      args.push('--ozone-platform=x11')
    }
    if (proxy?.server) {
      args.push(`--proxy-server=${proxy.server}`, '--proxy-bypass-list=<-loopback>')
    }
    const launchOptions = {
      headless: false,
      args,
      ignoreDefaultArgs: ['--enable-automation'],
      defaultViewport: null,
      timeout: 60000,
      protocolTimeout: (timeoutSec + 120) * 1000,
      // 独立 profile：常驻可见浏览器可能正持有池化 profile 的目录锁，共用会让本次启动失败
      userDataDir: interactiveProfilePath(`${host}#detached`, proxy?.server, executablePath || 'puppeteer-bundled')
    }
    if (executablePath) launchOptions.executablePath = executablePath
    if (display) launchOptions.env = { ...process.env, DISPLAY: display }
    // Puppeteer 13 不会替调用方建档案目录，交给 Chrome 自己创建时失败只会静默退出
    fs.mkdirSync(launchOptions.userDataDir, { recursive: true })

    const browser = await launchDetachedBrowser(puppeteer, launchOptions, { host, executablePath })
    chromeProc = browser.process()
    ws = browser.wsEndpoint()

    let geom = null
    let widget = null
    try {
      const page = await newPageSafe(browser, 30000, { reuseBlank: true })
      if (proxy?.auth) await withTimeout(page.authenticate(proxy.auth), 15000, '设置代理认证超时')
      await injectSessionCookies(page, host, headers)
      await withTimeout(page.setBypassCSP(true), 15000, '设置 Turnstile 页面策略超时')
      await withTimeout(page.evaluateOnNewDocument(detachedTurnstilePageScript, {
        siteKey,
        checkinUrl: checkinUrl.toString(),
        headers: validationHeaders,
        left: DETACHED_WIDGET.left,
        top: DETACHED_WIDGET.top,
        title: `${account.name || host} 签到验证`,
        windowTag: `relay-checkin ${host}`,
        maxRetries: 2
      }), 15000, '注入验证脚本超时')
      await navigateForTurnstile(page, account.baseUrl)
      widget = await readDetachedWidget(page)
      geom = await withTimeout(page.evaluate(() => ({
        screenX: window.screenX,
        screenY: window.screenY,
        innerWidth: window.innerWidth,
        innerHeight: window.innerHeight,
        outerWidth: window.outerWidth,
        outerHeight: window.outerHeight,
        frameW: window.outerWidth - window.innerWidth,
        frameH: window.outerHeight - window.innerHeight
      })), 15000, '读取浏览器窗口位置超时')
    } finally {
      // 无论导航成败都要脱离 CDP，attach 状态下挑战一定过不去
      try { browser.disconnect() } catch { /* 已断开 */ }
    }

    const widgetBox = widget || {
      source: 'fixed-fallback',
      x: DETACHED_WIDGET.left,
      y: DETACHED_WIDGET.top,
      width: DETACHED_WIDGET.width,
      height: DETACHED_WIDGET.height
    }
    const { x: viewX, y: viewY } = detachedWidgetClickPoint(widgetBox)
    // 断开 CDP 后再问系统要窗口几何：这是唯一不依赖 Chrome 自报数据的坐标来源
    const windowGeom = await nativeWindowGeometry(
      pointerDisplay,
      `relay-checkin ${host}`,
      { pid: chromeProc?.pid }
    )
    const origin = detachedClickOrigin(geom, windowGeom)
    const [boxX, boxY] = origin
      ? [origin.x + viewX, origin.y + viewY]
      : (geom ? viewportToScreen(geom, viewX, viewY) : [viewX, viewY])
    const autoClick = Boolean(pointerDisplay) && !nativePointerUnavailable()
    logger.info(`[relay-checkin-plugin] ${host} 已断开调试连接进入人机验证，`
      + `${autoClick ? '将自动勾选复选框' : '请在弹出的浏览器窗口中手动勾选'}（最多 ${timeoutSec} 秒）`)
    if (autoClick) {
      logger.info(`[relay-checkin-plugin] 复选框屏幕坐标 (${boxX}, ${boxY})｜`
        + `显示环境: ${describePointerEnv(display, pointerDisplay)}｜`
        + `依据: ${origin ? `系统实测窗口 ${windowGeom.width}x${windowGeom.height} @(${windowGeom.x},${windowGeom.y})` : '页面自报（系统未给出窗口几何）'}｜`
        + `组件: ${widgetBox.source} ${widgetBox.width}x${widgetBox.height} @视口(${widgetBox.x},${widgetBox.y})｜`
        + `页面 inner ${geom?.innerWidth}x${geom?.innerHeight} outer ${geom?.outerWidth}x${geom?.outerHeight}`)
    }

    const deadline = Date.now() + timeoutSec * 1000
    let clickedRound = 0
    let round = 1
    let clickAttempts = 0
    let lastClick = null
    let firstProbe = true
    let probeMisses = 0
    let reportedProgress = false
    while (Date.now() < deadline) {
      if (autoClick && round > clickedRound) {
        // 组件渲染完还要「像人一样」停一会儿再点：立刻点击本身就是行为特征。
        // 首轮还要留出 api.js 加载 + render 的时间，点在未就绪的组件上会直接判失败。
        await waitMs((clickedRound === 0 ? 6000 : 3500) + Math.floor(Math.random() * 3000))
        const clicked = await nativeClick(pointerDisplay, boxX, boxY, { windowId: windowGeom?.windowId })
        clickAttempts++
        const pointer = await nativeMouseLocation(pointerDisplay)
        lastClick = { clicked, x: boxX, y: boxY, pointer }
        const clickDetail = `目标=(${boxX}, ${boxY})｜指针=${pointer || '未知'}｜窗口=${windowGeom?.windowId || '未定位'}｜组件=${widgetBox.source}`
        if (clicked) {
          clickedRound = round
          logger.mark(`[relay-checkin-plugin] 已执行系统指针点击 ${host} 的验证复选框（第 ${round} 次挑战，${clickDetail}）`)
        } else {
          logger.warn(`[relay-checkin-plugin] 系统指针点击 ${host} 失败（第 ${round} 次尝试，${clickDetail}）`)
        }
      }
      // 探测要重连 CDP，attach 本身会让正在进行的挑战被判 bot，所以第一次探测
      // 必须等过 token 的正常签发耗时（实测 7~8 秒），之后也保持低频
      await waitMs(firstProbe ? 15000 : 6000)
      firstProbe = false
      const state = await probeDetachedState(ws, host)
      if (state?.result) {
        logger.info(`[relay-checkin-plugin] ${host} 页面内验证流程结束: `
          + (state.log || []).map(item => (item.code ? `${item.step}(${item.code})` : item.step)).join(' → '))
        return detachedResultToOutcome(state.result, timeoutSec)
      }
      // 读不到状态和「读到了但挑战还没结束」是两码事，日志里必须能分开：
      // 前者说明浏览器或注入脚本出了问题，后者只是还在等 Cloudflare
      if (!state) {
        probeMisses++
        if (probeMisses === 1 || probeMisses % 5 === 0) {
          logger.warn(`[relay-checkin-plugin] 读不到 ${host} 页面内的验证状态（第 ${probeMisses} 次），`
            + '可能是窗口已关闭或注入脚本未生效')
        }
        // 一次都没读到过、又连续失败一分钟：窗口或注入脚本已经废了，
        // 没必要把剩下的超时耗完（探测失败说明没连上，不存在打断挑战的风险）
        if (!reportedProgress && probeMisses >= 10) {
          await dumpDetachedFailure(ws, host, pointerDisplay, { clickAttempts, lastClick })
          return {
            turnstileFailed: true,
            message: '人机验证的窗口没了呀，晚点再试试~',
            detail: { stage: 'detached', reason: 'probe-unreachable', probeMisses, clickAttempts }
          }
        }
      } else if (!reportedProgress) {
        reportedProgress = true
        logger.info(`[relay-checkin-plugin] ${host} 验证进行中: 轮次=${state.round}`
          + `｜步骤=[${(state.log || []).map(item => (item.code ? `${item.step}(${item.code})` : item.step)).join(' → ') || '无'}]`)
      }
      if (state?.round) round = state.round
    }
    await dumpDetachedFailure(ws, host, pointerDisplay, { clickAttempts, lastClick })
    return {
      turnstileFailed: true,
      message: `人机验证没做完呀${autoClick ? '，晚点再试试~' : '，要在机器人那台电脑上点一下哦'}`,
      detail: { stage: 'detached', reason: 'timeout', clickAttempts }
    }
  } finally {
    if (ws || chromeProc) await closeDetachedBrowser(ws, chromeProc)
    scheduleVirtualDisplayRelease()
    releasePageSlot()
  }
}

/**
 * 在一种浏览器模式内完成 Turnstile 获取与签到提交。token 由 Cloudflare 绑定当前
 * 浏览器上下文和出口网络，因此必须在同一个页面里立即提交，不能跨模式搬运。
 */
async function runTurnstileAttempt(account, { checkinPath, headers, validationHeaders = headers, siteKey }, { interactive, timeoutSec }) {
  const host = new URL(account.baseUrl).hostname
  return await withPage(host, async page => {
    await injectSessionCookies(page, host, headers)
    await withTimeout(page.setBypassCSP(true), 15000, '设置 Turnstile 页面策略超时')
    await navigateForTurnstile(page, account.baseUrl)

    const attempt = await solveTurnstile(page, siteKey, timeoutSec, { interactive, host })
    if (!attempt.token) {
      return {
        turnstileFailed: true,
        message: turnstileFailureMessage(attempt, interactive),
        detail: attempt
      }
    }

    logger.info(`[relay-checkin-plugin] Turnstile ${interactive ? '可见' : '无头'}验证已签发 token，正在提交签到接口`)
    const url = new URL(checkinPath, `${account.baseUrl}/`)
    url.searchParams.set('turnstile', attempt.token)
    return await pageFetch(page, url.toString(), { method: 'POST', headers: validationHeaders })
  }, { interactive, profileKey: host, trackResult: false })
}

function boundedSeconds(value, fallback, min, max) {
  const n = Number(value)
  return Math.max(min, Math.min(Number.isFinite(n) ? n : fallback, max))
}

export function turnstileBrowserMode(browser = {}) {
  return browser.turnstileInteractive === false ? 'headless' : 'interactive'
}

/**
 * 手动指令的浏览器总预算：可见接管开启时直接走可见模式；关闭时才走无头模式。
 * 由调用层和测试共用，避免两处 clamp 漂移后外层先于浏览器超时。
 */
export function browserHangBudgetMs(browser = {}) {
  const slotSec = boundedSeconds(browser.slotWaitSec, 120, 30, 600)
  const quickSec = boundedSeconds(browser.turnstileTimeoutSec, 30, 5, 120)
  const interactiveEnabled = turnstileBrowserMode(browser) === 'interactive'
  const interactiveSec = !interactiveEnabled
    ? 0
    : boundedSeconds(browser.turnstileInteractiveTimeoutSec, 120, 30, 600)
  const powSec = boundedSeconds(browser.powTimeoutSec, 120, 15, 300)
  const activeSec = Math.max(interactiveEnabled ? interactiveSec : quickSec, powSec)
  // 300 秒覆盖 launch/newPage/初始化/导航/接口提交/关闭的硬超时余量。
  return (slotSec + activeSec + 300) * 1000
}

/**
 * Turnstile 站点浏览器签到：允许可见接管时直接使用持久可见浏览器，避免先进行一次
 * 大概率失败的无头挑战并污染同一出口的风险评分；关闭可见接管时才使用无头模式。
 * @param {object} account 账号
 * @param {object} opts { checkinPath: 签到接口路径, headers: 鉴权请求头, siteKey: Turnstile site key }
 * @returns {Promise<{status: number, json: object|null}|{turnstileFailed: true}>}
 */
export async function turnstileCheckin(account, { checkinPath, headers, validationHeaders = headers, siteKey }) {
  const cfg = getConfig()
  const host = new URL(account.baseUrl).hostname
  const quickTimeoutSec = boundedSeconds(cfg.browser.turnstileTimeoutSec, 30, 5, 120)
  const interactiveTimeoutSec = boundedSeconds(cfg.browser.turnstileInteractiveTimeoutSec, 120, 30, 600)

  if (turnstileBrowserMode(cfg.browser) === 'interactive') {
    logger.info(`[relay-checkin-plugin] 将直接打开可见浏览器处理 ${host}，请在机器人运行设备上于 ${interactiveTimeoutSec} 秒内完成验证`)
    let interactive
    try {
      interactive = await detachedTurnstileCheckin(
        account,
        { checkinPath, headers, validationHeaders, siteKey },
        interactiveTimeoutSec
      )
    } catch (err) {
      // 脱离调试连接的流程只在启动/导航阶段可能抛异常；退回旧的常驻可见浏览器再试一次，
      // 让「浏览器起不来」和「挑战没过」两类失败仍有各自的可读原因。
      const detail = err?.message || String(err)
      logger.warn(`[relay-checkin-plugin] 脱离调试连接的可见验证未能启动: ${detail}`)
      logger.warn('[relay-checkin-plugin] 退回附着调试连接的可见浏览器；Turnstile 对 CDP 连接极敏感，'
        + '这一轮很可能卡在「等待复选框可交互」直到超时')
      try {
        interactive = await runTurnstileAttempt(
          account,
          { checkinPath, headers, validationHeaders, siteKey },
          { interactive: true, timeoutSec: interactiveTimeoutSec }
        )
      } catch (fallbackErr) {
        const fallbackDetail = fallbackErr?.message || String(fallbackErr)
        interactive = {
          turnstileFailed: true,
          message: '浏览器起不来呀，晚点再试试~',
          detail: { stage: 'interactive-browser', reason: 'exception', detail: fallbackDetail }
        }
      }
    }

    const ok = browserResultOk(interactive)
    noteResult(host, ok)
    if (interactive.turnstileFailed) {
      logger.warn(`[relay-checkin-plugin] Turnstile 可见浏览器接管未完成: ${interactive.message}`)
    } else {
      logger.info('[relay-checkin-plugin] Turnstile 已通过可见浏览器完成并提交签到')
    }
    return interactive
  }

  let quick
  try {
    quick = await runTurnstileAttempt(
      account,
      { checkinPath, headers, validationHeaders, siteKey },
      { interactive: false, timeoutSec: quickTimeoutSec }
    )
  } catch (err) {
    const detail = err?.message || String(err)
    quick = {
      turnstileFailed: true,
      message: '浏览器起不来呀，晚点再试试~',
      detail: { stage: 'headless-browser', reason: 'exception', detail }
    }
  }
  if (!quick.turnstileFailed) {
    noteResult(host, browserResultOk(quick))
    return quick
  }

  logger.info(`[relay-checkin-plugin] Turnstile 无头尝试未通过: ${quick.message}`)
  const result = {
    ...quick,
    message: `${quick.message}（让主人在配置里打开「可见浏览器过 Turnstile」会好很多哦）`
  }
  noteResult(host, false)
  return result
}

/**
 * Sub2API 专用「干净配方」浏览器路径。
 *
 * 实测（某 Sub2API 站点）：走上面的 withPage 通道必定拿不到 Turnstile token
 * ——STEALTH_SCRIPT 与 setUserAgent 反而被 Cloudflare 判为自动化风险（error-callback
 * 300010），或者组件根本不渲染 iframe 直到超时。不注入任何反检测脚本、不改 UA、
 * 只等站点自己的 widget 往 input[name=cf-turnstile-response] 里写值，反而稳定出 token。
 *
 * 因此这里不复用 withPage / getBrowser，而是单独启一个一次性实例：既保证配方不被
 * 上面的公共初始化污染，也不会把这套（对其他站点无效的）配方带进 AnyRouter 等已有流程。
 * 页面并发闸门与熔断器仍然共用，避免绕过全局资源约束。
 */
let xvfbProc = null
let xvfbReleaseTimer = null

const XVFB_SCREEN = '1920x1080x24'

/**
 * 让 Xvfb 自己挑一个空闲编号（-displayfd 会把选中的号写到给定 fd）。
 * 比逐个试编号可靠：既避开与其他程序抢号，也不会被上次异常退出留下的
 * /tmp/.X<n>-lock 卡住（那种 stale lock 会让固定编号永久不可用）。
 * @returns {Promise<object|null>} 启动成功的子进程（带 display 字段），旧版 Xvfb 无此参数时返回 null
 */
function spawnXvfbAutoDisplay() {
  return new Promise(resolve => {
    let proc = null
    try {
      proc = spawn('Xvfb', ['-displayfd', '1', '-screen', '0', XVFB_SCREEN, '-nolisten', 'tcp'], {
        stdio: ['ignore', 'pipe', 'ignore'],
        detached: false
      })
    } catch {
      resolve(null)
      return
    }
    let settled = false
    let out = ''
    const finish = value => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (!value) {
        try { proc.kill() } catch { /* 已退出 */ }
      }
      resolve(value)
    }
    const timer = setTimeout(() => finish(null), 8000)
    proc.stdout.on('data', chunk => {
      out += String(chunk)
      const num = out.trim().match(/^\d+/)?.[0]
      if (!num || settled) return
      proc.display = `:${num}`
      proc.unref()
      // -displayfd 写号时监听 socket 已建立，但机器负载高时仍见过 Chrome 抢在
      // socket 可见之前连上去（报 Missing X server 且被旧版 Puppeteer 吞掉），补一层确认
      waitForXSocket(num).then(() => finish(proc))
    })
    proc.once('error', () => finish(null))
    proc.once('exit', () => finish(null))
  })
}

/**
 * 等 X server 的 unix socket 出现，最多等 timeoutMs；等不到也照常返回，
 * 让 Chrome 自己去报错，避免把可用的显示环境误判成不可用。
 */
async function waitForXSocket(num, timeoutMs = 3000) {
  const socket = `/tmp/.X11-unix/X${num}`
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (fs.existsSync(socket)) return true
    await waitMs(100)
  }
  return false
}

/**
 * 杀掉本插件自己留下的孤儿 Xvfb（父进程已是 1，说明当初拉起它的 Yunzai 进程已经没了）。
 * pm2 restart / kill -9 时子进程不会跟着退出，每次重启就多攒一个，几十次重启后
 * 会白占几百 MB 内存并把显示号耗光。只匹配本插件的固定参数，不动别人（含 xvfb-run）的实例。
 */
function reapOrphanXvfb() {
  for (const item of listProcesses()) {
    if (item.ppid !== 1) continue
    if (!item.command.startsWith(`Xvfb -displayfd 1 -screen 0 ${XVFB_SCREEN}`)) continue
    try {
      process.kill(item.pid, 'SIGTERM')
      logger.info(`[relay-checkin-plugin] 已回收上次运行残留的虚拟显示进程（pid ${item.pid}）`)
    } catch { /* 已退出或无权限 */ }
  }
}

/**
 * 验证结束后延迟回收虚拟显示：连续签到多个站点时会复用同一个 Xvfb，
 * 所以不立刻关；池里还留着常驻可见浏览器时也要继续等，否则窗口会失去 X server。
 */
function scheduleVirtualDisplayRelease(ms = 120000) {
  if (!xvfbProc) return
  if (xvfbReleaseTimer) clearTimeout(xvfbReleaseTimer)
  xvfbReleaseTimer = setTimeout(() => {
    xvfbReleaseTimer = null
    if (!xvfbProc) return
    for (const pool of pools.values()) {
      if (pool.instance || pool.activeTasks > 0 || pool.launching) {
        scheduleVirtualDisplayRelease(ms)
        return
      }
    }
    const proc = xvfbProc
    xvfbProc = null
    try { proc.kill() } catch { /* 已退出 */ }
  }, ms)
  xvfbReleaseTimer.unref?.()
}

/**
 * Turnstile 在纯无头（headless）下会静默卡死，必须有真实显示环境。
 * Linux 服务器上没有桌面时自动拉一个 Xvfb 虚拟屏（仅本进程使用，退出时回收）。
 * @returns {string|null} 需要注入子进程的 DISPLAY，null 表示沿用当前环境
 */
async function ensureVirtualDisplay() {
  if (process.platform !== 'linux') return null
  if (process.env.DISPLAY || process.env.WAYLAND_DISPLAY) return null
  if (xvfbReleaseTimer) {
    clearTimeout(xvfbReleaseTimer)
    xvfbReleaseTimer = null
  }
  if (xvfbProc && !xvfbProc.killed && xvfbProc.exitCode === null) return xvfbProc.display
  reapOrphanXvfb()

  // 不能复用机器上已有的 display：xvfb-run 起的实例带 -auth <Xauthority>，
  // 本进程没有那份 auth cookie，Chrome 连上去会报 "Missing X server"。因此始终自己起一个。
  const auto = await spawnXvfbAutoDisplay()
  if (auto) {
    xvfbProc = auto
    logger.info(`[relay-checkin-plugin] 已启动虚拟显示 ${auto.display} 用于人机验证（无桌面服务器）`)
    return auto.display
  }

  // 旧版 Xvfb 不认 -displayfd：退回从 :99 往上找没被占用的编号
  const failures = []
  for (let num = 99; num <= 108; num++) {
    const display = `:${num}`
    if (fs.existsSync(`/tmp/.X${num}-lock`)) continue
    const proc = spawn('Xvfb', [display, '-screen', '0', XVFB_SCREEN, '-nolisten', 'tcp'], {
      stdio: 'ignore',
      detached: false
    })
    const started = await new Promise(resolve => {
      // Xvfb 正常启动不会有任何输出，只能靠「没有立刻退出」判断
      const timer = setTimeout(() => resolve(true), 1200)
      proc.once('error', err => {
        clearTimeout(timer)
        failures.push(err?.code === 'ENOENT' ? 'Xvfb 未安装' : String(err?.message || err))
        resolve(false)
      })
      proc.once('exit', () => {
        clearTimeout(timer)
        failures.push(`${display} 启动失败（可能已被占用）`)
        resolve(false)
      })
    })
    if (!started) {
      // ENOENT 说明根本没装 Xvfb，换编号也没有意义
      if (failures.at(-1) === 'Xvfb 未安装') break
      continue
    }
    proc.display = display
    proc.unref()
    xvfbProc = proc
    logger.info(`[relay-checkin-plugin] 已启动虚拟显示 ${display} 用于人机验证（无桌面服务器）`)
    return display
  }
  throw new Error(`该站点验证需要显示环境，但本机既无图形桌面也无法启动 Xvfb（${failures[0] || '请安装 xvfb 包'}）`)
}

/**
 * 过 Turnstile 并在同一页面内完成 Sub2API 登录。
 * token 由 Cloudflare 绑定当前浏览器上下文与出口网络，必须在同一页里立刻用掉。
 *
 * @param {object} account 需含 baseUrl；tokenOnly 为 false 时还需 loginEmail / password
 * @param {object} opts { siteKey: 仅 tokenOnly 时用于自渲染组件, tokenOnly: 只取 token 不登录 }
 * @returns {Promise<{ok: true, data?: object, turnstileToken?: string}|{ok: false, msg: string}>}
 */
export async function sub2apiLogin(account, { siteKey = '', tokenOnly = false } = {}) {
  const cfg = getConfig()
  if (!cfg.browser.enable) {
    return { ok: false, msg: '这站登录要过人机验证，可主人把浏览器方案关了呀~' }
  }
  const safeUrl = await assertSafeRequestUrl(account.baseUrl)
  const host = safeUrl.hostname
  // 实测过码耗时 17~100 秒且波动大，沿用可见验证的额度（默认 120 秒）而不是
  // 无头的 30 秒，否则大部分尝试会在拿到 token 之前被掐断。
  const timeoutSec = boundedSeconds(cfg.browser.turnstileInteractiveTimeoutSec, 120, 30, 600)

  checkBreaker(host)
  await acquirePageSlot()
  let browser = null
  try {
    const display = await ensureVirtualDisplay()
    const puppeteer = await getPuppeteer()
    const proxy = parseProxy(proxyForHost(host, true))
    const executablePath = resolveBrowserExecutable(cfg.browser.executablePath)
    // 保持这份参数最小化：任何额外的伪装/降级开关都可能重新触发风险判定
    const args = [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-blink-features=AutomationControlled',
      '--lang=zh-CN',
      '--no-first-run',
      '--no-default-browser-check'
    ]
    if (proxy?.server) {
      args.push(`--proxy-server=${proxy.server}`, '--proxy-bypass-list=<-loopback>')
    }
    const launchOptions = {
      // 必须有头：无头模式下该站点的 Turnstile 组件不会签发 token
      headless: false,
      args,
      ignoreDefaultArgs: ['--enable-automation'],
      timeout: 60000,
      protocolTimeout: (timeoutSec + 120) * 1000
    }
    if (executablePath) launchOptions.executablePath = executablePath
    if (display) launchOptions.env = { ...process.env, DISPLAY: display }

    browser = await withTimeout(
      puppeteer.launch(launchOptions),
      70000,
      '浏览器启动超时（检查 Chrome 与虚拟显示是否可用）'
    )
    const page = await newPageSafe(browser, 30000)
    if (proxy?.auth) await withTimeout(page.authenticate(proxy.auth), 15000, '设置代理认证超时')
    await withTimeout(page.setViewport({ width: 1365, height: 900 }), 15000, '设置浏览器窗口超时')
    // 这里刻意不做：setUserAgent / evaluateOnNewDocument(STEALTH_SCRIPT) / setExtraHTTPHeaders

    logger.info(`[relay-checkin-plugin] Sub2API 人机验证启动: ${host}（最多 ${timeoutSec} 秒）`)
    await withTimeout(
      page.goto(`${safeUrl.origin}/login`, { waitUntil: 'domcontentloaded', timeout: 60000 }),
      70000,
      '打开登录页超时（网络或代理不通）'
    )

    const started = Date.now()
    const turnstileToken = await withTimeout(
      page.evaluate(async ({ timeoutMs, siteKey }) => {
        const wait = ms => new Promise(resolve => setTimeout(resolve, ms))
        const deadline = Date.now() + timeoutMs
        const fromInput = () => document.querySelector('input[name="cf-turnstile-response"]')?.value || ''
        // 首选站点自己渲染的组件：它带着站点配置的 action/cData，也最不容易被判风险
        while (Date.now() < deadline) {
          const value = fromInput()
          if (value) return value
          await wait(500)
        }
        // 站点页面没有组件（例如签到弹窗才渲染）时，用传入的 site key 自渲染兜底
        if (!siteKey || !window.turnstile?.render) return ''
        const el = document.createElement('div')
        document.body.appendChild(el)
        return await new Promise(resolve => {
          const timer = setTimeout(() => resolve(''), 30000)
          try {
            window.turnstile.render(el, {
              sitekey: siteKey,
              callback: token => {
                clearTimeout(timer)
                resolve(token)
              },
              'error-callback': () => {
                clearTimeout(timer)
                resolve('')
              }
            })
          } catch {
            clearTimeout(timer)
            resolve('')
          }
        })
      }, { timeoutMs: timeoutSec * 1000, siteKey }),
      (timeoutSec + 40) * 1000,
      '等待人机验证无响应'
    )

    const usedSec = ((Date.now() - started) / 1000).toFixed(1)
    if (!turnstileToken) {
      noteResult(host, false)
      logger.warn(`[relay-checkin-plugin] Sub2API 人机验证未通过（已等待 ${usedSec} 秒）`)
      return { ok: false, msg: '这站的人机验证没过去呀，它成功率本来就不稳，过一会儿再试试~' }
    }
    logger.info(`[relay-checkin-plugin] Sub2API 人机验证已签发 token（${usedSec} 秒）`)

    if (tokenOnly) {
      noteResult(host, true)
      return { ok: true, turnstileToken }
    }

    const login = await withTimeout(
      page.evaluate(async ({ origin, email, password, tk }) => {
        try {
          const res = await fetch(`${origin}/api/v1/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ email, password, turnstile_token: tk })
          })
          let json = null
          try { json = await res.json() } catch { /* 非 JSON 响应 */ }
          return { status: res.status, json }
        } catch (err) {
          return { status: 0, json: null, error: String(err) }
        }
      }, {
        origin: safeUrl.origin,
        email: String(account.loginEmail || '').trim(),
        password: String(account.password || ''),
        tk: turnstileToken
      }),
      ((cfg.request.timeout || 15) + 20) * 1000,
      '提交登录无响应'
    )

    // 站点响应统一包一层 { code, message, data }
    const body = login.json
    const data = body?.data
    if (login.status !== 200 || !data?.access_token) {
      noteResult(host, false)
      const msg = body?.message || body?.msg || login.error || `HTTP ${login.status}`
      if (body?.requires_2fa || data?.requires_2fa) {
        return { ok: false, msg: '这个账号开了两步验证，嘟嘟登不进去呀' }
      }
      return { ok: false, msg: `登录失败：${msg}` }
    }
    noteResult(host, true)
    return { ok: true, data, turnstileToken }
  } catch (err) {
    noteResult(host, false)
    return { ok: false, msg: err?.message || String(err) }
  } finally {
    if (browser) await withTimeout(browser.close(), 20000, '关闭浏览器超时').catch(() => {})
    scheduleVirtualDisplayRelease()
    releasePageSlot()
  }
}

/**
 * 关闭全部浏览器实例（供测试/退出时清理）
 */
export async function closeBrowser() {
  if (xvfbReleaseTimer) {
    clearTimeout(xvfbReleaseTimer)
    xvfbReleaseTimer = null
  }
  if (xvfbProc) {
    try { xvfbProc.kill() } catch { /* 已退出 */ }
    xvfbProc = null
  }
  for (const pool of pools.values()) {
    if (pool.idleTimer) clearTimeout(pool.idleTimer)
    pool.idleTimer = null
    const inst = pool.instance
    pool.instance = null
    try {
      await inst?.close()
    } catch {
      // 忽略
    }
  }
  pools.clear()
}
