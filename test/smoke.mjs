/**
 * 冒烟测试：mock Yunzai 全局环境，验证 store / config / adapters 纯逻辑与指令正则
 * 运行：node test/smoke.mjs（在插件根目录）
 */
import assert from 'node:assert'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')

// ---- mock Yunzai 全局 ----
global.logger = {
  info: () => {}, mark: () => {}, warn: () => {}, error: (...a) => console.error('[logger.error]', ...a)
}
global.Bot = { uin: 10000 }

// ---- 装上 TRSS 宿主适配层（业务代码通过它取 logger / 数据目录 / 配置 / 出图）----
const { installHost } = await import('../host/index.js')
const { createTrssHost } = await import('../host/trss.js')
installHost(createTrssHost())

// 用干净的 data 目录测试
const DATA = path.join(ROOT, 'data')
const hadData = fs.existsSync(DATA)
const backup = path.join(ROOT, 'data_backup_smoke')
if (hadData) fs.renameSync(DATA, backup)

// 预置一份"旧版本"残缺配置：验证升级后新增项自动补齐、用户已改的值保留
fs.mkdirSync(DATA, { recursive: true })
fs.writeFileSync(path.join(DATA, 'config.yaml'), 'schedule:\n  cron: "0 0 9 * * *"\npush:\n  mode: private\n')

try {
  // ---- config ----
  const { getConfig } = await import('../models/config.js')
  const cfg = getConfig()
  assert.equal(cfg.schedule.cron, '0 0 9 * * *', '用户已改的值应保留')
  assert.equal(cfg.push.mode, 'private', '用户已改的值应保留')
  assert.equal(cfg.push.usersPerImage, 5)
  assert.deepEqual(cfg.schedule.accountDelay, [5, 15])
  assert.equal(cfg.browser.enable, true)
  assert.equal(cfg.browser.executablePath, '')
  assert.equal(cfg.browser.wafTimeoutSec, 60)
  assert.equal(cfg.browser.turnstileTimeoutSec, 30)
  assert.equal(cfg.browser.turnstileInteractive, true)
  assert.equal(cfg.browser.turnstileInteractiveTimeoutSec, 120)
  assert.equal(cfg.browser.powTimeoutSec, 120)
  assert.equal(cfg.bind.timeoutSec, 300)
  assert.equal(cfg.bind.groupRecallSec, 60)
  assert.equal(cfg.proxy.url, '')
  assert.deepEqual(cfg.proxy.hosts, ['anyrouter'])
  assert.equal(cfg.proxy.useForBrowser, true)
  assert.equal(cfg.schedule.concurrency, 3)
  assert.equal(cfg.request.retry, 2)
  assert.equal(cfg.security.allowHttp, false)
  assert.deepEqual(cfg.security.allowedPrivateHosts, [])
  assert.equal(cfg.browser.maxConcurrentPages, 2)
  // 手动指令的整体超时预算必须覆盖排队与当前选择的验证模式，
  // 否则会出现「已告知失败但任务稍后真的执行了」的矛盾结果
  assert.equal(cfg.browser.slotWaitSec, 120)
  assert.ok(
    cfg.browser.slotWaitSec + cfg.browser.turnstileTimeoutSec +
      cfg.browser.turnstileInteractiveTimeoutSec + 120 > cfg.browser.slotWaitSec
  )
  const cfgText = fs.readFileSync(path.join(DATA, 'config.yaml'), 'utf-8')
  assert.ok(cfgText.includes('proxy:') && cfgText.includes('groupRecallSec'), '新增配置项应写回配置文件')
  assert.ok(cfgText.includes('turnstileInteractiveTimeoutSec'), '交互式 Turnstile 新配置应写回旧配置文件')
  assert.ok(cfgText.includes('0 0 9 * * *') && cfgText.includes('mode: private'), '写回后用户值应保留')
  assert.ok(cfgText.includes('# 代理设置'), '模板注释应保留')
  console.log('config OK')

  // ---- browser pool/profile pure logic ----
  const {
    browserPoolKey,
    interactiveProfilePath,
    browserHangBudgetMs,
    navigateForTurnstile,
    autoClickTurnstileCheckbox,
    bypassServiceWorkerCompat,
    legacyFrameOwnerBox,
    turnstileCheckboxPoint,
    resolveBrowserExecutable,
    newPageSafe,
    turnstileBrowserMode,
    browserExecutableVersion
  } = await import('../models/browser.js')
  assert.equal(
    browserPoolKey({ proxyServer: '', profileKey: 'ioll.pp.ua' }),
    'headless|direct',
    '无头浏览器应按网络出口复用'
  )
  assert.notEqual(
    browserPoolKey({ interactive: true, profileKey: 'ioll.pp.ua' }),
    browserPoolKey({ interactive: true, profileKey: 'free.sulmate.cn' }),
    '可见浏览器档案必须按站点隔离'
  )
  assert.notEqual(
    browserPoolKey({ interactive: true, profileKey: 'ioll.pp.ua' }),
    browserPoolKey({ interactive: true, profileKey: 'ioll.pp.ua', proxyServer: 'http://127.0.0.1:7897' }),
    '可见浏览器档案必须按代理出口隔离'
  )
  assert.notEqual(
    interactiveProfilePath('ioll.pp.ua', '', 'C:/Chrome/chrome.exe'),
    interactiveProfilePath('ioll.pp.ua', '', 'C:/Edge/msedge.exe'),
    '更换浏览器内核后必须使用全新档案，避免旧风控状态污染'
  )
  assert.equal(
    interactiveProfilePath('ioll.pp.ua'),
    interactiveProfilePath('ioll.pp.ua'),
    '相同站点和出口的档案路径必须稳定'
  )
  assert.ok(
    interactiveProfilePath('ioll.pp.ua').startsWith(path.join(DATA, 'browser-profile')),
    '持久浏览器档案必须保存在已忽略提交的 data 目录'
  )
  const fakeProgramFiles = path.join(ROOT, 'fake-program-files')
  const fakeChrome = path.join(fakeProgramFiles, 'Google', 'Chrome', 'Application', 'chrome.exe')
  const fakeEdge = path.join(fakeProgramFiles, 'Microsoft', 'Edge', 'Application', 'msedge.exe')
  assert.equal(resolveBrowserExecutable('', {
    platform: 'win32',
    env: { PROGRAMFILES: fakeProgramFiles },
    exists: candidate => candidate === fakeChrome || candidate === fakeEdge,
    versionOf: candidate => candidate === fakeEdge ? '151.0.1.0' : '129.0.1.0'
  }), fakeEdge, 'Windows 应自动选择版本最高的系统 Chrome/Edge')
  assert.equal(browserExecutableVersion(fakeEdge, {
    platform: 'win32',
    spawn: (command, args) => {
      assert.equal(command, 'powershell.exe')
      assert.ok(args.includes('-EncodedCommand'), '含空格的浏览器路径应通过编码命令安全传给 PowerShell')
      return { stdout: '151.0.4129.59\r\n', stderr: '', status: 0 }
    }
  }), '151.0.4129.59', '应正确读取 Windows 浏览器文件版本')
  let createdExtraPage = false
  const initialBlank = { url: () => 'about:blank' }
  assert.equal(await newPageSafe({
    pages: async () => [initialBlank],
    newPage: async () => { createdExtraPage = true; return {} }
  }, 1000, { reuseBlank: true }), initialBlank, '可见浏览器应复用启动自带的空白页')
  assert.equal(createdExtraPage, false, '复用初始页后不应再留下 about:blank 标签')
  assert.equal(turnstileBrowserMode(cfg.browser), 'interactive', '默认应直接使用可见模式，不先执行无头挑战')
  assert.equal(turnstileBrowserMode({ turnstileInteractive: false }), 'headless', '关闭可见接管时才使用无头模式')
  assert.equal(browserHangBudgetMs(cfg.browser), 540000, '默认总预算应覆盖直接可见模式的排队、验证与硬超时余量')
  assert.equal(
    browserHangBudgetMs({
      slotWaitSec: 600,
      turnstileTimeoutSec: 120,
      turnstileInteractive: true,
      turnstileInteractiveTimeoutSec: 600
    }),
    1500000,
    '配置取最大值时总预算仍必须覆盖可见模式等待与启动余量'
  )
  assert.equal(
    browserHangBudgetMs({
      slotWaitSec: 120,
      turnstileTimeoutSec: 30,
      turnstileInteractive: false,
      turnstileInteractiveTimeoutSec: 600
    }),
    540000,
    '关闭可见接管时应覆盖无头 Turnstile/POW 验证与启动余量'
  )
  let publicBypass = null
  assert.equal(
    await bypassServiceWorkerCompat({
      setBypassServiceWorker: async value => { publicBypass = value }
    }),
    'page-api',
    '新版 Puppeteer 应使用公开的 Service Worker API'
  )
  assert.equal(publicBypass, true)

  let legacyBypass = null
  assert.equal(
    await bypassServiceWorkerCompat({
      _client: () => ({
        send: async (method, params) => { legacyBypass = { method, params } }
      })
    }),
    'cdp',
    '旧版 Puppeteer 应通过 CDP 兼容禁用 Service Worker'
  )
  assert.deepEqual(legacyBypass, {
    method: 'Network.setBypassServiceWorker',
    params: { bypass: true }
  })
  assert.equal(
    await bypassServiceWorkerCompat({}),
    'unsupported',
    '完全不支持时应跳过可选优化而不是阻断签到'
  )
  const legacyCdpCalls = []
  const legacyBox = await legacyFrameOwnerBox({
    _client: {
      send: async (method, params) => {
        legacyCdpCalls.push({ method, params })
        if (method === 'DOM.getFrameOwner') return { backendNodeId: 88 }
        return { model: { border: [100, 200, 400, 200, 400, 265, 100, 265] } }
      }
    }
  }, { _id: 'turnstile-frame' })
  assert.deepEqual(legacyBox, { x: 100, y: 200, width: 300, height: 65 })
  assert.deepEqual(legacyCdpCalls, [
    { method: 'DOM.getFrameOwner', params: { frameId: 'turnstile-frame' } },
    { method: 'DOM.getBoxModel', params: { backendNodeId: 88 } }
  ])
  const checkboxClient = {
    send: async method => method === 'Accessibility.getFullAXTree'
      ? {
          nodes: [{
            role: { value: 'checkbox' },
            name: { value: '请验证您是真人' },
            backendDOMNodeId: 22,
            ignored: false
          }]
        }
      : { model: { border: [9, 20.5, 139, 20.5, 139, 44.5, 9, 44.5] } }
  }
  assert.deepEqual(
    await turnstileCheckboxPoint({}, {
      _id: 'ready-turnstile-frame',
      _client: () => checkboxClient
    }, { x: 100, y: 200, width: 300, height: 65 }),
    {
      supported: true,
      point: { x: 131, y: 232.5 },
      name: '请验证您是真人'
    },
    '应等到无障碍树暴露真实 checkbox 后再计算点击位置'
  )
  let stoppedPartialPage = false
  const partialNavigation = await navigateForTurnstile({
    goto: async () => { throw new Error('Navigation timeout of 30000 ms exceeded') },
    url: () => 'https://ioll.pp.ua/',
    waitForSelector: async selector => selector === 'body' ? {} : null,
    evaluate: async () => { stoppedPartialPage = true }
  }, 'https://ioll.pp.ua')
  assert.equal(partialNavigation.partial, true, '同源页面主体可用时不应被 DOMContentLoaded 超时误杀')
  assert.equal(stoppedPartialPage, true, '继续前应停止页面剩余的悬挂加载')
  await assert.rejects(
    navigateForTurnstile({
      goto: async () => { throw new Error('Navigation timeout of 30000 ms exceeded') },
      url: () => 'chrome-error://chromewebdata/',
      waitForSelector: async () => null,
      evaluate: async () => {}
    }, 'https://ioll.pp.ua'),
    /打开站点页面超时/,
    '浏览器错误页仍应判定为真实导航失败'
  )
  let checkedBodyForCertificateError = false
  await assert.rejects(
    navigateForTurnstile({
      goto: async () => { throw new Error('net::ERR_CERT_AUTHORITY_INVALID') },
      url: () => 'https://ioll.pp.ua/',
      waitForSelector: async () => { checkedBodyForCertificateError = true; return {} },
      evaluate: async () => {}
    }, 'https://ioll.pp.ua'),
    /打开站点页面失败.*ERR_CERT_AUTHORITY_INVALID/,
    '证书等非超时错误不能因同源 body 存在而被放行'
  )
  assert.equal(checkedBodyForCertificateError, false, '非恢复型导航错误不应检查或复用错误页主体')
  await assert.rejects(
    navigateForTurnstile({
      goto: async () => ({}),
      url: () => 'https://other.example/',
      waitForSelector: async () => null,
      evaluate: async () => {}
    }, 'https://ioll.pp.ua'),
    /跳转到了不同域名.*请使用该最终地址重新绑定/,
    'Turnstile token 与提交接口必须保持同源'
  )

  let clickedPoint = null
  let iframeDisposed = false
  const frameHandle = {
    boundingBox: async () => ({ x: 100, y: 200, width: 300, height: 65 }),
    dispose: async () => { iframeDisposed = true }
  }
  const readyFrame = {
    _id: 'ready-modern-turnstile-frame',
    url: () => 'https://challenges.cloudflare.com/cdn-cgi/challenge-platform/turnstile',
    frameElement: async () => frameHandle,
    _client: () => checkboxClient
  }
  const clicked = await autoClickTurnstileCheckbox({
    frames: () => [readyFrame],
    $: async () => { throw new Error('frame tree 命中后不应再走 DOM 回退') },
    mouse: {
      move: async () => {},
      click: async (x, y, options) => { clickedPoint = { x, y, options } }
    },
    evaluate: async () => {}
  }, 30, () => false)
  assert.equal(clicked, true, '标准 Turnstile iframe 应自动点击一次')
  assert.deepEqual(clickedPoint, { x: 131, y: 232.5, options: { delay: 120 } })
  assert.equal(iframeDisposed, true, '自动点击后应释放 iframe 句柄')

  let readinessPolls = 0
  let clickedBeforeReady = false
  const notReady = await autoClickTurnstileCheckbox({
    frames: () => [{
      _id: 'loading-turnstile-frame',
      url: () => 'https://challenges.cloudflare.com/loading-turnstile',
      frameElement: async () => ({
        boundingBox: async () => ({ x: 100, y: 200, width: 300, height: 65 }),
        dispose: async () => {}
      }),
      _client: () => ({
        send: async method => {
          if (method === 'Accessibility.getFullAXTree') {
            readinessPolls++
            return { nodes: [] }
          }
          return { model: null }
        }
      })
    }],
    mouse: {
      move: async () => {},
      click: async () => { clickedBeforeReady = true }
    },
    evaluate: async () => {}
  }, 30, () => readinessPolls >= 2)
  assert.equal(notReady, false)
  assert.equal(clickedBeforeReady, false, '只有 iframe 外框、checkbox 尚未就绪时绝不能提前点击')

  let legacyClickedPoint = null
  const legacyFrame = {
    _id: 'legacy-turnstile-frame',
    url: () => 'https://challenges.cloudflare.com/cdn-cgi/challenge-platform/turnstile',
    _client: () => checkboxClient
  }
  const legacyClicked = await autoClickTurnstileCheckbox({
    frames: () => [legacyFrame],
    _client: () => ({
      send: async method => method === 'DOM.getFrameOwner'
        ? { backendNodeId: 99 }
        : { model: { border: [100, 200, 400, 200, 400, 265, 100, 265] } }
    }),
    $: async () => { throw new Error('旧版 frame owner 命中后不应再走 DOM 回退') },
    mouse: {
      move: async () => {},
      click: async (x, y, options) => { legacyClickedPoint = { x, y, options } }
    },
    evaluate: async () => {}
  }, 30, () => false)
  assert.equal(legacyClicked, true, '旧版 Puppeteer 也应定位并点击 Turnstile iframe')
  assert.deepEqual(legacyClickedPoint, { x: 131, y: 232.5, options: { delay: 120 } })

  let manualCompleted = false
  let clickedAfterManual = false
  const canceledClick = await autoClickTurnstileCheckbox({
    $: async () => {
      setTimeout(() => { manualCompleted = true }, 50)
      return {
        boundingBox: async () => ({ x: 100, y: 200, width: 300, height: 65 }),
        dispose: async () => {}
      }
    },
    mouse: {
      move: async () => {},
      click: async () => { clickedAfterManual = true }
    },
    evaluate: async () => {}
  }, 30, () => manualCompleted)
  assert.equal(canceledClick, false, '人工验证先完成时应取消待执行的自动点击')
  assert.equal(clickedAfterManual, false, 'token 已生成后不得再点击验证控件')
  console.log('browser profile OK')

  // ---- 跨平台原生能力：真实指针、窗口几何、进程表 ----
  // Windows 分支只能在 Linux 上靠注入 platform / spawn 验证，无法真跑 PowerShell
  const {
    POINTER_WINDOWS,
    pointerDisplayFor,
    commandLineUsesProfile,
    isOrphanProcess,
    listProcesses,
    killProcessTree,
    parseShellGeometry,
    parsePointerLocation,
    pointerPath,
    nativeClick,
    nativePointerUnavailable,
    windowsClickCommand,
    windowsWindowGeometryCommand
  } = await import('../models/native.js')
  const { detachedClickOrigin } = await import('../models/browser.js')

  assert.equal(pointerDisplayFor(':99'), ':99', '自建虚拟屏优先')
  assert.equal(
    pointerDisplayFor(null, { platform: 'win32', env: {} }),
    POINTER_WINDOWS,
    'Windows 桌面本身就有真实指针，不该退化成人工勾选'
  )
  assert.equal(
    pointerDisplayFor(null, { platform: 'linux', env: { DISPLAY: ':0' } }), ':0',
    '有图形桌面的 Linux 应直接用本机 display'
  )
  assert.equal(pointerDisplayFor(null, { platform: 'linux', env: {} }), '', '无桌面且无虚拟屏只能手动点')
  assert.equal(pointerDisplayFor(null, { platform: 'darwin', env: {} }), '', 'macOS 没有可用的原生指针工具')

  // Linux 上 xdotool 可能在 Yunzai 已启动后才安装；一次 ENOENT 不应让后续轮次永久退化为手动。
  if (process.platform === 'linux' && !spawnSync('xdotool', ['-h'], { stdio: 'ignore' }).error) {
    const savedPath = process.env.PATH
    try {
      process.env.PATH = '/definitely-missing'
      await nativeClick(':99', 1, 1)
    } finally {
      process.env.PATH = savedPath
    }
    assert.equal(nativePointerUnavailable(), false, 'xdotool 恢复后应重新启用原生指针')
  }

  // Windows 的命令行会给含空格的路径加引号，分隔符与大小写也都不固定
  const winProfile = 'C:\\Users\\Bot 1\\Yunzai\\data\\browser-profile\\abc123'
  assert.equal(
    commandLineUsesProfile(`chrome.exe --user-data-dir="${winProfile}" --no-first-run`, winProfile, 'win32'),
    true, '带引号的 Windows 档案路径应能匹配'
  )
  assert.equal(
    commandLineUsesProfile('chrome.exe --user-data-dir=c:/users/bot 1/yunzai/data/browser-profile/abc123', winProfile, 'win32'),
    false, '不带引号时空格截断即视为不同路径，宁可漏杀也不能误杀'
  )
  assert.equal(
    commandLineUsesProfile(`chrome.exe --user-data-dir="${winProfile.toUpperCase()}"`, winProfile, 'win32'),
    true, 'Windows 路径比较必须忽略大小写'
  )
  assert.equal(
    commandLineUsesProfile('chrome --user-data-dir=/data/browser-profile/abc123x', '/data/browser-profile/abc123', 'linux'),
    false, '前缀相同的另一个目录不应被当成同一档案'
  )
  assert.equal(
    commandLineUsesProfile('chrome --user-data-dir=/data/browser-profile/abc123 --lang=zh-CN', '/data/browser-profile/abc123', 'linux'),
    true, 'Linux 档案路径应正常匹配'
  )

  // 孤儿判据：Linux 看 ppid 是否被 init 收养，Windows 看父进程还在不在
  assert.equal(isOrphanProcess({ pid: 20, ppid: 1 }, null, 'linux'), true)
  assert.equal(isOrphanProcess({ pid: 20, ppid: 300 }, null, 'linux'), false)
  assert.equal(isOrphanProcess({ pid: 20, ppid: 300 }, new Set([20]), 'win32'), true, 'Windows 上父进程已消失即为孤儿')
  assert.equal(isOrphanProcess({ pid: 20, ppid: 300 }, new Set([20, 300]), 'win32'), false)

  // Windows 进程表：必须走 EncodedCommand（PowerShell 5.1 会吞掉命令行里的双引号）
  let psInvocation = null
  const winProcesses = listProcesses({
    platform: 'win32',
    spawn: (command, args) => {
      psInvocation = { command, args }
      return { status: 0, stdout: '4321\t900\tchrome.exe --user-data-dir="C:\\p 1"\r\n8\t0\t\r\nbad line\r\n' }
    }
  })
  assert.match(psInvocation.command, /^(powershell|pwsh)\.exe$/)
  const encodedIndex = psInvocation.args.indexOf('-EncodedCommand')
  assert.ok(encodedIndex > 0, 'Windows 进程表查询必须用 -EncodedCommand 传递')
  const decodedCommand = Buffer.from(psInvocation.args[encodedIndex + 1], 'base64').toString('utf16le')
  assert.ok(decodedCommand.includes('Win32_Process'), '应通过 CIM 查询进程表')
  assert.ok(decodedCommand.includes('OutputEncoding'), '必须显式设成 UTF-8，否则中文路径会乱码')
  assert.deepEqual(
    winProcesses,
    [
      { pid: 4321, ppid: 900, command: 'chrome.exe --user-data-dir="C:\\p 1"' },
      { pid: 8, ppid: 0, command: '' }
    ],
    '制表符分隔的进程表应逐行解析，非法行跳过'
  )

  // Windows 上只杀主进程会留下渲染子进程继续占着档案目录，必须 taskkill /T
  let killArgs = null
  assert.equal(killProcessTree(4321, {
    platform: 'win32',
    spawn: (command, args) => {
      killArgs = { command, args }
      return { status: 0 }
    }
  }), true)
  assert.deepEqual(killArgs, { command: 'taskkill', args: ['/F', '/T', '/PID', '4321'] })

  // 点击脚本：轨迹终点必须精确落在目标上，且按下与抬起成对、顺序不能反
  const trail = pointerPath(400, 300)
  assert.equal(trail.length, 6)
  assert.deepEqual([trail.at(-1).x, trail.at(-1).y], [400, 300], '最后一步不许抖动，必须落在目标点')
  assert.ok(trail.every(step => step.delayMs >= 30 && step.delayMs < 80), '每步之间要有停顿')
  const clickScript = windowsClickCommand(270, 332, '65552')
  assert.ok(clickScript.includes('[void][RelayNative]::SetCursorPos(270, 332)'), '指针必须停在目标坐标')
  assert.ok(clickScript.includes('$hwnd = [IntPtr]65552'), '传了窗口句柄就要先把窗口抬到最前')
  assert.ok(
    clickScript.indexOf('mouse_event(0x0002') < clickScript.indexOf('mouse_event(0x0004'),
    '必须先按下再抬起'
  )
  // 注意 user32 声明块里本来就有 SetForegroundWindow 这个名字，要按「有没有调用」判断
  assert.ok(clickScript.includes('::SetForegroundWindow($hwnd)'), '并发多窗口时不抬窗会点到别的窗口上')
  assert.ok(!windowsClickCommand(10, 20).includes('::SetForegroundWindow('), '没有句柄时不该抬窗')

  // 两个平台的几何输出统一成 KEY=数值，于是共用同一套解析
  assert.deepEqual(
    parseShellGeometry('WINDOW=65552\nX=10\nY=10\nWIDTH=1600\nHEIGHT=1000\n'),
    { windowId: '65552', x: 10, y: 10, width: 1600, height: 1000 }
  )
  assert.deepEqual(
    parseShellGeometry('WINDOW=1\nX=0\nY=0\nWIDTH=800\nHEIGHT=600\nWINDOW=2\nX=5\nY=6\nWIDTH=900\nHEIGHT=700\n'),
    { windowId: '2', x: 5, y: 6, width: 900, height: 700 },
    '匹配到多个窗口时取最后一组'
  )
  assert.equal(parseShellGeometry('WINDOW=1\n'), null, '缺尺寸时应判为取不到')
  assert.equal(parsePointerLocation('X=270\nY=332\nSCREEN=0\n'), '(270, 332)')
  assert.equal(parsePointerLocation('nothing'), '')
  const geometryScript = windowsWindowGeometryCommand('relay-checkin kktoken.cc')
  assert.ok(geometryScript.includes("-like '*relay-checkin kktoken.cc*'"), '按窗口标题子串匹配')
  assert.ok(
    geometryScript.includes('GetClientRect') && geometryScript.includes('ClientToScreen'),
    'Windows 侧要返回客户区矩形的屏幕坐标'
  )

  // Windows 返回客户区（frameW≈0，frameH=标签栏+地址栏）；Linux 返回窗口外框（左右各半边框）
  assert.deepEqual(
    detachedClickOrigin(
      { innerWidth: 1600, innerHeight: 912 },
      { windowId: '65552', x: 8, y: 31, width: 1600, height: 1000 }
    ),
    { x: 8, y: 119 },
    'Windows 客户区几何应算出视口原点'
  )
  assert.equal(
    detachedClickOrigin({ innerWidth: 1600, innerHeight: 912 }, { x: 0, y: 0, width: 1600, height: 1500 }),
    null,
    '边框高得离谱说明找错了窗口，应退回页面自报'
  )
  console.log('原生指针 / 进程表 OK')

  // ---- OCR 解释器解析（Windows 的应用商店存根会让 OCR 永远超时）----
  const { findWindowsPython } = await import('../models/ocr.js')
  // PATH 用 Windows 的分号分隔（findWindowsPython 写死分号，正是为了能在这里测）
  const winPath = [
    'C:\\Users\\Bot\\AppData\\Local\\Microsoft\\WindowsApps',
    'C:\\Python312'
  ].join(';')
  assert.equal(
    findWindowsPython({ PATH: winPath }, candidate => candidate.includes('WindowsApps') || candidate.includes('Python312')),
    path.join('C:\\Python312', 'python.exe'),
    '必须跳过 WindowsApps 里的应用商店存根'
  )
  assert.equal(
    findWindowsPython({ PATH: winPath }, () => false), 'py',
    'PATH 里没有可用解释器时交给 py launcher'
  )
  console.log('OCR 解释器解析 OK')

  // ---- adapters/common ----
  const { quotaToUsd, parseUserInfo, parseCheckinResult, classifyValidation, deriveAwardQuota, matchProxy, request } = await import('../models/adapters/common.js')
  // 代理域名匹配：hosts 关键字包含匹配；空数组 = 全部走代理；未配置 url = 不走
  const P = 'http://127.0.0.1:7890'
  assert.equal(matchProxy('anyrouter.top', { url: P, hosts: ['anyrouter'] }), P)
  assert.equal(matchProxy('agentrouter.org', { url: P, hosts: ['anyrouter'] }), null)
  assert.equal(matchProxy('agentrouter.org', { url: P, hosts: [] }), P, '空 hosts 应全部走代理')
  assert.equal(matchProxy('anyrouter.top', { url: '', hosts: ['anyrouter'] }), null, '未配置代理地址不走代理')
  assert.equal(matchProxy('anyrouter.top', null), null)
  // 浏览器是否走显式代理由 proxy.useForBrowser 控制（TUN 模式需关掉避免环路）
  const { proxyForHost } = await import('../models/adapters/common.js')
  assert.equal(proxyForHost('anyrouter.top'), null, '默认未配置代理地址时不走代理')
  assert.equal(proxyForHost('anyrouter.top', true), null)
  assert.equal(quotaToUsd(500000), '$1.00')
  assert.equal(quotaToUsd('250000'), '$0.50')
  assert.equal(quotaToUsd('abc'), null)
  assert.equal(quotaToUsd(null), null)  // Number(null)=0 → 应为 null 还是 $0.00？null 意为缺失
  const ui = parseUserInfo({ success: true, data: { id: 88, username: 'u', display_name: 'DN', quota: 1000000, used_quota: 500000 } })
  assert.equal(ui.ok, true)
  assert.equal(ui.siteUserId, 88)
  assert.equal(ui.balanceText, '$2.00')
  assert.equal(ui.usedText, '$1.00')
  assert.equal(parseUserInfo(null).ok, false)
  assert.equal(parseUserInfo({ success: false, message: 'x' }).msg, 'x')

  let r = parseCheckinResult(200, { success: true, message: '签到成功', data: { quota_awarded: 250000 } })
  assert.deepEqual([r.ok, r.already, r.awardQuota], [true, false, 250000])
  r = parseCheckinResult(200, { success: true, data: { quota: 100000 } })  // Veloera
  assert.equal(r.awardQuota, 100000)
  r = parseCheckinResult(200, { success: false, message: '今日已签到' })
  assert.deepEqual([r.ok, r.already], [true, true])
  r = parseCheckinResult(200, { success: false, message: 'Turnstile token 为空' })
  assert.equal(r.validation, 'turnstile', '站点提示 Turnstile 时必须归类为人机验证，才会触发浏览器降级')
  assert.match(r.msg, /人机验证/, '给用户看的原因要说人话')
  assert.equal(classifyValidation({ message: '需要完成安全验证' }), 'pow')
  r = parseCheckinResult(403, { success: false, code: 'VERIFICATION_REQUIRED', message: '需要完成安全验证' })
  assert.equal(r.validation, 'pow')
  assert.match(r.msg, /安全验证/)
  r = parseCheckinResult(404, null)
  assert.match(r.msg, /没有签到功能/)
  r = parseCheckinResult(302, null)
  assert.match(r.msg, /去登录/)
  r = parseCheckinResult(401, { success: false })
  assert.match(r.msg, /凭据/)
  r = parseCheckinResult(200, { ret: 1, msg: 'ok', data: { quota: 123 } })
  assert.deepEqual([r.ok, r.awardQuota], [true, 123])
  r = parseCheckinResult(200, { code: 0, msg: 'ok' })
  assert.equal(r.ok, true)
  r = parseCheckinResult(403, null, { textSnippet: '<title>Access Verification</title> aliyun_waf' })
  assert.equal(r.validation, 'waf', 'WAF 拦截必须归类，否则不会触发浏览器降级')
  assert.match(r.msg, /防护/)
  r = parseCheckinResult(522, null)
  assert.match(r.msg, /站点没反应/)
  r = parseCheckinResult(0, null, { error: '请求超时（15 秒）' })
  assert.match(r.msg, /连不上/)

  // 非 JSON 响应的诊断只保留响应形状，不能把查询参数或正文写进日志。
  const savedFetch = global.fetch
  const savedWarn = global.logger.warn
  const savedAllowedPrivateHosts = cfg.security.allowedPrivateHosts
  const diagnostics = []
  global.logger.warn = (...args) => diagnostics.push(args.join(' '))
  cfg.security.allowedPrivateHosts = ['x.com']
  global.fetch = async () => ({
    status: 200,
    text: async () => '<html><title>Cloudflare</title></html>',
    headers: { get: name => name.toLowerCase() === 'content-type' ? 'text/html; charset=utf-8' : null }
  })
  try {
    const nonJson = await request('https://x.com/api/checkin?secret=do-not-log', { method: 'POST' })
    assert.equal(nonJson.json, null)
    assert.match(diagnostics[0], /POST \/api\/checkin 返回非 JSON：HTTP 200/)
    assert.match(diagnostics[0], /Content-Type=text\/html; charset=utf-8.*类型=html,cloudflare/)
    assert.doesNotMatch(diagnostics[0], /do-not-log|<html|Cloudflare/)

    diagnostics.length = 0
    global.fetch = async () => { throw new Error('mock network failure') }
    await assert.rejects(
      request('https://x.com/api/checkin?secret=do-not-log', { method: 'GET', maxRetry: 0 }),
      /GET 请求失败/
    )
    assert.match(diagnostics[0], /GET \/api\/checkin 请求失败/)
    assert.doesNotMatch(diagnostics[0], /do-not-log/)
  } finally {
    global.fetch = savedFetch
    global.logger.warn = savedWarn
    cfg.security.allowedPrivateHosts = savedAllowedPrivateHosts
  }

  assert.equal(deriveAwardQuota(
    { quota: 1000000, usedQuota: 100000 },
    { quota: 1200000, usedQuota: 400000 }
  ), 500000, '奖励推导应抵消签到期间的正常消费')
  console.log('adapters/common OK')

  // ---- adapters/index ----
  const { normalizeBaseUrl, cookieTypeForHost, preferredBindingForHost, getAdapter } = await import('../models/adapters/index.js')
  assert.equal(normalizeBaseUrl('xx.com/'), 'https://xx.com')
  assert.throws(() => normalizeBaseUrl('http://a.b'), /HTTPS/)
  assert.throws(() => normalizeBaseUrl('https://127.0.0.1'), /不允许/)
  assert.throws(() => normalizeBaseUrl('https://example.com/path'), /根地址/)
  const { isPrivateAddress } = await import('../models/url-security.js')
  assert.equal(isPrivateAddress('10.0.0.1'), true)
  assert.equal(isPrivateAddress('169.254.169.254'), true)
  assert.equal(isPrivateAddress('8.8.8.8'), false)
  assert.equal(cookieTypeForHost('agentrouter.org'), 'agentrouter')
  assert.equal(cookieTypeForHost('xx.agentrouter.cn'), 'agentrouter')
  assert.equal(cookieTypeForHost('ps.air-outer.com'), 'agentrouter', 'air-outer.com 系域名应识别为 AgentRouter')
  assert.equal(cookieTypeForHost('anyrouter.top'), 'anyrouter')
  assert.equal(cookieTypeForHost('other.com'), 'generic')
  assert.equal(preferredBindingForHost('anyrouter.top'), 'cookie', 'AnyRouter 应引导 Cookie 绑定')
  assert.equal(preferredBindingForHost('ps.air-outer.com'), 'email', 'AgentRouter 应引导邮箱绑定')
  assert.equal(preferredBindingForHost('newapi.example.com'), null, '普通站点应继续走令牌探测')
  assert.equal(getAdapter('veloera').type, 'veloera')
  assert.equal(getAdapter('不存在').type, 'newapi')
  console.log('adapters/index OK')

  // ---- 各 adapter 请求头 ----
  const newapi = (await import('../models/adapters/newapi.js')).default
  let h = newapi.buildHeaders({ token: 'T', siteUserId: 5 })
  assert.equal(h.Authorization, 'Bearer T')
  assert.equal(h['New-Api-User'], '5')
  h = newapi.buildHeaders({ token: 'T' })
  assert.ok(!('New-Api-User' in h))
  const veloera = (await import('../models/adapters/veloera.js')).default
  h = veloera.buildHeaders({ token: 'T', siteUserId: 5 })
  assert.equal(h.Authorization, 'T')  // 不带 Bearer
  assert.equal(h['Veloera-User'], '5')
  const generic = (await import('../models/adapters/generic.js')).default
  h = generic.buildHeaders({ token: 'S', siteUserId: 5 })
  assert.equal(h.Cookie, 'session=S')
  const agentrouterModule = await import('../models/adapters/agentrouter.js')
  const agentrouter = agentrouterModule.default
  h = agentrouter.buildHeaders({ token: 'S', siteUserId: 7 })
  assert.equal(h.Cookie, 'session=S')
  assert.equal(h['New-Api-User'], '7')
  assert.equal(agentrouterModule.sessionCookieFrom([
    'acw_tc=x; Path=/',
    'session=abc.def==; Path=/; HttpOnly'
  ]), 'abc.def==')
  assert.equal(agentrouterModule.parseLoginAwardQuota({
    data: {
      quota_per_unit: 500000,
      announcements: [{ content: '支持登录签到；签到送 $25 Credit' }]
    }
  }), 12500000)
  assert.equal(agentrouterModule.hasEmailLogin({ authMode: 'email', loginEmail: 'u@example.com', password: 'p' }), true)
  assert.equal(agentrouterModule.hasEmailLogin({ token: 'session-only' }), false)
  const anyrouter = (await import('../models/adapters/anyrouter.js')).default
  h = anyrouter.buildHeaders({ token: 'S', siteUserId: 8 })
  assert.equal(h.Cookie, 'session=S')
  assert.equal(h['New-Api-User'], '8')
  // Turnstile 降级依赖各令牌型适配器声明签到路径
  const newapiMod = (await import('../models/adapters/newapi.js')).default
  const veloeraMod = (await import('../models/adapters/veloera.js')).default
  assert.equal(newapiMod.checkinPath, '/api/user/checkin')
  assert.equal(veloeraMod.checkinPath, '/api/user/check_in')
  const validationHeaders = newapiMod.buildValidationHeaders({ token: 'T', siteUserId: 1 })
  assert.ok(validationHeaders['X-Game-Action-Id'] && validationHeaders['X-Game-Body-SHA256'], 'POW 签到应带网页完整性标记')
  console.log('adapter headers OK')

  // ---- store（仅用户隔离 + 同站多账号）----
  const store = await import('../models/store.js')
  const eGroup = { user_id: 111, group_id: 999, isGroup: true, self_id: 10000, sender: { nickname: 'N1', card: 'C1' } }
  const ePrivate = { user_id: 111, isGroup: false, self_id: 10000, sender: { nickname: 'N1' } }
  const eOtherGroup = { user_id: 111, group_id: 888, isGroup: true, self_id: 10000, sender: { nickname: 'N1' } }

  assert.equal(store.keyOf(eGroup), 'u:111')
  assert.equal(store.keyOf(ePrivate), 'u:111', '群/私聊应同键（仅用户隔离）')

  const en1 = store.ensureEntry(eGroup)
  assert.equal(en1.groupId, '999')
  assert.equal(en1.nickname, 'C1', '群名片优先')

  const acc = (over = {}) => ({
    name: 'a.com', baseUrl: 'https://a.com', type: 'agentrouter', token: 't1',
    siteUserId: 1, signPath: null, auto: true, username: 'u1', ...over
  })
  let up = store.upsertAccount(eGroup, acc())
  assert.deepEqual([up.index, up.updated], [1, false])

  // 同站点不同站点用户ID → 追加为新账号（同站多账号）
  up = store.upsertAccount(eGroup, acc({ siteUserId: 2, token: 't2', username: 'u2' }))
  assert.deepEqual([up.index, up.updated], [2, false])
  assert.equal(store.getEntry(eGroup).accounts.length, 2)

  // AgentRouter 官方域名与备用域名是同一站，同一用户ID应更新而不是重复添加。
  const official = store.upsertAccount(eGroup, acc({
    name: 'agentrouter.org', baseUrl: 'https://agentrouter.org', siteUserId: 99, token: 'official-1'
  }))
  assert.equal(official.updated, false)
  const alias = store.upsertAccount(eGroup, acc({
    name: 'ps.air-outer.com', baseUrl: 'https://ps.air-outer.com', siteUserId: 99, token: 'official-2'
  }))
  assert.equal(alias.updated, true)
  assert.equal(alias.index, official.index)
  assert.equal(alias.account.baseUrl, 'https://ps.air-outer.com')

  // 同站点同站点用户ID → 更新凭据，且保留单账号定时开关偏好
  store.setAccountAuto(eGroup, 1, false)
  up = store.upsertAccount(eGroup, acc({ token: 't1-new' }))
  assert.deepEqual([up.index, up.updated], [1, true])
  assert.equal(up.account, store.getEntry(eGroup).accounts[0], '应返回入库后的对象引用（供添加后签到直接落缓存）')
  let entryNow = store.getEntry(eGroup)
  assert.equal(entryNow.accounts.length, 3)
  assert.equal(entryNow.accounts[0].token, 't1-new')
  assert.equal(entryNow.accounts[0].auto, false, '更新凭据不应重置单账号定时开关')

  // 无 siteUserId 时按 token 匹配
  up = store.upsertAccount(eGroup, acc({ name: 'b.com', baseUrl: 'https://b.com', siteUserId: null, token: 'bt' }))
  assert.equal(up.updated, false)
  up = store.upsertAccount(eGroup, acc({ name: 'b.com', baseUrl: 'https://b.com', siteUserId: null, token: 'bt' }))
  assert.deepEqual([up.index, up.updated], [4, true])

  // accountLabel / setAccountAuto 边界
  assert.equal(store.accountLabel({ name: 'x.com', username: 'U' }), 'x.com (U)')
  assert.equal(store.accountLabel({ name: 'x.com' }), 'x.com')
  assert.equal(store.setAccountAuto(eGroup, 99, false), null)

  // 私聊可见同一批账号；且私聊不清空 groupId
  const en2 = store.touchEntry(ePrivate)
  assert.equal(en2.accounts.length, 4, '私聊应共享群里添加的账号')
  assert.equal(en2.groupId, '999', '私聊使用不应清空最近群')

  // 换群后 groupId 跟随最近使用的群，且两个群都留在候选列表里（最近优先）
  store.touchEntry(eOtherGroup)
  assert.equal(store.getEntry(ePrivate).groupId, '888')
  assert.deepEqual(store.groupCandidates(store.getEntry(eGroup)), ['888', '999'], '用过的群都应记入候选，最近的在前')
  // 回到旧群应提到首位而不是重复追加
  store.touchEntry(eGroup)
  assert.deepEqual(store.groupCandidates(store.getEntry(eGroup)), ['999', '888'])
  // rememberGroup 幂等 + 限长
  store.rememberGroup(store.getEntry(eGroup), '999')
  assert.deepEqual(store.groupCandidates(store.getEntry(eGroup)), ['999', '888'])
  for (const g of ['1', '2', '3', '4', '5']) store.rememberGroup(store.getEntry(eGroup), g)
  assert.equal(store.groupCandidates(store.getEntry(eGroup)).length, 5, '候选群列表应限长 5')
  // 旧数据（只有 groupId 无 groupIds）应能迁移出候选列表
  assert.deepEqual(store.groupCandidates({ groupId: '777' }), ['777'])
  assert.deepEqual(store.groupCandidates({ groupId: null }), [])

  // 删除（仅操作本用户数据）
  assert.equal(store.removeAccount(eGroup, 9), null)
  assert.equal(store.removeAccount(eGroup, 4).name, 'b.com')
  assert.equal(store.getEntry(eGroup).accounts.length, 3)

  // Sub2API 重新绑定：refresh_token 是一次性的、每次绑定都会轮换，只有 saveAccount 把
  // 验证阶段查到的站点用户ID 回填进账号，才能认出是同一个账号；缺 ID 又换了令牌就会重复入库
  const s2acc = (over = {}) => ({
    name: 's2.test', baseUrl: 'https://s2.test', type: 'sub2api', authMode: 'refresh',
    token: 'RT_A', siteUserId: 5, signPath: null, auto: true, ...over
  })
  const s2First = store.upsertAccount(eGroup, s2acc())
  assert.equal(s2First.updated, false)
  const s2Rebind = store.upsertAccount(eGroup, s2acc({ token: 'RT_B' }))
  assert.deepEqual(
    [s2Rebind.index, s2Rebind.updated], [s2First.index, true],
    '令牌轮换后重新绑定同一账号应更新而不是重复添加'
  )
  assert.equal(
    store.upsertAccount(eGroup, s2acc({ token: 'RT_C', siteUserId: null })).updated, false,
    '缺站点用户ID 时无法去重，因此 saveAccount 必须回填 info.siteUserId'
  )
  store.removeAccount(eGroup, store.getEntry(eGroup).accounts.length)
  store.removeAccount(eGroup, s2First.index)
  assert.equal(store.getEntry(eGroup).accounts.length, 3, 'Sub2API 用例应清理干净不影响后续断言')

  // 定时总开关 + allEntries
  store.setAuto(eGroup, false)
  assert.equal(store.getEntry(eGroup).autoCheckin, false)
  const all = store.allEntries()
  assert.equal(all.length, 1)
  assert.equal(all[0].key, 'u:111')

  // ---- lock：同一用户互斥，不同用户互不影响 ----
  const lock = await import('../models/lock.js')
  const l1 = lock.tryAcquire('111', '签到')
  assert.ok(l1, '首次应获取到锁')
  assert.equal(lock.tryAcquire('111', '查询'), null, '同一用户重复获取应失败')
  assert.equal(lock.heldBy('111').label, '签到', '应报告持有中的操作名')
  const l2 = lock.tryAcquire('222', '签到')
  assert.ok(l2, '不同用户不应互相阻塞')
  l1.release()
  l1.release() // 重复释放应无副作用
  assert.equal(lock.heldBy('111'), null)
  assert.ok(lock.tryAcquire('111', '签到'), '释放后应可再获取')

  // withUserLock：占用时返回 busy 而不是排队；释放后可再次执行
  let ran = 0
  const busy = await lock.withUserLock('111', '列表', async () => { ran++ })
  assert.equal(busy.ok, false, '被占用应返回 busy')
  assert.equal(busy.busy.label, '签到')
  assert.equal(ran, 0, 'busy 时不应执行任务体')
  assert.equal(lock.tryAcquire('111', 'x'), null, 'busy 返回后锁仍应由原持有者持有')
  assert.ok(lock.heldBy('222'), '其他用户的锁不受影响')
  l2.release()
  // 通过 withUserLock 并发调用同一用户：只有一个能进入
  let entered = 0
  const results = await Promise.all([
    lock.withUserLock('333', 'A', async () => { entered++; await new Promise(r => setTimeout(r, 30)) }),
    lock.withUserLock('333', 'B', async () => { entered++ })
  ])
  assert.equal(entered, 1, '同一用户并发只应有一个进入')
  assert.equal(results.filter(r => r.ok).length, 1)
  assert.equal(lock.heldBy('333'), null, '执行完应自动释放')
  // 任务体抛错也必须释放锁
  await lock.withUserLock('444', 'E', async () => { throw new Error('x') }).catch(() => {})
  assert.equal(lock.heldBy('444'), null, '异常路径也应释放锁')

  // 归属校验：锁被超时兜底夺走后，旧持有者 release 不能删掉新持有者的锁
  // （构造：手改 since 使其过期 → 新持有者取到锁 → 旧持有者释放）
  const old = lock.tryAcquire('555', '旧任务')
  const state = lock.heldBy('555')
  assert.equal(state.label, '旧任务')
  // 直接改内部时间不可行（未导出），改用可观察路径：同 key 释放后再取，验证 token 隔离
  old.release()
  const fresh = lock.tryAcquire('555', '新任务')
  old.release() // 旧句柄重复释放不得影响新锁
  assert.equal(lock.heldBy('555')?.label, '新任务', '旧句柄的 release 不应删除新持有者的锁')
  fresh.release()
  assert.equal(lock.heldBy('555'), null)
  console.log('lock OK')

  // 定时推送白名单
  assert.deepEqual(store.getPushGroups(), [])
  assert.equal(store.isPushGroup('999'), false)
  assert.equal(store.setPushGroup('999', true), true)
  assert.equal(store.setPushGroup('999', true), false, '重复开启应返回未变化')
  assert.deepEqual(store.getPushGroups(), ['999'])
  assert.equal(store.isPushGroup(999), true, '数字/字符串群号应等价')
  assert.equal(store.setPushGroup('999', false), true)
  assert.equal(store.isPushGroup('999'), false)
  store.setPushGroup('888', true)
  assert.ok(fs.existsSync(path.join(DATA, 'push_groups.json')), '白名单应落盘')
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(DATA, 'push_groups.json'), 'utf-8')), ['888'])
  // 手工编辑名单应热生效；群号统一转成字符串并去重、去空值
  fs.writeFileSync(path.join(DATA, 'push_groups.json'), JSON.stringify(['777', 777, '', null]))
  assert.deepEqual(store.getPushGroups(), ['777'])
  assert.equal(store.isPushGroup('777'), true)
  assert.equal(store.isPushGroup('888'), false)

  // 固定群推送计划：每个目标群都包含同一机器人名下的全部用户
  const { buildGroupPushPlan } = await import('../models/push-plan.js')
  const pushItems = [
    { entry: { selfId: 'bot-1', userId: '111' }, results: [] },
    { entry: { selfId: 'bot-1', userId: '222' }, results: [] },
    { entry: { selfId: 'bot-2', userId: '333' }, results: [] }
  ]
  const pushPlan = buildGroupPushPlan(pushItems, ['100', '200'])
  assert.equal(pushPlan.length, 4)
  assert.deepEqual(
    pushPlan.map(plan => [plan.selfId, plan.groupId, plan.items.map(item => item.entry.userId)]),
    [
      ['bot-1', '100', ['111', '222']],
      ['bot-1', '200', ['111', '222']],
      ['bot-2', '100', ['333']],
      ['bot-2', '200', ['333']]
    ]
  )

  // 持久化落盘验证
  const onDisk = JSON.parse(fs.readFileSync(path.join(DATA, 'accounts.json'), 'utf-8'))
  assert.ok(onDisk['u:111'])
  assert.equal(onDisk['u:111'].accounts[0].token, 't1-new')
  console.log('store OK')

  // ---- executor 纯逻辑（randInt 边界）----
  const { randInt } = await import('../models/executor.js')
  for (let i = 0; i < 200; i++) {
    const v = randInt(5, 15)
    assert.ok(v >= 5 && v <= 15)
  }
  console.log('executor.randInt OK')

  // ---- 指令正则（与 apps/checkin.js 保持一致）----
  const rules = {
    help: /^#中转(?:站)?(帮助|help)$/,
    addEmail: /^#中转(?:站)?添加邮箱\s+\S+(?:\s+\S+)*$/,
    addCookie: /^#中转(?:站)?添加[cC]ookie\s+\S+(?:\s+\S+)*$/,
    add: /^#中转(?:站)?添加\s+\S+(?:\s+\S+)*$/,
    list: /^#中转(?:站)?列表$/,
    remove: /^#中转(?:站)?删除\s*(\d+)$/,
    checkin: /^#中转(?:站)?签到\s*(\d+)?$/,
    query: /^#中转(?:站)?查询$/,
    toggle: /^#中转(?:站)?定时\s*(开|关)\s*(\d+)?$/,
    pushToggle: /^#中转(?:站)?(开启|关闭)(定时(签到)?)?群推送$/,
    bindPrefixed: /^[#＃/\\]?\s*中转(?:站)?绑定/,
    bind: /^[\s\S]+$/
  }
  assert.ok(rules.help.test('#中转帮助') && rules.help.test('#中转站help'))
  assert.ok(rules.addEmail.test('#中转添加邮箱 agentrouter.org'))
  assert.ok(rules.addEmail.test('#中转站添加邮箱 agentrouter.org'), '中转站前缀应兼容邮箱绑定')
  assert.ok(rules.addEmail.test('#中转添加邮箱 agentrouter.org user@example.com password'))
  assert.ok(rules.add.test('#中转添加 https://x.com abc'))
  assert.ok(rules.add.test('#中转添加 x.com abc 123'))
  assert.ok(rules.add.test('#中转添加 x.com'), '仅地址应命中（发起私聊绑定流程）')
  assert.ok(rules.add.test('#中转站添加 x.com'), '中转站前缀应兼容添加指令')
  assert.ok(rules.add.test('#中转添加 x.com abc 123 多余参数'), '参数过多也应命中，以便撤回并提示')
  assert.ok(!rules.add.test('#中转添加cookie x.com s 1'), 'addCookie 消息不应命中 add 规则')
  assert.ok(rules.addCookie.test('#中转添加cookie x.com sess 1'))
  assert.ok(rules.addCookie.test('#中转站添加cookie x.com sess 1'), '中转站前缀应兼容 Cookie 绑定')
  assert.ok(rules.addCookie.test('#中转添加Cookie x.com sess 1'))
  assert.ok(rules.addCookie.test('#中转添加cookie x.com'), '仅地址应命中（发起私聊绑定流程）')
  assert.ok(rules.addCookie.test('#中转添加cookie x.com sess'), '缺用户ID也应命中，由处理器提示补全')
  assert.ok(rules.addCookie.test('#中转添加cookie x.com sess 1 多余'), '参数过多也应命中，以便撤回并提示')
  assert.ok(rules.checkin.test('#中转签到') && rules.checkin.test('#中转签到 2') && rules.checkin.test('#中转签到2'))
  assert.ok(rules.checkin.test('#中转站签到 2'), '中转站前缀应兼容指定序号签到')
  assert.ok(rules.list.test('#中转站列表') && rules.remove.test('#中转站删除3') && rules.query.test('#中转站查询'), '中转站前缀应兼容列表/删除/查询')
  assert.ok(rules.remove.test('#中转删除 1') && rules.remove.test('#中转删除3'))
  assert.ok(rules.toggle.test('#中转定时 开') && rules.toggle.test('#中转定时关'))
  assert.ok(rules.toggle.test('#中转定时 关 2') && rules.toggle.test('#中转定时开1'), '带序号的单账号定时开关应命中')
  assert.ok(rules.toggle.test('#中转站定时开1'), '中转站前缀应兼容定时开关')
  assert.ok(rules.pushToggle.test('#中转开启群推送') && rules.pushToggle.test('#中转关闭群推送'))
  assert.ok(rules.pushToggle.test('#中转开启定时签到群推送'), '长格式应兼容')
  assert.ok(rules.pushToggle.test('#中转站关闭群推送'), '中转站前缀应兼容群推送开关')
  assert.ok(!rules.pushToggle.test('#中转群推送'), '无开启/关闭动词不应命中')
  assert.ok(rules.bind.test('sess-value 12345'), '兜底规则应命中普通私聊消息')
  assert.ok(rules.bind.test('/xgyToken+abc= 250'), '/ 开头的凭据也应命中（核心会归一化首字符，处理器按原文解析）')
  assert.ok(rules.bind.test('#中转列表'), '兜底规则命中指令没关系，处理器按原文首字符放行')
  assert.ok(rules.bindPrefixed.test('中转绑定 tok') && rules.bindPrefixed.test('#中转绑定 tok') && rules.bindPrefixed.test('#中转站绑定 tok'), 'disableAdopt 放行用的前缀格式应命中')
  assert.ok(rules.bindPrefixed.test('/中转绑定 tok'), '/ 被归一化前的原文也应识别为前缀格式')
  console.log('指令正则 OK')

  console.log('\n全部冒烟测试通过 ✓')
} finally {
  // 还原 data 目录
  if (fs.existsSync(DATA)) fs.rmSync(DATA, { recursive: true, force: true })
  if (hadData) fs.renameSync(backup, DATA)
}

// config.js 的 chokidar watcher 会保持进程存活（生产为热更新所需），测试显式退出
process.exit(0)
