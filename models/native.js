import { spawn, spawnSync } from 'node:child_process'
import { logger } from '../host/index.js'

/**
 * 平台原生能力层：真实指针点击、窗口几何、进程表、进程树回收。
 *
 * 为什么需要它：Turnstile 判自动化的决定性因素之一是「有没有操作系统级的原始输入」——
 * CDP 的 Input.dispatchMouseEvent 是注入事件，实测必被判 bot（错误码 600010）。
 * 各平台的等价原语完全不同，这里统一成一组接口，让 browser.js 无差别调用：
 *   Linux   : xdotool 驱动 X server 的指针（自建 Xvfb 虚拟屏或本机桌面都行）
 *   Windows : PowerShell 调 user32.dll（SetCursorPos / mouse_event），
 *             这条路径与真实硬件走同一个输入队列，页面里拿到的事件 isTrusted 为 true
 *   macOS   : 没有免安装的等价工具，直接判定不可用，调用方退回 CDP 点击
 *
 * Windows 侧有两个前提，改动前务必知道：
 * 1. **一律不给 PowerShell 声明 DPI 感知**。系统缩放不是 100% 时，DPI-unaware 进程
 *    看到的坐标系恰好等于 Chrome 自报的 CSS 像素（两者都是「物理像素 ÷ 缩放」），
 *    于是 window.screenX、GetClientRect、SetCursorPos 三者同一套单位，不需要任何换算。
 *    一旦让 PowerShell 变成 DPI-aware，125% 缩放下点击会整体偏向右下。
 * 2. 命令统一用 -EncodedCommand（UTF-16LE base64）传：PowerShell 5.1 会吞掉命令行里的
 *    双引号，而档案路径常带空格和中文，直接拼字符串必然踩坑。
 */

/** 哨兵 display：Windows 桌面本身就有真实指针，不存在 X display 的概念 */
export const POINTER_WINDOWS = 'win32-desktop'

/** 一次点击的鼠标按下/抬起标志（user32 的 MOUSEEVENTF_LEFTDOWN / LEFTUP） */
const MOUSE_LEFT_DOWN = '0x0002'
const MOUSE_LEFT_UP = '0x0004'

const PS_PRELUDE = "$ErrorActionPreference='Stop'\n"
  + '[Console]::OutputEncoding=[System.Text.Encoding]::UTF8\n'

/**
 * user32 原语：点击、窗口几何、指针位置三处共用同一份声明。
 * 用 -TypeDefinition 而不是 -MemberDefinition，因为要带 RECT / POINT 两个结构体。
 */
const PS_USER32 = `Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class RelayNative {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
  [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X; public int Y; }
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr hWnd, out RECT rect);
  [DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr hWnd, ref POINT point);
  [DllImport("user32.dll")] public static extern bool GetCursorPos(out POINT point);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint flags, uint dx, uint dy, uint data, IntPtr extra);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int cmd);
}
'@
`

// Windows Server Core 等精简系统可能只有其中一个
const PS_CANDIDATES = ['powershell.exe', 'pwsh.exe']
let psExecutable = null

/**
 * 真实指针整体暂不可用（缺 xdotool / 缺 PowerShell）。Linux 上工具可能在进程运行
 * 期间才安装，不能把一次 ENOENT 永久当成不可用；nativePointerUnavailable() 会刷新状态。
 */
let pointerUnavailable = false

function refreshPointerAvailability() {
  if (!pointerUnavailable || process.platform !== 'linux') return
  // 只探测可执行文件是否已经出现，不连接 X server，避免 DISPLAY 不可用时误判。
  const probe = spawnSync('xdotool', ['-h'], { stdio: 'ignore' })
  if (!probe.error || probe.error.code !== 'ENOENT') pointerUnavailable = false
}

export function nativePointerUnavailable() {
  refreshPointerAvailability()
  return pointerUnavailable
}

function markPointerUnavailable(reason) {
  if (pointerUnavailable) return
  pointerUnavailable = true
  logger.warn(`[relay-checkin-plugin] ${reason}，无法自动勾选人机验证（可在弹出的窗口中手动勾选）`)
}

function psCandidates() {
  return psExecutable ? [psExecutable] : PS_CANDIDATES
}

function psArgs(command) {
  return [
    '-NoProfile',
    '-NonInteractive',
    // 只影响脚本文件，EncodedCommand 本身不受执行策略限制；写上是为了个别组策略环境
    '-ExecutionPolicy', 'Bypass',
    '-EncodedCommand', Buffer.from(PS_PRELUDE + command, 'utf16le').toString('base64')
  ]
}

/**
 * 解析 `KEY=数值` 形式的几何输出。xdotool 的 `getwindowgeometry --shell` 与
 * Windows 侧命令都按这个格式输出，于是两边共用同一套解析。
 * 匹配到多个窗口时 xdotool 会依次输出各自的 WINDOW/X/Y/WIDTH/HEIGHT，取最后一组。
 */
export function parseShellGeometry(out) {
  const pick = key => {
    const all = [...String(out || '').matchAll(new RegExp(`^${key}=(-?\\d+)$`, 'gm'))]
    return all.length ? Number(all.at(-1)[1]) : null
  }
  const width = pick('WIDTH')
  const height = pick('HEIGHT')
  const windowId = pick('WINDOW')
  if (!width || !height) return null
  return { windowId: windowId ? String(windowId) : '', x: pick('X') || 0, y: pick('Y') || 0, width, height }
}

/**
 * 解析 `X=` / `Y=` 形式的指针坐标输出，两个平台共用。
 * @returns {string} 形如 `(270, 332)`，取不到时为空串
 */
export function parsePointerLocation(out) {
  const x = String(out || '').match(/^X=(-?\d+)$/m)?.[1]
  const y = String(out || '').match(/^Y=(-?\d+)$/m)?.[1]
  return x && y ? `(${x}, ${y})` : ''
}

/**
 * 跑一个外部命令并收集 stdout，带硬超时。
 * 「工具没装」（ENOENT）要与「跑了但失败」分开返回：前者要置位不可用并给安装提示，
 * 后者只是这一次没成功，下次还该继续尝试。
 * @returns {Promise<{ok: boolean, stdout: string, notFound: boolean}>}
 */
function runCommand(command, args, { timeoutMs = 15000, env = process.env } = {}) {
  return new Promise(resolve => {
    let proc = null
    try {
      proc = spawn(command, args, { env, stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true })
    } catch (err) {
      resolve({ ok: false, stdout: '', notFound: err?.code === 'ENOENT' })
      return
    }
    let out = ''
    let settled = false
    const finish = value => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try { proc.kill() } catch { /* 已退出 */ }
      resolve(value)
    }
    const timer = setTimeout(() => finish({ ok: false, stdout: out, notFound: false }), timeoutMs)
    proc.stdout.on('data', chunk => { out += String(chunk) })
    proc.once('error', err => finish({ ok: false, stdout: out, notFound: err?.code === 'ENOENT' }))
    proc.once('exit', code => finish({ ok: code === 0, stdout: out, notFound: false }))
  })
}

/**
 * 执行一段 PowerShell。首次调用会在 powershell.exe / pwsh.exe 之间定下用哪个，
 * 两个都没有才判定真实指针不可用。
 * @returns {Promise<{ok: boolean, stdout: string}>}
 */
async function runPowerShell(command, timeoutMs) {
  for (const exe of psCandidates()) {
    const res = await runCommand(exe, psArgs(command), { timeoutMs })
    if (res.notFound) continue
    psExecutable = exe
    return { ok: res.ok, stdout: res.stdout }
  }
  markPointerUnavailable('本机找不到 PowerShell（powershell.exe / pwsh.exe）')
  return { ok: false, stdout: '' }
}

/**
 * 生成一条「像人」的指针轨迹：从目标左下方斜着过来，中途带抖动，每步停 30~80 毫秒。
 * 终点不抖，必须精确落在目标上。两个平台共用同一套轨迹，行为特征保持一致。
 * @returns {Array<{x: number, y: number, delayMs: number}>}
 */
export function pointerPath(x, y, { steps = 6 } = {}) {
  const fromX = x - 120 - Math.floor(Math.random() * 60)
  const fromY = y + 70 + Math.floor(Math.random() * 40)
  const trail = []
  for (let i = 1; i <= steps; i++) {
    const t = i / steps
    const jitter = i < steps ? () => Math.round(Math.random() * 6 - 3) : () => 0
    trail.push({
      x: Math.round(fromX + (x - fromX) * t) + jitter(),
      y: Math.round(fromY + (y - fromY) * t) + jitter(),
      delayMs: 30 + Math.floor(Math.random() * 50)
    })
  }
  return trail
}

/**
 * 用 xdotool 在指定 display 上把真实指针移到屏幕坐标并点击。
 * @returns {Promise<boolean>} 点击是否成功执行
 */
async function xdotoolClick(display, x, y, windowId) {
  const argv = []
  // 同一虚拟屏上可能同时开着别的窗口（并发签到、常驻可见实例），它们都在 (0,0)
  // 互相遮挡；先把目标窗口抬到最前，屏幕坐标点击才会落到它身上。
  // windowraise 直接调 XRaiseWindow，不需要窗口管理器
  if (windowId) argv.push('windowraise', windowId, 'sleep', '0.20')
  for (const step of pointerPath(x, y)) {
    argv.push('mousemove', String(step.x), String(step.y), 'sleep', (step.delayMs / 1000).toFixed(3))
  }
  // 指针到位后再停顿一下才按下，避免「移动即点击」的机械特征
  argv.push('sleep', (0.25 + Math.random() * 0.35).toFixed(3), 'click', '1')

  const res = await runCommand('xdotool', argv, {
    timeoutMs: 15000,
    env: { ...process.env, DISPLAY: display }
  })
  if (res.notFound) {
    markPointerUnavailable('未安装 xdotool（Debian / Ubuntu 执行 apt install xdotool）')
  }
  return res.ok
}

/**
 * 生成 Windows 点击用的 PowerShell 脚本（导出仅为便于测试）。
 *
 * 移动用 SetCursorPos、按下抬起用 mouse_event：两者产生的都是系统级输入，
 * 与 xdotool 在 X11 上的地位相同。不用 SendInput 是因为它要额外声明一堆结构体，
 * 而 mouse_event 在 Win10/11 上仍然直接转发给 SendInput，行为一致。
 * @param {string|number} windowId 目标窗口句柄，传了才抬窗
 */
export function windowsClickCommand(x, y, windowId = '') {
  const lines = [PS_USER32]
  if (windowId) {
    // SW_RESTORE：窗口被最小化时也能恢复出来，正常显示时无副作用
    lines.push(
      `$hwnd = [IntPtr]${Number(windowId)}`,
      '[void][RelayNative]::ShowWindow($hwnd, 9)',
      '[void][RelayNative]::SetForegroundWindow($hwnd)',
      'Start-Sleep -Milliseconds 200'
    )
  }
  for (const step of pointerPath(x, y)) {
    lines.push(
      `[void][RelayNative]::SetCursorPos(${step.x}, ${step.y})`,
      `Start-Sleep -Milliseconds ${step.delayMs}`
    )
  }
  lines.push(
    `Start-Sleep -Milliseconds ${250 + Math.floor(Math.random() * 350)}`,
    `[RelayNative]::mouse_event(${MOUSE_LEFT_DOWN}, 0, 0, 0, [IntPtr]::Zero)`,
    `Start-Sleep -Milliseconds ${70 + Math.floor(Math.random() * 60)}`,
    `[RelayNative]::mouse_event(${MOUSE_LEFT_UP}, 0, 0, 0, [IntPtr]::Zero)`,
    "'CLICKED'"
  )
  return lines.join('\n')
}

/**
 * 真实指针点击。display 为 POINTER_WINDOWS 时走 PowerShell，否则走 xdotool。
 * @returns {Promise<boolean>} 点击是否成功执行
 */
export async function nativeClick(display, x, y, { windowId = '' } = {}) {
  if (!display || nativePointerUnavailable()) return false
  if (display !== POINTER_WINDOWS) return await xdotoolClick(display, x, y, windowId)
  // Add-Type 首次编译要一两秒，超时给足；点击自身的时序全在脚本内部控制
  const res = await runPowerShell(windowsClickCommand(x, y, windowId), 25000)
  return res.ok && res.stdout.includes('CLICKED')
}

/**
 * 生成 Windows 取窗口几何用的 PowerShell 脚本（导出仅为便于测试）。
 *
 * 用 Get-Process 的 MainWindowTitle 找窗口，省掉 EnumWindows 回调那一大坨：
 * 断开 CDP 的那个 Chrome 是独立进程、独立档案、只开一个窗口，主窗口就是目标窗口。
 * 返回的是**客户区**矩形（屏幕坐标 + 客户区尺寸），于是 detachedClickOrigin 里的
 * `height - innerHeight` 正好是标签栏 + 地址栏的高度，`width - innerWidth` 约为 0。
 */
export function windowsWindowGeometryCommand(title) {
  // -like 的通配符只有 * ? []，窗口标题里是站点域名和固定前缀，不含这些
  const literal = String(title).replace(/'/g, "''")
  return `${PS_USER32}
$proc = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -like '*${literal}*' } | Select-Object -First 1
if (-not $proc) { exit 3 }
$hwnd = $proc.MainWindowHandle
$rect = New-Object 'RelayNative+RECT'
[void][RelayNative]::GetClientRect($hwnd, [ref]$rect)
$origin = New-Object 'RelayNative+POINT'
[void][RelayNative]::ClientToScreen($hwnd, [ref]$origin)
"WINDOW=$($hwnd.ToInt64())"
"X=$($origin.X)"
"Y=$($origin.Y)"
"WIDTH=$($rect.Right - $rect.Left)"
"HEIGHT=$($rect.Bottom - $rect.Top)"`
}

/**
 * 按标题问操作系统要窗口的真实几何与句柄。
 *
 * Chrome 自报的 outerHeight - innerHeight 并不可靠（没有窗口管理器的 Xvfb 上可能为 0，
 * 算出的点击点整体偏上、正好落在提示文字上——于是「点了却毫无反应」，Turnstile 连
 * error-callback 都不会触发）。系统给的数据不会骗人。
 * @returns {Promise<{windowId:string,x:number,y:number,width:number,height:number}|null>}
 */
export async function nativeWindowGeometry(display, title) {
  if (!display || nativePointerUnavailable()) return null
  if (display === POINTER_WINDOWS) {
    const res = await runPowerShell(windowsWindowGeometryCommand(title), 25000)
    return res.ok ? parseShellGeometry(res.stdout) : null
  }
  const res = await runCommand(
    'xdotool',
    ['search', '--onlyvisible', '--name', title, 'getwindowgeometry', '--shell'],
    { timeoutMs: 8000, env: { ...process.env, DISPLAY: display } }
  )
  return parseShellGeometry(res.stdout)
}

/**
 * 读指针的最终落点。点击「执行成功」但页面毫无反应时，
 * 这一个坐标就能区分「点歪了」和「点对了但组件没反应」。
 * @returns {Promise<string>} 形如 `(270, 332)`，取不到时为空串
 */
export async function nativeMouseLocation(display) {
  if (!display || nativePointerUnavailable()) return ''
  if (display === POINTER_WINDOWS) {
    const res = await runPowerShell(`${PS_USER32}
$point = New-Object 'RelayNative+POINT'
[void][RelayNative]::GetCursorPos([ref]$point)
"X=$($point.X)"
"Y=$($point.Y)"`, 25000)
    return res.ok ? parsePointerLocation(res.stdout) : ''
  }
  const res = await runCommand('xdotool', ['getmouselocation', '--shell'], {
    timeoutMs: 5000,
    env: { ...process.env, DISPLAY: display }
  })
  return parsePointerLocation(res.stdout)
}

/**
 * 决定真实指针该在哪里驱动。
 *
 * Windows / 有图形桌面的 Linux 机器本身就有指针可用（不会去起 Xvfb），
 * 以前这种情况一律要求用户自己动手点，其实没必要。
 * Wayland 桌面只有在 XWayland 也开着（DISPLAY 存在）时才驱动得动，此时要让 Chrome 走 X11。
 * @param {string|null} virtualDisplay 本插件自己拉起的 Xvfb display
 * @returns {string} 可用于点击的 display 或 POINTER_WINDOWS，空串表示只能手动点
 */
export function pointerDisplayFor(virtualDisplay, { platform = process.platform, env = process.env } = {}) {
  if (virtualDisplay) return virtualDisplay
  if (platform === 'win32') return POINTER_WINDOWS
  if (platform !== 'linux') return ''
  return env.DISPLAY || ''
}

// CommandLine 可能为空（系统进程），制表符分隔比 CSV / JSON 都好解析。
// 单个进程读不到就跳过（$ErrorActionPreference 是 Stop，不写 SilentlyContinue 会整条中断）
const WIN_PROCESS_COMMAND = 'Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object '
  + '{ "$($_.ProcessId)`t$($_.ParentProcessId)`t$($_.CommandLine)" }'

function runPowerShellSync(command, spawnImpl, timeoutMs = 20000) {
  for (const exe of psCandidates()) {
    let out = null
    try {
      out = spawnImpl(exe, psArgs(command), {
        encoding: 'utf8',
        timeout: timeoutMs,
        windowsHide: true,
        maxBuffer: 16 * 1024 * 1024
      })
    } catch {
      continue
    }
    if (out?.error?.code === 'ENOENT') continue
    psExecutable = exe
    return out?.status === 0 ? String(out.stdout || '') : ''
  }
  return ''
}

function parsePsOutput(text) {
  const list = []
  for (const line of String(text).split('\n')) {
    const m = line.match(/^\s*(\d+)\s+(\d+)\s+(.+)$/)
    if (!m) continue
    list.push({ pid: Number(m[1]), ppid: Number(m[2]), command: m[3] })
  }
  return list
}

function parseWinProcessOutput(text) {
  const list = []
  for (const line of String(text).split(/\r?\n/)) {
    const first = line.indexOf('\t')
    const second = first < 0 ? -1 : line.indexOf('\t', first + 1)
    if (second < 0) continue
    const pid = Number(line.slice(0, first))
    const ppid = Number(line.slice(first + 1, second))
    if (!Number.isInteger(pid) || pid <= 0) continue
    // 命令行本身含制表符的极端情况下，第二个制表符之后整段都算命令行
    list.push({ pid, ppid: Number.isInteger(ppid) ? ppid : 0, command: line.slice(second + 1) })
  }
  return list
}

/**
 * 取当前进程表。Windows 走 PowerShell 的 CIM 查询（约 1 秒，只在启动浏览器前用一次），
 * 其余平台走 ps。
 * @returns {Array<{pid: number, ppid: number, command: string}>}
 */
export function listProcesses({ platform = process.platform, spawn = spawnSync } = {}) {
  try {
    if (platform === 'win32') return parseWinProcessOutput(runPowerShellSync(WIN_PROCESS_COMMAND, spawn))
    const out = spawn('ps', ['-eo', 'pid=,ppid=,args='], { encoding: 'utf8', timeout: 5000 })
    if (out?.status !== 0 || !out?.stdout) return []
    return parsePsOutput(out.stdout)
  } catch {
    return []
  }
}

/**
 * 判断进程是不是「孤儿」——当初拉起它的进程已经没了（pm2 restart / 崩溃留下的残留）。
 *
 * Linux 上父进程死后子进程会被 init 收养，ppid 变成 1；Windows 不会重挂父子关系，
 * ppid 只是个指向已消失进程的悬空数字，所以那边的判据是「ppid 不在当前进程表里」。
 * @param {Set<number>} alivePids 当前存活的 pid 集合（仅 Windows 需要）
 */
export function isOrphanProcess(proc, alivePids, platform = process.platform) {
  if (platform !== 'win32') return proc.ppid === 1
  return !alivePids.has(proc.ppid)
}

/**
 * 命令行里的 --user-data-dir 是否指向给定档案目录。
 *
 * Windows 的命令行里路径可能被引号包起来（含空格时 Node 会自动加），
 * 分隔符和大小写也都不固定，所以逐个取出参数值再规范化比较，不能直接找子串。
 */
export function commandLineUsesProfile(command, userDataDir, platform = process.platform) {
  const flag = '--user-data-dir='
  const normalize = value => (platform === 'win32'
    ? String(value).replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase()
    : String(value))
  const want = normalize(userDataDir)
  const text = String(command || '')
  for (let from = 0; ;) {
    const idx = text.indexOf(flag, from)
    if (idx < 0) return false
    from = idx + flag.length
    const rest = text.slice(from)
    let value
    if (rest.startsWith('"')) {
      const close = rest.indexOf('"', 1)
      value = close < 0 ? rest.slice(1) : rest.slice(1, close)
    } else {
      const end = rest.indexOf(' ')
      value = end < 0 ? rest : rest.slice(0, end)
    }
    if (normalize(value) === want) return true
  }
}

/**
 * 杀掉一个进程连同它的子进程。
 *
 * Windows 没有进程组信号，只杀主进程会留下一堆渲染子进程继续占着浏览器档案目录
 * （于是「清理过了但下次照样起不来」），必须用 taskkill /T 收整棵树。
 * @returns {boolean} 是否成功发出终止
 */
export function killProcessTree(pid, { platform = process.platform, spawn = spawnSync } = {}) {
  if (platform === 'win32') {
    try {
      const out = spawn('taskkill', ['/F', '/T', '/PID', String(pid)], {
        encoding: 'utf8', timeout: 10000, windowsHide: true
      })
      return out?.status === 0
    } catch {
      return false
    }
  }
  try {
    process.kill(pid, 'SIGKILL')
    return true
  } catch {
    return false
  }
}
