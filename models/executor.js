import { getAdapter } from './adapters/index.js'
import { quotaToUsd, request, parseCheckinResult, classifyValidation, deriveAwardQuota } from './adapters/common.js'
import { powCheckin, turnstileCheckin } from './browser.js'
import { ocrCaptcha } from './ocr.js'
import { getConfig } from './config.js'
import { accountLabel, persist } from './store.js'
import { logger } from '../host/index.js'

export const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

/**
 * 落盘失败（磁盘满、Windows 文件被占用等）只记日志：
 * 签到结果本身已在内存，不能因缓存落盘失败让整轮任务中断
 */
function safePersist() {
  try {
    persist()
  } catch (err) {
    logger.error(`[relay-checkin-plugin] 状态缓存落盘失败: ${err?.message || err}`)
  }
}

export const randInt = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min

const STATUS_TEXT = { ok: '签到成功', already: '今日已签', unknown: '签到未确认', fail: '签到失败' }

/**
 * 站点回复是否属于「需要人机验证」类拦截（应降级到浏览器方案重试）：
 * 仅匹配明确的人机验证提示。网页 X-Game-* 完整性标记由 NewAPI 适配器单独处理，
 * 不能把所有「完整性 / 请刷新」错误误报成 Turnstile。
 */
function needsBrowser(msg) {
  return /turnstile|人机|验证码|captcha|访问验证|checking your browser|安全验证|verification_required|pow[_ -]?shield|proof.?of.?work/i.test(String(msg || ''))
}

/**
 * 图形验证码站点降级签到（NewAPI 魔改站常见流程）：
 * POST /api/user/checkin/captcha 取 captcha_id + 图片 → ddddocr 识别 → 带
 * captcha_id/captcha_answer 重新提交签到，答错自动换码重试。
 */
async function captchaFallback(account, adapter, checkinPath = adapter.checkinPath, maxAttempts = 15) {
  const headers = adapter.buildHeaders(account)
  const captchaUrl = new URL('/api/user/checkin/captcha', `${account.baseUrl}/`).toString()
  const checkinUrl = new URL(checkinPath, `${account.baseUrl}/`).toString()
  let lastMsg = ''

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const cap = await request(captchaUrl, { method: 'POST', headers })
    const captchaId = cap.json?.data?.captcha_id
    const image = cap.json?.data?.captcha_image
    if (!cap.json?.success || !captchaId || !image) {
      const msg = cap.json?.message || `HTTP ${cap.status}`
      const hint = /请打开网站/.test(String(msg)) ? '，这站签到只认网页会话，改用 #中转添加cookie 地址 session值 用户ID 绑一下吧' : ''
      logger.warn(`[relay-checkin-plugin] ${account.name} 获取验证码失败：${msg}`)
      return { ok: false, already: false, validation: 'captcha', msg: `拿不到验证码呀${hint}` }
    }

    let answer = ''
    try {
      answer = await ocrCaptcha(Buffer.from(image.replace(/^data:image\/\w+;base64,/, ''), 'base64'))
    } catch (err) {
      logger.warn(`[relay-checkin-plugin] ${account.name} 验证码识别异常：${err?.message || err}`)
      return { ok: false, already: false, validation: 'captcha', msg: '验证码认不出来呀，让主人看下日志哦' }
    }
    if (!answer) {
      lastMsg = '这张验证码嘟嘟没看清'
      continue
    }
    logger.warn(`[relay-checkin-plugin] ${account.name} 验证码识别：${answer}（第 ${attempt} 次）`)

    const res = await request(checkinUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({ captcha_id: captchaId, captcha_answer: answer })
    })
    const parsed = parseCheckinResult(res.status, res.json, res)
    if (parsed.ok || parsed.already) {
      logger.warn(`[relay-checkin-plugin] ${account.name} 验证码签到完成（第 ${attempt} 次尝试）`)
      return parsed
    }
    lastMsg = parsed.msg
    // 答错：站点侧验证码已作废，换新码重试
  }
  return { ok: false, already: false, validation: 'captcha', msg: `验证码试了 ${maxAttempts} 次都没对呀：${lastMsg}` }
}

/**
 * Turnstile 站点浏览器降级签到：取 site key → 页面内过挑战 → 带 token 重调签到接口
 */
async function turnstileFallback(account, adapter, checkinPath = adapter.checkinPath) {
  const headers = adapter.buildHeaders(account)
  let siteKey = null
  try {
    const { json } = await request(`${account.baseUrl}/api/status`, {
      headers
    })
    siteKey = json?.data?.turnstile_site_key || null
  } catch {
    // 取不到 site key 走下方统一失败
  }
  if (!siteKey) {
    return { ok: false, already: false, msg: '这站要过人机验证，可嘟嘟找不到验证组件呀' }
  }

  const res = await turnstileCheckin(account, {
    checkinPath,
    headers,
    validationHeaders: adapter.buildValidationHeaders?.(account) || headers,
    siteKey
  })
  if (res.turnstileFailed) {
    return { ok: false, already: false, msg: res.message || '人机验证没过去呀' }
  }
  const parsed = parseCheckinResult(res.status, res.json, res)
  if (!parsed.ok && parsed.validation === 'turnstile') {
    // 走到这里说明 Cloudflare 已经签发了 token、请求也发出去了（res.status 是站点的回复），
    // 站点却仍判验证不通过。实测最常见的原因是本机出口 IP 被判成高风险：数据中心 IP
    // 拿到的 token 在站点侧校验一律不通过，同一套代码换成非数据中心出口后立刻放行。
    // 手动点验证同样过不去，所以别再让用户去点。
    const detail = res.json?.message || res.json?.msg || ''
    logger.warn(`[relay-checkin-plugin] ${account.name} 已提交 Turnstile 凭据但站点判定失败`
      + `（HTTP ${res.status}${detail ? `｜${detail}` : ''}）：多半是本机出口 IP 被判成高风险，`
      + '在 proxy.url 配一个非数据中心出口后重试即可；站点的 site key 与 secret 不配对也会这样')
    parsed.msg = `${parsed.msg}（嘟嘟拿到验证凭据了可站点没认，给嘟嘟换个网络出口再试试~）`
  }
  return parsed
}

/**
 * NewAPI POW-Shield 浏览器签到：挑战、计算和 POST 必须留在同一个页面上下文。
 */
async function powFallback(account, adapter, checkinPath = adapter.checkinPath) {
  const headers = adapter.buildHeaders(account)
  const res = await powCheckin(account, {
    checkinPath,
    headers,
    validationHeaders: adapter.buildValidationHeaders?.(account) || headers
  })
  if (res.powFailed) {
    return { ok: false, already: false, uncertain: Boolean(res.uncertain), validation: 'pow', msg: res.message || '站点的安全验证没做完呀' }
  }
  return parseCheckinResult(res.status, res.json, res)
}

async function readCheckinStatus(adapter, account) {
  if (typeof adapter.getCheckinStatus !== 'function') return null
  try {
    return await adapter.getCheckinStatus(account)
  } catch (err) {
    logger.warn(`[relay-checkin-plugin] ${account.name} 签到状态查询失败: ${err?.message || err}`)
    return { supported: true, ok: false, msg: err?.message || String(err) }
  }
}

async function readUserInfo(adapter, account) {
  try {
    const info = await adapter.userInfo(account)
    return info?.ok ? info : null
  } catch {
    return null
  }
}

/**
 * 对单个账号执行签到，并顺带查询最新余额
 * @returns {Promise<{name, status, statusText, award, balance, msg}>}
 */
export async function checkinAccount(account) {
  const adapter = getAdapter(account.type)
  let r = null
  let beforeStatus = null
  let beforeInfo = null
  let afterInfo = null

  try {
    beforeStatus = await readCheckinStatus(adapter, account)
    if (beforeStatus?.ok && beforeStatus.checked) {
      // 明确查到本轮执行前已经签到：跳过非幂等 POST。
      r = {
        ok: true,
        already: true,
        confirmed: true,
        awardQuota: beforeStatus.awardQuota ?? null,
        awardText: beforeStatus.awardText ?? null,
        statusTextOverride: '本轮前已签到',
        msg: ''
      }
    } else {
      const compareBalance = typeof adapter.compareBalance === 'function'
        ? adapter.compareBalance(account)
        : adapter.compareBalance
      if (compareBalance || (beforeStatus?.ok && beforeStatus.checked === false)) {
        beforeInfo = await readUserInfo(adapter, account)
      }

      if (adapter.checkinWithInfo) {
        // AnyRouter 系在同一套 WAF cookie 下完成前后余额查询与签到。
        const session = await adapter.checkinWithInfo(account)
        r = session.checkin
        if (session.info?.ok) afterInfo = session.info
      } else {
        try {
          r = await adapter.checkin(account)
          if (r.info?.ok) afterInfo = r.info
        } catch (err) {
          r = { ok: false, already: false, uncertain: true, msg: err?.message || String(err) }
        }
        // 站点要求人机验证且浏览器方案可用时，自动降级为浏览器签到
        const validation = r?.validation || classifyValidation({ message: r?.msg })
        const browserCheckinPath = account.signPath || adapter.checkinPath
        // 图形验证码：不依赖浏览器，直接取码识别后重提签到
        if (!r.ok && browserCheckinPath && validation === 'captcha') {
          logger.info(`[relay-checkin-plugin] ${account.name} 需图形验证码，尝试自动识别`)
          try {
            r = await captchaFallback(account, adapter, browserCheckinPath)
          } catch (err) {
            logger.warn(`[relay-checkin-plugin] ${account.name} 验证码方案失败：${err?.message || err}`)
            r = { ok: false, already: false, validation: 'captcha', msg: '验证码这条路走不通呀，让主人看下日志哦' }
          }
        } else if (!r.ok && browserCheckinPath && getConfig().browser.enable && (validation || needsBrowser(r.msg))) {
          if (validation === 'pow' || /安全验证|pow[_ -]?shield|proof.?of.?work/i.test(r.msg || '')) {
            logger.info(`[relay-checkin-plugin] ${account.name} 需 POW 安全验证，尝试浏览器方案`)
            try {
              r = await powFallback(account, adapter, browserCheckinPath)
            } catch (err) {
              logger.warn(`[relay-checkin-plugin] ${account.name} POW 浏览器方案失败：${err?.message || err}`)
              r = { ok: false, already: false, validation: 'pow', msg: '安全验证这条路走不通呀，让主人看下日志哦' }
            }
          } else if (validation === 'turnstile' || (!validation && needsBrowser(r.msg))) {
            logger.info(`[relay-checkin-plugin] ${account.name} 需人机验证，尝试浏览器方案`)
            r = await turnstileFallback(account, adapter, browserCheckinPath)
          }
        }
      }

      const afterStatus = beforeStatus?.supported === false
        ? null
        : await readCheckinStatus(adapter, account)
      if (afterStatus?.ok && afterStatus.checked) {
        const changedThisRun = beforeStatus?.ok && beforeStatus.checked === false
        if (!r.ok || r.already) {
          r = {
            ok: true,
            already: !changedThisRun,
            confirmed: true,
            awardQuota: r.awardQuota ?? afterStatus.awardQuota ?? null,
            awardText: r.awardText ?? afterStatus.awardText ?? null,
            statusTextOverride: changedThisRun ? '状态复核成功' : '状态复核已签',
            msg: ''
          }
        } else {
          r.confirmed = true
          if (r.awardQuota == null) r.awardQuota = afterStatus.awardQuota ?? null
          if (r.awardText == null) r.awardText = afterStatus.awardText ?? null
        }
      } else if (r.uncertain && afterStatus?.ok && !afterStatus.checked) {
        r.msg = `${r.msg}；复查了一下还是没签上呀`
      }
    }
  } catch (err) {
    r = { ok: false, already: false, msg: err?.message || String(err) }
  }

  // 查询签到后余额；失败不影响已经确认的签到结果。
  if (!afterInfo) afterInfo = await readUserInfo(adapter, account)
  if (!r?.ok && r?.uncertain && adapter.reconcileByBalance) {
    const awardQuota = deriveAwardQuota(beforeInfo, afterInfo)
    if (awardQuota != null) {
      r = {
        ok: true,
        already: false,
        confirmed: true,
        awardQuota,
        statusTextOverride: '余额复核成功',
        msg: ''
      }
    }
  }
  return finalizeCheckinResult(account, r, { beforeInfo, afterInfo })
}

/**
 * 用户可见文案的最后一道关。
 *
 * 站点抛出的原始异常（fetch failed / HTTP 5xx / 类型错误）对用户毫无意义，统一换成人话。
 * 只能放在这一层：上游的 r.msg 还要参与 classifyValidation / needsBrowser 的关键词判断，
 * 提前替换会让「站点要求人机验证」这类自动降级失效。真实原因都已写进日志。
 */
function friendlyMsg(msg) {
  const text = String(msg || '')
  if (!text) return ''
  if (/请求超时|timeout|aborted/i.test(text)) return '站点太慢啦，等下再试呀~'
  if (/fetch failed|ENOTFOUND|ECONNREFUSED|ECONNRESET|EAI_AGAIN|certificate|socket/i.test(text)) {
    return '连不上这个站呀，检查下网络哦'
  }
  if (/请求失败|HTTP \d{3}/i.test(text)) return '站点没好好回话呀，晚点再试试~'
  if (/TypeError|ReferenceError|Cannot read|undefined is not/i.test(text)) return '出了点小岔子，让主人看下日志哦'
  return text
}

/**
 * 把适配器结果整理成统一展示行，并更新账号运行状态。
 * AgentRouter 邮箱登录响应的 quota 可能是 0 占位值；登录后会用新 Session
 * 再查一次 /api/user/self，不能把登录响应余额直接用于结果图。
 */
export function finalizeCheckinResult(account, r, { beforeInfo = null, afterInfo = null } = {}) {
  const result = { name: accountLabel(account), status: 'fail', statusText: '', award: '', balance: '-', msg: '' }
  if (afterInfo?.balanceText) result.balance = afterInfo.balanceText
  else if (r?.balanceText) result.balance = r.balanceText

  if (r?.ok && !r.already && r.awardQuota == null) {
    r.awardQuota = deriveAwardQuota(beforeInfo, afterInfo)
  }

  if (r?.ok) {
    result.status = r.confirmed === false ? 'unknown' : (r.already ? 'already' : 'ok')
    result.statusText = r.statusTextOverride || STATUS_TEXT[result.status]
    result.msg = friendlyMsg(r.msg)
    // Sub2API 等站点的奖励本身就是美元金额，由适配器直接给出文本，不走 quota 换算
    const value = r.awardText ?? (r.awardQuota != null ? (quotaToUsd(r.awardQuota) ?? r.awardQuota) : null)
    if (value != null) {
      result.award = r.already ? `今日 +${value}` : `+${value}`
    }
  } else {
    result.status = 'fail'
    result.statusText = STATUS_TEXT.fail
    result.msg = friendlyMsg(r?.msg) || '没签上呀'
  }

  // 缓存运行时状态供 #中转列表 展示（由调用方批量落盘）
  const now = new Date().toISOString()
  if (result.status === 'ok' || result.status === 'already') {
    account.lastCheckinAt = now
    account.lastCheckinAttemptAt = now
    account.lastCheckinConfirmed = true
  } else if (result.status === 'unknown') {
    account.lastCheckinAttemptAt = now
    account.lastCheckinConfirmed = false
  }
  if (result.balance !== '-') account.lastBalance = result.balance

  return result
}

/**
 * 对一个用户条目的全部（或指定序号）账号执行签到
 * @param {object} entry 存储条目
 * @param {object} opts { index: 1起的序号(可选), delayRange: [min,max]秒(可选，账号间随机间隔),
 *                        autoOnly: 仅执行定时开关打开的账号（定时任务用） }
 */
export async function checkinEntry(entry, { index = null, delayRange = null, autoOnly = false } = {}) {
  let accounts = index ? [entry.accounts[index - 1]].filter(Boolean) : entry.accounts
  if (autoOnly) accounts = accounts.filter(acc => acc.auto !== false)
  const results = []
  for (let i = 0; i < accounts.length; i++) {
    if (i > 0 && delayRange) {
      await sleep(randInt(delayRange[0], delayRange[1]) * 1000)
    }
    results.push(await checkinAccount(accounts[i]))
  }
  safePersist()
  return results
}

/**
 * 刷新条目内各账号的余额缓存（#中转列表 用）：
 * 纯 HTTP 站实时查询；AnyRouter 等浏览器站太慢，跳过用缓存。
 * 并发执行，单账号超时/失败保留旧缓存，不影响其他账号
 *
 * allowBrowser: false 会传给支持该选项的适配器（sub2api）：凭据过期时它本可以开浏览器
 * 重新过码登录（一两分钟），但这里 10 秒就超时了，被丢下的浏览器任务仍会占着全局页面
 * 槽位，把后续签到一起拖慢，所以列表刷新一律不许拉起浏览器。
 */
const BROWSER_TYPES = new Set(['anyrouter'])

export async function refreshBalances(entry, { timeoutMs = 10000 } = {}) {
  await Promise.allSettled(entry.accounts.map(async account => {
    if (BROWSER_TYPES.has(account.type)) return
    const adapter = getAdapter(account.type)
    let timer = null
    try {
      // 超时后原 promise 仍会被本 race 接管（不会变成未处理拒绝），同时清掉定时器避免悬挂
      const info = await Promise.race([
        adapter.userInfo(account, { allowBrowser: false }),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error('刷新超时')), timeoutMs)
        })
      ])
      if (info.ok) {
        account.lastBalance = info.balanceText
        if (info.username) account.username = info.username
      }
    } finally {
      if (timer) clearTimeout(timer)
    }
  }))
  safePersist()
}

/**
 * 余额查询（不签到）
 * @returns {Promise<Array<{name, status, statusText, award, balance, msg}>>}
 */
export async function queryEntry(entry) {
  const results = []
  for (const account of entry.accounts) {
    const adapter = getAdapter(account.type)
    const row = { name: accountLabel(account), status: 'ok', statusText: '正常', award: '', balance: '-', msg: '' }
    try {
      const info = await adapter.userInfo(account)
      if (info.ok) {
        row.balance = info.balanceText
        row.award = `已用 ${info.usedText}`
        account.lastBalance = info.balanceText
      } else {
        row.status = 'fail'
        row.statusText = '查询失败'
        row.msg = friendlyMsg(info.msg)
      }
    } catch (err) {
      logger.warn(`[relay-checkin-plugin] ${account.name} 余额查询异常: ${err?.message || err}`)
      row.status = 'fail'
      row.statusText = '查询失败'
      row.msg = friendlyMsg(err.message)
    }
    results.push(row)
  }
  safePersist()
  return results
}
