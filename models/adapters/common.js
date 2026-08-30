import { getConfig } from '../config.js'
import { assertSafeRequestUrl } from '../url-security.js'
import { logger } from '../../host/index.js'

/**
 * 按代理配置判断某 host 是否走代理，返回代理地址或 null（纯函数便于测试）
 * hosts 为域名关键字（包含匹配）；空数组 = 配置了代理后全部走代理
 */
export function matchProxy(host, proxyCfg) {
  if (!proxyCfg?.url) return null
  const hosts = (Array.isArray(proxyCfg.hosts) ? proxyCfg.hosts : []).filter(Boolean)
  if (!hosts.length) return proxyCfg.url
  return hosts.some(h => String(host).includes(String(h))) ? proxyCfg.url : null
}

/**
 * 当前配置下某 host 应使用的代理地址（无需代理返回 null）
 * @param {boolean} forBrowser 无头浏览器用：proxy.useForBrowser=false 时返回 null
 *   （Clash 等开启 TUN/系统代理时，Chrome 显式走 --proxy-server 可能形成环路，
 *   此时应让浏览器直连、由系统层透明代理转发）
 */
export function proxyForHost(host, forBrowser = false) {
  const cfg = getConfig().proxy
  if (forBrowser && cfg?.useForBrowser === false) return null
  return matchProxy(host, cfg)
}

let proxyAgentCache = null

/**
 * 复用 Yunzai 根目录自带的 https-proxy-agent 构建代理 Agent（按代理地址缓存）
 * 兼容 v7（具名导出 HttpsProxyAgent）与 v5（默认导出）
 */
async function getProxyAgent(proxyUrl) {
  if (proxyAgentCache?.url === proxyUrl) return proxyAgentCache.agent
  let mod
  try {
    mod = await import('https-proxy-agent')
  } catch {
    throw new Error('未找到 https-proxy-agent 依赖（Yunzai 自带），代理不可用')
  }
  const HttpsProxyAgent = mod.HttpsProxyAgent ?? mod.default
  if (typeof HttpsProxyAgent !== 'function') {
    throw new Error('https-proxy-agent 版本不兼容，代理不可用')
  }
  proxyAgentCache = { url: proxyUrl, agent: new HttpsProxyAgent(proxyUrl) }
  return proxyAgentCache.agent
}

/**
 * 经 http 代理请求 https 站点（node:https + proxy agent；不跟随重定向，与 fetch 路径语义一致）
 * 用独立定时器兜底超时：options.timeout 依赖 socket 分配，代理 CONNECT 阶段挂起时不会触发
 */
async function proxiedRequest(url, { method, headers, body, timeoutMs, proxyUrl }) {
  const agent = await getProxyAgent(proxyUrl)
  const { request: httpsRequest } = await import('node:https')
  return await new Promise((resolve, reject) => {
    const req = httpsRequest(url, { method, headers, agent }, res => {
      const chunks = []
      res.on('data', c => chunks.push(c))
      res.on('end', () => {
        clearTimeout(timer)
        const text = Buffer.concat(chunks).toString('utf8')
        let json = null
        try {
          json = JSON.parse(text)
        } catch {
          // 非 JSON 响应
        }
        resolve({
          status: res.statusCode,
          json,
          contentType: String(res.headers['content-type'] || ''),
          textSnippet: json ? '' : text.slice(0, 512),
          bodyLength: text.length,
          setCookies: Array.isArray(res.headers['set-cookie'])
            ? res.headers['set-cookie']
            : (res.headers['set-cookie'] ? [String(res.headers['set-cookie'])] : [])
        })
      })
    })
    const timer = setTimeout(() => req.destroy(new Error('代理请求超时（代理隧道无响应）')), timeoutMs)
    req.on('error', err => {
      clearTimeout(timer)
      reject(err)
    })
    if (body != null) req.write(body)
    req.end()
  })
}

/**
 * 非 JSON 响应只记录形状，不记录正文：HTML 里可能回显用户信息，接口 URL 也可能带
 * 一次性令牌。有限标记足够区分 Cloudflare 页面、登录页和普通空响应。
 */
function requestPathname(targetUrl) {
  try { return new URL(targetUrl).pathname || '/' } catch { return '[invalid-url]' }
}

function logNonJsonResponse(method, targetUrl, response) {
  if (response?.json != null) return
  const snippet = String(response?.textSnippet || '')
  const markers = [
    /<!doctype\s+html|<html[\s>]/i.test(snippet) ? 'html' : '',
    /cloudflare|turnstile|challenge-platform/i.test(snippet) ? 'cloudflare' : '',
    /登录|login|sign[ -]?in/i.test(snippet) ? 'login' : ''
  ].filter(Boolean)
  logger.warn(`[relay-checkin-plugin] ${method} ${requestPathname(targetUrl)} 返回非 JSON：`
    + `HTTP ${response?.status ?? '?'}｜Content-Type=${response?.contentType || '未知'}`
    + `｜长度=${Number.isFinite(response?.bodyLength) ? response.bodyLength : '未知'}`
    + `｜类型=${markers.join(',') || '未知'}`)
}

/**
 * 发起 JSON 请求（带超时与重试；命中代理配置的 https 站点走代理）
 * @param {object} opts { method, headers, body: JSON 对象或字符串,
 *                        timeoutMs: 覆盖配置超时, maxRetry: 覆盖配置重试次数 }
 * @returns {Promise<{status: number, json: object|null, setCookies: string[]}>}
 */
export async function request(url, { method = 'GET', headers = {}, body = null, timeoutMs = null, maxRetry = null } = {}) {
  const cfg = getConfig()
  const tMs = timeoutMs ?? (cfg.request.timeout || 15) * 1000
  const normalizedMethod = String(method || 'GET').toUpperCase()
  const idempotent = ['GET', 'HEAD', 'OPTIONS'].includes(normalizedMethod)
  // 签到 POST 不能自动重试：第一次可能已在服务端成功，只是响应在途中丢失。
  const retries = idempotent ? (maxRetry ?? (cfg.request.retry ?? 2)) : 0
  let requestBody = body
  const fullHeaders = {
    'User-Agent': cfg.request.userAgent,
    Accept: 'application/json',
    ...headers
  }
  if (body != null && typeof body !== 'string' && !Buffer.isBuffer(body)) {
    requestBody = JSON.stringify(body)
    if (!Object.keys(fullHeaders).some(key => key.toLowerCase() === 'content-type')) {
      fullHeaders['Content-Type'] = 'application/json'
    }
  }
  const safeUrl = await assertSafeRequestUrl(url)
  const targetUrl = safeUrl.href
  const proxyUrl = safeUrl.protocol === 'https:' ? proxyForHost(safeUrl.hostname) : null

  let lastErr = null
  for (let attempt = 0; attempt <= retries; attempt++) {
    if (proxyUrl) {
      try {
        const response = await proxiedRequest(targetUrl, {
          method: normalizedMethod,
          headers: fullHeaders,
          body: requestBody,
          timeoutMs: tMs,
          proxyUrl
        })
        logNonJsonResponse(normalizedMethod, targetUrl, response)
        return response
      } catch (err) {
        lastErr = err
        continue
      }
    }
    const controller = new AbortController()
    let timedOut = false
    const timer = setTimeout(() => {
      timedOut = true
      controller.abort()
    }, tMs)
    try {
      const res = await fetch(targetUrl, {
        method: normalizedMethod,
        headers: fullHeaders,
        body: requestBody,
        redirect: 'manual',
        signal: controller.signal
      })
      let json = null
      let text = ''
      if (typeof res.text === 'function') {
        text = await res.text()
        try { json = JSON.parse(text) } catch { /* 非 JSON 响应 */ }
      } else {
        try { json = await res.json() } catch { /* 测试桩或非 JSON 响应 */ }
      }
      const response = {
        status: res.status,
        json,
        contentType: String(res.headers?.get?.('content-type') || ''),
        textSnippet: json ? '' : text.slice(0, 512),
        bodyLength: text.length,
        setCookies: responseSetCookies(res.headers)
      }
      logNonJsonResponse(normalizedMethod, targetUrl, response)
      return response
    } catch (err) {
      lastErr = timedOut
        ? new Error(`请求超时（${tMs / 1000} 秒）`)
        : err
    } finally {
      clearTimeout(timer)
    }
  }
  // 用户只会看到「连不上」这类人话，真实原因（超时/DNS/证书）只有这里留得住
  logger.warn(`[relay-checkin-plugin] ${normalizedMethod} ${requestPathname(targetUrl)} 请求失败: ${lastErr?.message || lastErr}`)
  throw new Error(`${normalizedMethod} 请求失败: ${lastErr?.message || lastErr}`)
}

function responseSetCookies(headers) {
  if (!headers) return []
  if (typeof headers.getSetCookie === 'function') {
    const values = headers.getSetCookie()
    if (Array.isArray(values)) return values.map(String)
  }
  const combined = headers.get?.('set-cookie')
  return combined ? [String(combined)] : []
}

/**
 * new-api 系 quota 换算美元（500000 quota = $1），兼容字符串数字；
 * 缺失值（null/undefined/空串）返回 null 而非 $0.00
 */
export function quotaToUsd(quota) {
  if (quota === null || quota === undefined || quota === '') return null
  const n = Number(quota)
  if (!Number.isFinite(n)) return null
  return '$' + (n / 500000).toFixed(2)
}

/**
 * 解析 /api/user/self 响应为统一结构
 */
export function parseUserInfo(json) {
  if (!json?.success || !json?.data) {
    return { ok: false, msg: json?.message || '获取用户信息失败' }
  }
  const d = json.data
  return {
    ok: true,
    username: d.display_name || d.username || '',
    siteUserId: d.id,
    quota: d.quota,
    usedQuota: d.used_quota,
    checkedIn: typeof d.checked_in === 'boolean' ? d.checked_in : null,
    balanceText: quotaToUsd(d.quota) ?? '-',
    usedText: quotaToUsd(d.used_quota) ?? '-'
  }
}

/**
 * 识别签到接口要求的校验类型。
 * NewAPI 及其魔改站的校验提示既可能放在 message，也可能放在 code/error_code，
 * 因此先统一分类，再由执行器选择 Turnstile、POW 或普通 WAF 处理。
 */
export function classifyValidation(json, meta = {}) {
  const msg = json?.message || json?.msg || json?.error?.message || ''
  const code = json?.code || json?.error_code || json?.error?.code || ''
  const text = `${code} ${msg} ${meta.textSnippet || ''}`
  if (/pow[_ -]?shield|pow[_ -]?(?:captcha|token)|verification_required|verification_expired|verification_invalid|需要完成安全验证|安全验证|security verification|proof.?of.?work/i.test(text)) {
    return 'pow'
  }
  if (/turnstile/i.test(text)) return 'turnstile'
  if (/captcha|验证码|人机|请打开网站|请从网站页面发起签到/i.test(text)) return 'captcha'
  if (/访问验证|checking your browser|aliyun_waf|acw_sc|cloudflare|waf/i.test(text)) return 'waf'
  return null
}

/**
 * 解析签到响应为统一结构
 */
export function parseCheckinResult(status, json, meta = {}) {
  if ([520, 521, 522, 523, 524, 525, 526].includes(Number(status))) {
    return { ok: false, already: false, msg: '站点没反应呀，晚点再试试~' }
  }
  if (status === 404) {
    return { ok: false, already: false, msg: '这站没有签到功能呀' }
  }
  if (status === 301 || status === 302) {
    return { ok: false, already: false, msg: '站点让嘟嘟去登录呀，凭据大概过期了，重新绑一下吧' }
  }
  const msg = json?.message || json?.msg || json?.error?.message || ''
  const validation = classifyValidation(json, meta)
  if (validation) {
    const validationMessage = {
      turnstile: '这站要过人机验证呀',
      pow: '这站要做安全验证呀',
      captcha: '这站要填验证码呀',
      waf: '被站点的防护拦下来啦'
    }[validation]
    return { ok: false, already: false, validation, msg: validationMessage }
  }
  if (status === 401 || status === 403) {
    return { ok: false, already: false, msg: '凭据不好用了呀，重新绑一下吧' }
  }
  if (Number(status) === 0 && meta?.error) {
    return { ok: false, already: false, msg: '连不上这个站呀，检查下网络哦' }
  }
  if (!json) {
    return { ok: false, already: false, msg: '站点回了句嘟嘟看不懂的话呀' }
  }
  const success = json.success === true ||
    (json.success == null && (json.ret === 1 || json.code === 0 || json.code === '0'))
  if (success) {
    // new-api 为 quota_awarded；Veloera 为 quota（均为本次奖励额度）
    const award = json.data?.quota_awarded ?? json.data?.quota ?? json.quota_awarded ?? json.quota ?? null
    return { ok: true, already: false, msg: msg || '签到成功', awardQuota: award }
  }
  if (/已签|签过|重复签|already/i.test(msg)) {
    return { ok: true, already: true, msg: '今日已签到' }
  }
  return { ok: false, already: false, msg: msg || '签到失败' }
}

/**
 * 用签到前后的「余额 + 累计消耗」推导新增额度，避免把同时发生的消费算成负奖励。
 */
export function deriveAwardQuota(before, after) {
  const values = [before?.quota, before?.usedQuota, after?.quota, after?.usedQuota].map(Number)
  if (values.some(value => !Number.isFinite(value))) return null
  const delta = (values[2] + values[3]) - (values[0] + values[1])
  return delta > 0 ? delta : null
}
