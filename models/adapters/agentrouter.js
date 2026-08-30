import { request, parseUserInfo, isAliyunWafPage } from './common.js'
import { logger } from '../../host/index.js'

/**
 * AgentRouter 的 $25 签到发生在一次真正的新登录中。
 * 邮箱模式使用用户重置后的 AgentRouter 站内密码，每轮都用不带旧 Cookie 的
 * POST /api/user/login 重新登录；旧 Cookie 模式只能验证会话和查询余额。
 */
const adapter = {
  type: 'agentrouter',
  label: 'AgentRouter',
  reconcileByBalance: true,

  buildHeaders(account) {
    return {
      Cookie: `session=${account.token || ''}`,
      'New-Api-User': String(account.siteUserId ?? ''),
      'X-Requested-With': 'XMLHttpRequest',
      'Content-Type': 'application/json'
    }
  },

  compareBalance(account) {
    return hasEmailLogin(account)
  },

  async userInfo(account) {
    const { json } = await request(`${account.baseUrl}/api/user/self`, {
      headers: this.buildHeaders(account)
    })
    return parseUserInfo(json)
  },

  async login(account) {
    if (!hasEmailLogin(account)) {
      return { ok: false, already: false, msg: '这个账号没存邮箱和站内密码呀，重新绑一下吧' }
    }

    // 不携带旧 session，直接执行一次全新的邮箱登录。
    const res = await request(`${account.baseUrl}/api/user/login?turnstile=`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: account.baseUrl,
        Referer: `${account.baseUrl}/login?expired=true`,
        'X-Requested-With': 'XMLHttpRequest'
      },
      body: {
        username: account.loginEmail,
        password: account.password
      }
    })

    const json = res.json
    if (!json?.success || !json?.data) {
      if (isAliyunWafPage(res)) {
        logger.warn(`[relay-checkin-plugin] ${account.baseUrl} 的登录接口被阿里云 WAF 拦下`
          + `（HTTP ${res.status}，返回滑块验证页而不是 JSON）：该站已开启滑动验证，`
          + '纯 HTTP 与本机浏览器都过不去；换一个非数据中心出口（proxy.url）即可恢复，'
          + 'Cookie 模式同样被拦，不是替代方案')
      }
      return { ok: false, already: false, msg: loginError(res.status, json, res) }
    }

    const data = json.data
    const session = sessionCookieFrom(res.setCookies)
    if (session) account.token = session
    if (data.id != null) account.siteUserId = data.id

    const checkedIn = typeof data.checked_in === 'boolean' ? data.checked_in : null
    if (checkedIn === true) {
      return {
        ok: true,
        already: false,
        confirmed: true,
        awardQuota: await readLoginAwardQuota(account),
        statusTextOverride: '邮箱登录签到成功'
      }
    }
    if (checkedIn === false) {
      return {
        ok: true,
        already: true,
        confirmed: true,
        statusTextOverride: '今日已签（登录复核）'
      }
    }
    return {
      ok: true,
      already: false,
      confirmed: false,
      msg: '登录成功啦，但站点没说签到有没有算上呀',
      statusTextOverride: '登录成功·签到未确认'
    }
  },

  async checkin(account) {
    if (hasEmailLogin(account)) return await this.login(account)

    const res = await request(`${account.baseUrl}/api/user/self`, {
      headers: this.buildHeaders(account)
    })
    if (isAliyunWafPage(res)) {
      logger.warn(`[relay-checkin-plugin] ${account.baseUrl} 的用户接口被阿里云 WAF 拦下`
        + `（HTTP ${res.status}，返回滑块验证页）：这台机器过不去该站的滑动验证，`
        + '在 proxy.url 配一个非数据中心出口后重试')
      return { ok: false, already: false, msg: '这站挂了滑动验证，嘟嘟连余额都查不到呀，给嘟嘟配个代理吧' }
    }
    const info = parseUserInfo(res.json)
    if (!info.ok) return { ok: false, already: false, msg: info.msg || 'Session 不好用了呀，重新绑一下吧' }
    return {
      ok: true,
      already: false,
      confirmed: false,
      msg: 'Cookie 只能看余额，今天的 $25 领没领嘟嘟说不准呀（用 #中转添加邮箱 绑定才能自动领）',
      statusTextOverride: 'Session 有效·未重登',
      balanceText: info.balanceText,
      info
    }
  }
}

export function hasEmailLogin(account) {
  return account?.authMode === 'email' &&
    Boolean(String(account.loginEmail || '').trim()) &&
    Boolean(String(account.password || ''))
}

export function sessionCookieFrom(setCookies = []) {
  for (const value of Array.isArray(setCookies) ? setCookies : [setCookies]) {
    const match = /(?:^|,\s*)session=([^;,]+)/i.exec(String(value || ''))
    if (match?.[1]) return match[1].trim()
  }
  return null
}

export function parseLoginAwardQuota(json) {
  const data = json?.data
  const quotaPerUnit = Number(data?.quota_per_unit)
  if (!Number.isFinite(quotaPerUnit) || quotaPerUnit <= 0) return null
  const announcements = Array.isArray(data?.announcements) ? data.announcements : []
  const text = announcements.map(item => String(item?.content || '')).join('\n')
  const match = /签到[^\n$]{0,30}(?:送|赠送|奖励)?\s*\$\s*(\d+(?:\.\d+)?)/i.exec(text)
  const credit = Number(match?.[1])
  return Number.isFinite(credit) && credit > 0
    ? Math.round(credit * quotaPerUnit)
    : null
}

async function readLoginAwardQuota(account) {
  try {
    const { json } = await request(`${account.baseUrl}/api/status`)
    return parseLoginAwardQuota(json)
  } catch {
    return null
  }
}

export function loginError(status, json, response = null) {
  const msg = json?.message || json?.msg
  if (msg) return `登录失败：${msg}`
  // WAF 拦截页也是 HTTP 200，先认出来再谈状态码，否则用户只看到「响应异常」
  if (isAliyunWafPage(response)) return '这站挂了滑动验证，嘟嘟过不去呀，给嘟嘟配个代理再试试~'
  if (status === 401 || status === 403) return `登录失败：邮箱或密码无效 (HTTP ${status})`
  if (status === 404) return '站点没有邮箱登录接口'
  return `登录响应异常 (HTTP ${status})`
}

export default adapter
