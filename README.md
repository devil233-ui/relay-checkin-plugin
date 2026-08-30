# relay-checkin-plugin

中转站自动签到插件。手动签到 / 每日定时 / 余额查询，结果出图，数据按用户隔离，群内所有人可用。

支持 **new-api、Veloera 及同源魔改站、AnyRouter、AgentRouter、Sub2API**，站点类型自动识别。
宿主支持 **TRSS-Yunzai**（OneBot v11）与 **[Yunzai NG](https://github.com/Yunzai-NG/yunzai-ng)**。

> **本仓库是 Fork**，上游：[Cat-bl/relay-checkin-plugin](https://github.com/Cat-bl/relay-checkin-plugin)。
> 两个镜像同步更新：[GitHub](https://github.com/cchanlan/relay-checkin-plugin) ·
> [GitCode](https://gitcode.com/ccxhan/relay-checkin-plugin)（国内更快）

所有 `#中转xxx` 都兼容 `#中转站xxx` 写法。

## 相对上游新增

- 同一份代码兼容 Yunzai NG（宿主依赖收进 `host/` 适配层，指令逻辑不动）
- 新增 **Sub2API** 站点：自动识别、邮箱密码或 refresh_token 绑定、过期走纯 HTTP 续期不开浏览器
- 新增 `#中转添加刷新令牌`：本机过不去码的站点可直接用浏览器抓的 token 绑定
- **图形验证码自动识别**（ddddocr），答错自动换码重试
- **Turnstile 改为断开调试连接后由页面自治过码** —— 实测 CDP 会话连着就必被判自动化
- **三个平台都能自动勾选**：Windows 走 PowerShell + user32 真实指针，有桌面的机器用本机指针，
  无桌面 Linux 自动拉 Xvfb + xdotool
- 失败留档（页内步骤日志、组件位置、指针落点、截图），并绕开 Puppeteer 13 吞掉 Chrome stderr 的问题
- 浏览器档案占用自愈、锅巴配置面板、new-api 网页会话（`authMode: session`）支持

## 安装

在 Yunzai 根目录执行（两个仓库内容相同）：

```bash
git clone --depth=1 https://gitcode.com/ccxhan/relay-checkin-plugin ./plugins/relay-checkin-plugin
# GitHub 也行：https://github.com/cchanlan/relay-checkin-plugin
```

重启即可，依赖蹭 Yunzai 自带的。

### 人机验证（Turnstile）的运行环境

过码要在真实显示环境里用**系统级指针**勾选复选框（CDP 注入的点击一律被判自动化），
各平台的准备工作不同：

| 系统 | 要装什么 | 说明 |
| --- | --- | --- |
| 无桌面 Linux | `apt install -y xvfb xdotool` | 自动拉虚拟屏，全程无人值守 |
| 有桌面 Linux | `apt install -y xdotool` | 用本机桌面，勾选时会短暂占用鼠标 |
| Windows 10 / 11 | 无需安装 | 用系统自带 PowerShell 调 user32 指针。要在**已登录的桌面会话**里跑 Yunzai，装成 Windows 服务会起不来浏览器 |
| macOS | — | 没有免安装的指针工具，需要自己在弹出的窗口里点一下 |

另外建议装最新的 Chrome 或 Edge，Turnstile 会拒绝过旧内核。

### 图形验证码（可选）

部分 NewAPI 魔改站签到要填图形码，装了才能自动识别：

```bash
cd plugins/relay-checkin-plugin
# 推荐：系统 Python 3.14 的 ensurepip 可能携带不兼容的旧 pip
uv venv --python 3.13 .venv
uv pip install --python .venv/bin/python ddddocr
# 已有 Python 3.13 或更低版本且 venv 正常时，也可使用：
# python3 -m venv .venv && .venv/bin/python -m pip install ddddocr
py -m venv .venv && .venv\Scripts\pip install ddddocr    # Windows
```

系统 Python 3.14 如果执行 `python3 -m venv` 后没有 `pip`，通常是 `ensurepip` 携带的
旧版 pip 仍引用已移除的 `pkgutil.ImpImporter`；请按上面的 uv 方式使用 Python 3.13。

### 装在 Yunzai NG 上

```bash
# 在 NG 主目录执行
git clone --depth=1 https://github.com/cchanlan/relay-checkin-plugin ./plugins/relay-checkin-plugin
# NG 侧没有现成依赖可蹭。puppeteer 只用于过码，出图走内核渲染器，可跳过 Chromium 下载
PUPPETEER_SKIP_DOWNLOAD=1 npm install --prefix ./plugins/relay-checkin-plugin
```

NG 侧另有面板配置与 `ctx.cron` 定时（改 cron 立即生效），出图交给渲染器插件。

## 指令

```
#中转添加 站点地址 [令牌]        令牌绑定，群里可只发地址、私聊补令牌
#中转添加cookie 站点地址 session  只认网页会话的魔改站
#中转添加邮箱 站点地址 邮箱 密码   AgentRouter / Sub2API
#中转添加刷新令牌 站点地址 令牌     Sub2API，过不去码时用

#中转签到 [序号]     不带序号签全部
#中转查询           余额
#中转列表           各账号余额、今日状态、定时开关
#中转删除 序号
#中转定时 开/关 [序号]

#中转开启群推送 / #中转关闭群推送    群管理用，把本群设为定时结果推送目标
#中转帮助  #中转插件更新
```

同一站点可绑多个账号（按站点用户 ID 区分）；添加成功会自动签一次。
群里发含令牌的指令会自动尝试撤回，列表图里令牌打码。

## 配置

改 `data/config.yaml`，或装了锅巴在面板里改（保存即生效，保留注释）。分组如下：

| 段 | 常用项 |
| --- | --- |
| `schedule` | `cron` 定时时间、`jitterMinutes` 随机抖动、`accountDelay` 账号间隔、`concurrency` 并发 |
| `push` | `mode`（`group` 群合并转发 / `private` 私聊 / `off`）、`usersPerImage` 一张图几个人 |
| `browser` | `turnstileTimeoutSec` 过码超时、`maxConcurrentPages` 页面并发、`executablePath` 指定 Chrome |
| `request` | `timeout`、`retry`、`userAgent` |
| `bind` | `timeoutSec` 私聊补令牌的等待时长、`groupRecallSec` 群内撤回延迟 |
| `proxy` | `url` 与 `hosts`（只对指定站点走代理）、`useForBrowser` |
| `security` | `allowHttp`、`allowedPrivateHosts` |

## 已知限制

- Turnstile 升级到人工挑战时仍需接管，插件会把截图发出来
- AnyRouter 等纯浏览器站的余额走缓存，不是每次实时刷
- 一次性 refresh_token 轮换后立刻落盘，但若同时手动操作可能撞车，重绑即可
- 上游与本 fork 都不保证站点接口稳定，站点改版可能需要跟进

仅供学习交流，账号风险自负。

