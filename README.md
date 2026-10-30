# mihomo-lite

> 版本：v1.5.15
>
> **⚠️ 测试阶段（BETA）**：本项目当前处于测试阶段，功能与配置格式可能随时调整，请勿在生产环境使用。

mihomo 内核多协议服务端一键管理脚本，交互风格参考 [singbox-lite](https://github.com/0xdabiaoge/singbox-lite)。

## 🚀 一键安装

```bash
(curl -LfsS https://raw.githubusercontent.com/guanxi660-crypto/mihomo-lite/main/mihomo-lite.sh -o /usr/local/bin/mh || wget -q https://raw.githubusercontent.com/guanxi660-crypto/mihomo-lite/main/mihomo-lite.sh -O /usr/local/bin/mh) && chmod +x /usr/local/bin/mh && mh
```

脚本拉取不畅时用镜像：

```bash
(curl -LfsS https://gh-proxy.com/https://raw.githubusercontent.com/guanxi660-crypto/mihomo-lite/main/mihomo-lite.sh -o /usr/local/bin/mh || wget -q https://gh-proxy.com/https://raw.githubusercontent.com/guanxi660-crypto/mihomo-lite/main/mihomo-lite.sh -O /usr/local/bin/mh) && chmod +x /usr/local/bin/mh && mh
```

安装后随时以 root 运行 `mh` 进入管理菜单；脚本自身的更新用菜单 **【12 更新脚本】**，更新完成后会自动 `exec` 重载新版本（菜单标题的版本号立刻变，不用退出重进）。核心下载失败时可用 `GH_PROXY=镜像前缀 mh` 重试（如 `GH_PROXY=https://ghfast.top/ mh`）。

## 支持协议（mihomo listeners 服务端入站，字段已按官方 wiki 核实）

| 协议 | 说明 |
|---|---|
| **VLESS + XHTTP + Reality** ⭐ | 推荐首选：XHTTP 把流量拆成标准 HTTP 请求序列，抗主动探测强、可套 CDN，内置随机 padding；Reality 负责 TLS 层伪装（此传输层不使用 Vision） |
| VLESS + TCP + Reality + Vision | 可选 VLESS Encryption（后量子加密），Reality 密钥对由核心生成；裸 TCP 场景延迟最低 |
| Hysteria2 | Salamander 混淆 + masquerade 伪装 |
| TUIC v5 | QUIC / 0-RTT / BBR |
| AnyTLS | TLS 流量填充 |
| Mieru | TCP/UDP 自研加密（无通用分享链接，输出 clash.yaml） |
| Shadowsocks 2022 | blake3 三种加密，严格长度密钥校验 |
| Trojan + Reality | 无需证书 |
| VLESS / VMess + WS + Argo | 临时隧道（自动探测域名）或固定隧道（Token） |

## 功能

- 中文交互菜单：添加 / 删除 / **修改**节点、查看链接、重启 / 停止、状态、日志、卸载（Argo 节点不在节点修改列表里，统一走 **Argo 管理 → 3 修改**）
- 8 种协议：XHTTP+Reality（首选）/ Reality+Vision / Hysteria2 / TUIC v5 / AnyTLS / Mieru / SS2022 / Trojan-Reality
- 节点默认命名「地区.运营商.协议」（点分隔、不带端口），可自定义覆盖；重名自动追加 `.2`/`.3`（客户端 proxies 不允许同名）
- 修改节点时 Mieru 可在 **TCP / UDP** 之间在线切换，改完自动重建配置并重启
- 对外端口默认随机空闲端口（避免撞车），Argo 回源端口默认 8888（仅监听 127.0.0.1，可在 Argo 管理里改）
- 节点可选对外 **IPv4 / IPv6**：双栈机器添加时选择、单栈机器自动采用，纯 IPv6 机器自动以 `::` 监听（Argo 节点例外：对外走 Cloudflare 域名，添加时问的是 cloudflared 传输协议）
- 按 CPU 能力选择内核（x86-64-v3 优化版 / compatible 兼容版），老 CPU 可正常运行
- 复用本机已有 cloudflared，不覆盖、不破坏原有 Cloudflare 部署
- 分享链接输出（`/etc/mihomo-lite/sub/links.txt`，Argo 节点另存 `sub/argo.txt`）+ Clash/Mihomo 客户端配置（`sub/clash.yaml`）
- 支持 systemd / OpenRC / 无 init 直跑三种模式
- 重启前 `mihomo -t` 配置校验 + 启动后存活兜底检查
- SS2022 严格长度密钥校验（避免运行期 `decode psk` 错误）

## 节点命名

默认名 = **地区.运营商.协议[.传输][.安全]**，分隔符统一用 `.`，**不带端口**（端口唯一性交给重名去重处理）。回车即用默认值，手输覆盖。

| 协议 | 默认名示例 |
|---|---|
| Hysteria2 | `SG.Dromatics.Hy2` |
| TUIC v5 | `SG.Dromatics.Tuic` |
| VLESS + TCP + Reality | `SG.Dromatics.Reality` |
| Trojan + Reality | `SG.Dromatics.Trojan.Reality` |
| VLESS + XHTTP + Reality | `SG.Dromatics.Vless.xhttp.reality` |
| AnyTLS | `SG.Dromatics.AnyTls` |
| Mieru | `SG.Dromatics.Mieru` |
| Shadowsocks 2022 | `SG.Dromatics.SS2022` |
| Argo + VLESS/WS | `SG.Dromatics.Argo` |
| Argo + VMess/WS | `SG.Dromatics.Argo` |

规则细节：

- 只有简称的协议（Hy2 / Tuic / Reality）只保留简称，首字母大写，不追加传输与安全段
- Argo 节点只留 `Argo` 一段，不追加协议/传输/安全（VLESS 还是 VMess 看节点本身，名字里不重复）
- 运营商名按**空格截断**，只取第一个词：`Dromatics System` → `Dromatics`
- 重名自动追加 `.2`、`.3`；旧版 `地区-运营商-协议-端口` 形式的历史节点会在启动时一次性迁移为点分风格，手改过的自定义名原样保留

## SNI 伪装域名

添加 TLS 类节点（Hysteria2 / TUIC / AnyTLS / Reality / XHTTP）时，默认从随机池四选一：

```
aws.amazon.com  www.amd.com  www.amazon.com  www.microsoft.com
```

回车即用随机值，也可手动输入覆盖。需要锁定单一值时用环境变量（跳过随机）：

```bash
SNI_DEFAULT=aws.amazon.com bash mihomo-lite.sh
```

自签证书的 CN 跟随所选 SNI，Reality 的 `dest` 也直接取该域名 `:443`。

## Argo 隧道

添加 Argo 节点时会问 cloudflared 的传输协议（不再问本机对外 IP 版本——Argo 对外只走 Cloudflare 域名，问 IP 没有意义）：

```
Argo 传输协议: 1) http2 (TCP, 默认最稳)  2) quic (UDP, 家宽/弱网常更顺)
选择 [当前 http2]:
```

选择结果写入 `metadata.json` 的 `argo.protocol`，`run-argo.sh` **先跑选定的协议**；20 秒内退出（常见：机房封 UDP 7844，quic 直接连不上）会自动换另一条协议并在日志里写明，不会一声不响地躺着。要严格只用选定协议：`ARGO_NO_FALLBACK=1`。

### 固定隧道（Token）

- 粘贴时会自动清洗 `\r`、首尾空格与引号，也接受整条命令（`cloudflared service install <token>`、`--token <token>`），只取最后一个字段
- 添加后脚本会等日志出现 `Registered tunnel connection` 才算通；进程在跑但没连上，会直接把最近日志和命中原因打出来（token 错误 / 网络超时）
- 面板侧必须配 Public Hostname：Type=HTTP，URL=`127.0.0.1:回源端口`，否则隧道通了也是 502

环境变量仍可覆盖默认值（影响的是"当前默认值"，交互里手动选仍然优先）：

```bash
ARGO_PROTOCOL=quic bash mihomo-lite.sh     # 默认 QUIC
ARGO_PROTOCOL=http2 bash mihomo-lite.sh    # 默认 http2
```

老配置（`metadata.json` 里没有 `argo.protocol` 字段）保持原行为：先 http2，20 秒内退出自动换 quic 重试。

### 修改 Argo 配置（Argo 管理 → 3）

Argo 节点和隧道是一体的，所以端口/域名这类字段**不在「节点修改」列表里**（那里只列独立协议节点），统一在这里改：

| 可改项 | 说明 |
|---|---|
| 回源监听端口 | WS 监听端口（仅 127.0.0.1）。改完同步更新节点 tag 与 `run-argo.sh`，隧道指向随之切换。固定隧道需要你在 CF 面板把 Public Hostname 的 URL 改成 `127.0.0.1:新端口`；临时隧道会重新分配域名 |
| 隧道域名 | 固定隧道填 Public Hostname；临时隧道留空即可（启动后自动探测回填） |
| 连接 CF 边缘的 IP 版本 | `1) 仅 IPv4` / `2) 仅 IPv6` / `3) auto`，落到 `cloudflared --edge-ip-version`；写入 `argo.edge_ip`，重启沿用。这台机器 IPv6 到 CF 不通、或想固定走 v4 时用这个 |

改完自动重写 `run-argo.sh`、重建配置并重启；临时隧道会等新域名探测出来再刷新链接。

### 查看 Argo 隧道（Argo 管理 → 4）

Argo 节点不在「节点修改」列表里，也常常在「查看节点链接」里被忽略——所以单独给了一个入口：

- 隧道信息：模式 / 回源端口 / 域名 / 传输协议 / 边缘 IP / cloudflared 运行状态
- 节点列表：每个 WS 节点的协议、回源地址、绑定的域名
- Argo 节点链接：同时落盘到 `sub/argo.txt`（`links.txt` 里也保留全量）

固定隧道添加时会把 Public Hostname 写进节点的 `argo_domain`；旧数据缺这个字段时，链接生成会自动回退用隧道全局域名，不会再出现「节点在、链接不在」。

节点命名与其它协议同一套规则：**地区.运营商.协议**，用 `.` 分隔、不带端口，Argo 节点只留 `Argo` 一段。例如 `SG.Dromatics.Argo`。分享链接里不再加 `arg-` 前缀。要改名走【Argo 管理 → 3 修改】。

## 关于订阅

本项目**不提供订阅生成链接**（不在节点机上开放 HTTP 订阅端口）：NAT/受限机器端口宝贵，多开一个明文 HTTP 端口既占资源又容易被扫描器探测到订阅内容、泄露节点信息。如需生成订阅链接、在线管理节点，请移步 [SubPilot](https://github.com/guanxi660-crypto/SubPilot)。

## 免责声明

仅供学习了解，非盈利目的。使用本程序须遵守部署服务器所在地及所在国家法律法规，作者不对任何不当行为负责。
