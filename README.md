# mihomo-lite

> 版本：v1.1.0
>
> **⚠️ 测试阶段（BETA）**：本项目当前处于测试阶段，功能与配置格式可能随时调整，请勿在生产环境使用。

mihomo 内核多协议服务端一键管理脚本，交互风格参考 [singbox-lite](https://github.com/0xdabiaoge/singbox-lite)。

## 支持协议（mihomo listeners 服务端入站，字段已按官方 wiki 核实）

| 协议 | 说明 |
|---|---|
| VLESS + TCP + Reality + Vision | 可选 VLESS Encryption（后量子加密），Reality 密钥对由核心生成 |
| Hysteria2 | Salamander 混淆 + masquerade 伪装 |
| TUIC v5 | QUIC / 0-RTT / BBR |
| AnyTLS | TLS 流量填充 |
| Mieru | TCP/UDP 自研加密（无通用分享链接，输出 clash.yaml） |
| Shadowsocks 2022 | blake3 三种加密，严格长度密钥校验 |
| Trojan + Reality | 无需证书 |
| VLESS / VMess + WS + Argo | 临时隧道（自动探测域名）或固定隧道（Token） |

## Argo 隧道

cloudflared 使用 `--protocol auto`：**优先 QUIC，连接失败自动回退 http2(TCP)**。
特殊环境下（如 UDP 被劫持导致 QUIC 静默失效）可用环境变量强制 TCP：

```bash
ARGO_PROTOCOL=http2 bash mihomo-lite.sh
```

## 安装

```bash
bash <(curl -Ls https://raw.githubusercontent.com/guanxi660-crypto/mihomo-lite/main/mihomo-lite.sh)
```

## 功能

- 中文交互菜单：添加/删除节点、查看链接、重启/停止、状态、日志、卸载
- 分享链接输出（`/etc/mihomo-lite/sub/links.txt`）+ Clash/Mihomo 客户端配置（`sub/clash.yaml`）
- 支持 systemd / OpenRC / 无 init 直跑三种模式
- 重启前 `mihomo -t` 配置校验 + 启动后存活兜底检查
- SS2022 严格长度密钥校验（避免运行期 `decode psk` 错误）

## 免责声明

仅供学习了解，非盈利目的。使用本程序须遵守部署服务器所在地及所在国家法律法规，作者不对任何不当行为负责。
