#!/bin/bash
#=============================================================================
# mihomo-lite —— mihomo 内核多协议服务端一键管理脚本
# 交互风格参考 singbox-lite (0xdabiaoge/singbox-lite)
# 节点能力（均基于 mihomo listeners 服务端入站，字段已按 mihomo 官方 wiki 核实）：
#   1. VLESS + TCP + Reality + Vision (可选 VLESS Encryption 后量子加密)
#   2. Hysteria2 (Salamander 混淆)
#   3. TUIC v5
#   4. AnyTLS
#   5. Mieru
#   6. Shadowsocks 2022
#   7. Trojan + Reality
#   8. VLESS/VMess + WS + Argo 隧道（添加时选 cloudflared 协议: http2/TCP 或 quic/UDP）
# 支持: Debian/Ubuntu(systemd) / Alpine(OpenRC) / 无 init 直跑模式
# 需 root 权限运行
#=============================================================================
umask 077
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}"

SCRIPT_VERSION="1.5.23"
MIHOMO_DIR="/etc/mihomo-lite"
MIHOMO_BIN="/usr/local/bin/mihomo"
CLOUDFLARED_BIN="/usr/local/bin/cloudflared"
CONFIG_FILE="${MIHOMO_DIR}/config.yaml"
METADATA_FILE="${MIHOMO_DIR}/metadata.json"
CERTS_DIR="${MIHOMO_DIR}/certs"
SUB_DIR="${MIHOMO_DIR}/sub"
ARGO_LOG="/var/log/mihomo-argo.log"
CORE_LOG="/var/log/mihomo-core.log"
SERVICE_NAME="mihomo-lite"
ARGO_SERVICE_NAME="mihomo-argo"
GITHUB_RAW_URL="https://raw.githubusercontent.com/guanxi660-crypto/mihomo-lite/main/mihomo-lite.sh"
SELF_SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"
# SNI 随机池(默认四选一); 想锁定单一值用环境变量 SNI_DEFAULT=xxx mh
DEFAULT_SNI_LIST="aws.amazon.com www.amd.com www.amazon.com www.microsoft.com"

# ---------------- 基础输出 ----------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'
_info()    { echo -e "${CYAN}[信息] $1${NC}"; }
_success() { echo -e "${GREEN}[成功] $1${NC}"; }
_warn()    { echo -e "${YELLOW}[注意] $1${NC}"; }
_error()   { echo -e "${RED}[错误] $1${NC}" >&2; }

_check_root() {
  [[ $EUID -ne 0 ]] && { _error "此脚本必须以 root 权限运行。"; exit 1; }
}

# ---------------- 依赖 ----------------
_install_dependencies() {
  # 必要组件清单: 命令 → 包名(Debian/Alpine 通用, 差异处单独处理)
  # curl/jq/openssl 基础三件套; ss(iproute2) 端口检测; pgrep(procps) 进程检测;
  # timeout/tee/seq/base64/shuf/readlink(coreutils); bash 为脚本本体运行环境
  local missing="" c
  for c in curl jq openssl ss ip pgrep shuf readlink bash timeout tee; do
    command -v "$c" >/dev/null 2>&1 || missing="$missing $c"
  done
  # ca-certificates 无命令可查，检测证书目录
  [ -d /etc/ssl/certs ] || missing="$missing ca-certificates"
  [ -z "$missing" ] && return 0
  _info "检测到缺少必要组件:$missing，正在安装..."
  if command -v apt >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1
    apt-get install -y --no-install-recommends curl jq openssl iproute2 procps coreutils bash ca-certificates >/dev/null 2>&1
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache curl jq openssl iproute2 procps coreutils bash ca-certificates 2>/dev/null || apk add --no-cache curl jq openssl
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl jq openssl iproute2 procps coreutils bash ca-certificates >/dev/null 2>&1
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl jq openssl iproute2 procps coreutils bash ca-certificates >/dev/null 2>&1
  else
    _error "无法识别的包管理器，请手动安装:$missing"; return 1
  fi
  # 安装后逐一复核，缺一样就拒绝继续，避免半残环境跑出难排查的问题
  missing=""
  for c in curl jq openssl ss ip pgrep shuf readlink bash timeout tee; do
    command -v "$c" >/dev/null 2>&1 || missing="$missing $c"
  done
  if [ -n "$missing" ]; then
    _error "组件安装后仍缺失:$missing，请手动安装后重试。"
    return 1
  fi
  _success "必要组件就绪。"
}

# ---------------- 工具函数 ----------------
_gen_uuid()    { cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16 | sed 's/\(.\{8\}\)\(.\{4\}\)\(.\{4\}\)\(.\{4\}\)/\1-\2-\3-\4-/'; }
_gen_hex()     { openssl rand -hex "$1" 2>/dev/null; }
_url_encode()  { printf '%s' "$1" | jq -sRr @uri; }
_b64_nopad()   { printf '%s' "$1" | base64 | tr -d '\n\r' | sed 's/=//g'; }

_get_ip4() {
  local ip
  ip=$(timeout 5 curl -4fsS --max-time 4 https://icanhazip.com 2>/dev/null || timeout 5 curl -4fsS --max-time 4 https://ipinfo.io/ip 2>/dev/null)
  printf '%s' "${ip//[$'\r\n ']/}"
}

_get_ip6() {
  local ip
  ip=$(timeout 5 curl -6fsS --max-time 4 https://icanhazip.com 2>/dev/null || timeout 5 curl -6fsS --max-time 4 https://ipinfo.io/ip 2>/dev/null)
  printf '%s' "${ip//[$'\r\n ']/}"
}

_get_public_ip() {
  local ip
  ip=$(_get_ip4)
  [ -z "$ip" ] && ip=$(_get_ip6)
  printf '%s' "$ip"
}

# 按节点记录的 ip_ver 解析用于链接的地址; 双栈缺失时自动回退另一栈
_resolve_node_ip() {
  local ver="$1" v4 v6
  case "$ver" in
    v6)
      v6=$(_get_ip6); [ -n "$v6" ] && { printf '%s' "$v6"; return; }
      _warn "该节点指定 IPv6，但当前未探测到可用 IPv6 地址，已回退 IPv4。" >&2
      _get_ip4
      ;;
    *)
      v4=$(_get_ip4); [ -n "$v4" ] && { printf '%s' "$v4"; return; }
      _get_ip6
      ;;
  esac
}

# listener 监听地址: 有全局 IPv4 用 0.0.0.0(兼容所有环境), 纯 IPv6 机器必须用 ::
# (0.0.0.0 只绑 IPv4, IPv6-only 机器上节点将完全连不上)
_listen_addr() {
  if ip -4 addr show scope global 2>/dev/null | grep -q "inet "; then
    echo "0.0.0.0"
  else
    echo "::"
  fi
}

# 询问对外 IP 版本; 只有单栈时静默采用, 结果存 IP_VER
_ask_ip_ver() {
  local v4 v6 iv
  v4=$(_get_ip4); v6=$(_get_ip6)
  if [ -n "$v4" ] && [ -n "$v6" ]; then
    echo "本机双栈可用: IPv4=${v4}  IPv6=${v6}"
    read -rp "对外 IP 版本 (4/6) [4]: " iv || iv=""
    iv=$(printf '%s' "${iv%$'\r'}" | tr -d '[:space:]')
    case "$iv" in
      6|v6|V6) IP_VER="v6" ;;
      4|v4|V4|"") IP_VER="v4" ;;
      *) _warn "输入 '${iv}' 无法识别，按 IPv4 处理。"; IP_VER="v4" ;;
    esac
  elif [ -n "$v6" ]; then
    IP_VER="v6"; _info "检测到仅 IPv6，节点使用 IPv6 地址。"
  else
    IP_VER="v4"
  fi
  _info "对外 IP 版本: ${IP_VER}"
}

# Argo 传输协议选择: 结果存 ARGO_PROTO_RESULT (http2|quic)
# Argo 节点对外只走 Cloudflare 域名, 与"本机对外 IP 版本"无关, 所以这里问协议而不是 IP
_ask_argo_protocol() {
  local cur t
  cur="${ARGO_PROTOCOL:-}"
  [ -z "$cur" ] && cur=$(jq -r '.argo.protocol // ""' "$METADATA_FILE" 2>/dev/null)
  [ "$cur" = "quic" ] || cur="http2"
  echo "Argo 传输协议: 1) http2 (TCP, 默认最稳)  2) quic (UDP, 家宽/弱网常更顺)"
  read -rp "选择 [当前 ${cur}]: " t || t=""
  t=$(printf '%s' "${t%$'\r'}" | tr -d '[:space:]' | tr 'a-z' 'A-Z')
  case "$t" in
    1|HTTP2|H2) ARGO_PROTO_RESULT="http2" ;;
    2|QUIC)     ARGO_PROTO_RESULT="quic" ;;
    "")         ARGO_PROTO_RESULT="$cur" ;;
    *)          _warn "输入 '${t}' 无法识别，保留 ${cur}。"; ARGO_PROTO_RESULT="$cur" ;;
  esac
  _info "Argo 传输协议: ${ARGO_PROTO_RESULT} (启动失败不再自动回退，需切换请重新添加)"
  if [ -n "${ARGO_PROTOCOL:-}" ] && [ "$ARGO_PROTO_RESULT" != "$ARGO_PROTOCOL" ]; then
    _warn "环境变量 ARGO_PROTOCOL=${ARGO_PROTOCOL} 优先级更高，实际启动仍按该值。"
  fi
}

_detect_init_system() {
  if [ -f /sbin/openrc-run ] || command -v rc-service >/dev/null 2>&1; then
    INIT_SYSTEM="openrc"
  elif command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    INIT_SYSTEM="systemd"
  else
    INIT_SYSTEM="direct"
  fi
}

# 默认节点名: 国家-运营商-协议 (ip-api.com 单次请求取两个字段, 结果缓存 24h, 失败退化为 XX-ISP)
_geo_node_name() {
  local proto_label="$1" cc="" isp="" ts now raw cut i
  now=$(date +%s)
  # 命中缓存就不打接口(免费额度 45 次/分钟, 双栈机器每次添加要问两轮)
  if [ -s "$METADATA_FILE" ]; then
    ts=$(jq -r '.geo.ts // 0' "$METADATA_FILE" 2>/dev/null)
    if [ -n "$ts" ] && [ "$ts" -gt 0 ] 2>/dev/null && [ $((now - ts)) -lt 86400 ]; then
      cc=$(jq -r '.geo.cc // ""' "$METADATA_FILE" 2>/dev/null)
      isp=$(jq -r '.geo.isp // ""' "$METADATA_FILE" 2>/dev/null)
    fi
  fi
  if [ -z "$cc" ] || [ -z "$isp" ]; then
    cc=""; isp=""
    # 一次请求拿两行: 第一行 countryCode, 第二行 isp; 失败重试一次
    for i in 1 2; do
      raw=$(timeout 6 curl -fsS "http://ip-api.com/line/?fields=countryCode,isp&lang=zh" 2>/dev/null | tr -d '\r')
      cc=$(printf '%s\n' "$raw" | sed -n '1p' | tr -d '[:space:]')
      isp=$(printf '%s\n' "$raw" | sed -n '2p')
      [ -n "$cc" ] && [ -n "$isp" ] && break
      cc=""; isp=""
    done
    # 取到才写缓存, 失败不落盘, 下次自动重试
    if [ -n "$cc" ] && [ -n "$isp" ] && [ -s "$METADATA_FILE" ]; then
      local tmp="${METADATA_FILE}.tmp"
      if jq --arg cc "$cc" --arg isp "$isp" --argjson ts "$now" '.geo = {cc:$cc, isp:$isp, ts:$ts}' "$METADATA_FILE" > "$tmp" 2>/dev/null && [ -s "$tmp" ]; then
        mv "$tmp" "$METADATA_FILE"
      else
        rm -f "$tmp"
      fi
    fi
  fi
  [ -z "$cc" ] && cc="XX"
  if [ -z "$isp" ]; then
    isp="ISP"
  else
    isp="${isp%%(*}"                                                   # 砍掉括号补充说明
    isp="${isp%% *}"                                                   # 空格后截断: 只保留第一个词, 否则点分结构会被空格打断
    isp=$(printf '%s' "$isp" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    # 按字符(非字节)截断到 16, 避免把中文运营商名切半产生非法 UTF-8
    cut=$(printf '%s' "$isp" | jq -Rr '.[0:16]' 2>/dev/null)
    [ -n "$cut" ] && isp="$cut"
    [ -z "$isp" ] && isp="ISP"
  fi
  echo "${cc}.${isp}.${proto_label}"
}

# 协议 → 默认名后缀(点分风格): 地区.运营商.<这里>
# 约定: 用 . 分隔, 不带端口; 隧道类带 Argo.协议.传输.安全; 只有简称的协议首字母大写(Hy2 / Tuic / Reality)
_proto_label() {
  case "$1" in
    vless-xhttp)    echo "Vless.xhttp.reality" ;;
    vless-reality)  echo "Reality" ;;
    hysteria2)      echo "Hy2" ;;
    tuic)           echo "Tuic" ;;
    anytls)         echo "AnyTls" ;;
    mieru)          echo "Mieru" ;;
    ss2022)         echo "SS2022" ;;
    trojan-reality) echo "Trojan.Reality" ;;
    vless-ws)       echo "Argo" ;;
    vmess-ws)       echo "Argo" ;;
    *)              echo "$1" ;;
  esac
}

# 名称清洗: 去 \r、首尾空白与成对包裹的引号 (添加/修改两条路径共用)
_normalize_name() {
  local s
  s=$(printf '%s' "$1" | tr -d '\r')
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  [[ ${#s} -ge 2 && "$s" == \"*\" ]] && s="${s:1:${#s}-2}"
  [[ ${#s} -ge 2 && "$s" == \'*\' ]] && s="${s:1:${#s}-2}"
  printf '%s' "$s"
}

# Token 清洗: 粘贴常带 \r/换行/首尾空格/引号, 甚至整条命令; 脏字符会让 cloudflared 直接退出
_clean_token() {
  local t
  t=$(printf '%s' "$1" | tr -d '\r\n')
  t="${t#"${t%%[![:space:]]*}"}"
  t="${t%"${t##*[![:space:]]}"}"
  [[ ${#t} -ge 2 && "$t" == \"*\" ]] && t="${t:1:${#t}-2}"
  [[ ${#t} -ge 2 && "$t" == \'*\' ]] && t="${t:1:${#t}-2}"
  # 整条命令粘贴时取最后一个字段: cloudflared ... --token XXX / cloudflared service install XXX
  case "$t" in
    *[[:space:]]*) t=$(printf '%s' "$t" | awk '{print $NF}') ;;
  esac
  t=$(printf '%s' "$t" | tr -d '[:space:]')
  printf '%s' "$t"
}

# 名称去重: 与已有节点重名时追加 -2/-3...; 结果写回 NODE_NAME
# (mihomo 客户端 proxies 不允许同名, 重复添加同协议会直接撞名)
_unique_node_name() {
  local base="$1" cand="$1" n=2
  if [ -s "$METADATA_FILE" ] && command -v jq >/dev/null 2>&1; then
    while jq -e --arg nm "$cand" 'any(.nodes[]?; .name == $nm)' "$METADATA_FILE" >/dev/null 2>&1; do
      cand="${base}.${n}"; n=$((n+1))
      [ "$n" -gt 99 ] && break
    done
  fi
  if [ "$cand" != "$base" ]; then
    _warn "名称 ${base} 已存在，改用 ${cand}。"
  fi
  NODE_NAME="$cand"
}

# 节点命名交互: 传默认名后缀(见 _proto_label), 结果存 NODE_NAME
# 注意: 输入被吞(空行/EOF/paste 带 \r)时不能静默用默认名, 这里会清洗并回显最终名称
_ask_node_name() {
  local def nm
  def=$(_geo_node_name "$1")
  read -rp "节点名称 [${def}]: " nm || nm=""
  nm=$(_normalize_name "$nm")
  if [ -n "$nm" ]; then
    NODE_NAME="$nm"
  else
    NODE_NAME="$def"
  fi
  _unique_node_name "$NODE_NAME"
  _info "节点名称: ${NODE_NAME}"
}

# mieru 专用: 端口方式 (单端口 / 端口段)
# mihomo 的 mieru listener 用 port: "a-b" 会给段内每个端口各开一个监听(实测验证),
# 内存约 12KB + 1 个 fd / 端口, 默认上限 1000 个, 可用 MAX_RANGE_PORTS 覆盖。
MAX_RANGE_PORTS="${MAX_RANGE_PORTS:-1000}"
_ask_port_range() {
  local mode p a b n i rp def_a def_b
  echo "端口方式: 1) 单端口（客户端固定用这个端口）  2) 端口段（客户端每条连接随机挑，抗封锁更强）"
  read -rp "选择 [1]: " mode || mode=""
  mode=$(printf '%s' "${mode%$'\r'}" | tr -d '[:space:]')
  if [ "$mode" != "2" ]; then
    _ask_port "Mieru 端口" rand || return 1
    ASK_RANGE_RESULT=""
    return 0
  fi
  for i in $(seq 1 50); do
    rp=$(shuf -i 20000-64000 -n 1 2>/dev/null || echo $(( (RANDOM % 44000) + 20000 )))
    if ! _check_port_conflict "$rp"; then def_a="$rp"; break; fi
  done
  [ -z "${def_a:-}" ] && def_a=20000
  def_b=$(( def_a + 999 )); [ "$def_b" -gt 65535 ] && def_b=65535
  read -rp "端口段 (格式 a-b) [${def_a}-${def_b}]: " p || p=""
  p=$(printf '%s' "${p%$'\r'}" | tr -d '[:space:]')
  [ -z "$p" ] && p="${def_a}-${def_b}"
  if ! [[ "$p" =~ ^([0-9]+)-([0-9]+)$ ]]; then
    _error "格式应为 a-b，例如 20000-20999。"
    return 1
  fi
  a="${BASH_REMATCH[1]}"; b="${BASH_REMATCH[2]}"
  { [ "$a" -ge 1 ] && [ "$b" -le 65535 ] && [ "$a" -lt "$b" ]; } || { _error "端口段无效 (需 1 <= a < b <= 65535)。"; return 1; }
  n=$(( b - a + 1 ))
  if [ "$n" -gt "$MAX_RANGE_PORTS" ]; then
    _error "范围 ${n} 个端口超过上限 ${MAX_RANGE_PORTS}（每端口一个监听，约 12KB 内存 + 1 个 fd）。"
    _info "确实需要就用 MAX_RANGE_PORTS=${n} 重新运行。"
    return 1
  fi
  _check_port_conflict "$a" && return 1
  _check_port_conflict "$b" && return 1
  _info "端口段: ${a}-${b}（共 ${n} 个，记得在防火墙/安全组整段放行对应传输层）"
  ASK_PORT_RESULT="$a"
  ASK_RANGE_RESULT="${a}-${b}"
}

_check_port_conflict() {
  local port="$1"
  [[ ! "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ] && { _error "端口 ${port} 无效 (1-65535)。"; return 0; }
  if command -v ss >/dev/null 2>&1; then
    ss -lntu 2>/dev/null | awk '{print $5}' | grep -qE "[:.]${port}$" && { _error "端口 ${port} 已被系统占用。"; return 0; }
  fi
  if [ -s "$METADATA_FILE" ]; then
    jq -e --argjson p "$port" '.nodes[]? | select(.port == $p)' "$METADATA_FILE" >/dev/null 2>&1 && { _error "端口 ${port} 已被脚本节点占用。"; return 0; }
  fi
  return 1
}

# 随机选取一个默认 SNI: 默认从池子里随机; SNI_DEFAULT 环境变量优先(锁单一值)
_pick_sni() {
  [ -n "${SNI_DEFAULT:-}" ] && { echo "$SNI_DEFAULT"; return; }
  echo "$DEFAULT_SNI_LIST" | tr ' ' '\n' | sed '/^$/d' | shuf -n1 2>/dev/null || echo "aws.amazon.com"
}

# 自签证书 (用于 hy2/tuic/anytls 等需要 TLS 证书的协议)
_gen_selfsigned_cert() {
  local sni="$1" tag="$2"
  mkdir -p "$CERTS_DIR"
  local crt="${CERTS_DIR}/${tag}.crt" key="${CERTS_DIR}/${tag}.key"
  openssl req -new -newkey ec:<(openssl ecparam -name prime256v1) -x509 -sha256 -days 3650 \
    -nodes -subj "/CN=${sni}" -keyout "$key" -out "$crt" >/dev/null 2>&1
  [ -s "$crt" ] && [ -s "$key" ] || { _error "自签证书生成失败。"; return 1; }
  echo "${crt}|${key}"
}

# 一次性迁移: 旧命名(CC-ISP-协议[-端口] 或 …-Argo-vless-ws) → 点分风格 CC.ISP.协议[.传输][.tls]
# 只迁移命中旧自动命名模式的节点, 手改过的自定义名原样保留
_migrate_node_names() {
  [ -s "$METADATA_FILE" ] || return 0
  local n
  n=$(jq -r '[.nodes[]? | select((.name // "") | test("-HY2$|-TUIC$|-AnyTLS$|-Mieru$|-SS2022$|-VLESS-XHTTP$|-VLESS-Reality$|-Trojan-Reality$|-Argo-vless-ws$|-Argo-vmess-ws$|-Argo-VLESS-WS$|-Argo-VMESS-WS$|\\.Argo\\.Vless\\.ws\\.tls$|\\.Argo\\.Vmess\\.ws\\.tls$|-[A-Za-z0-9.]+-[0-9]+$| "))] | length' "$METADATA_FILE" 2>/dev/null)
  [ "${n:-0}" -gt 0 ] 2>/dev/null || return 0
  local tmp="${METADATA_FILE}.tmp"
  if jq '
      def fix_isp:
        split(".") as $p
        | if (($p | length) >= 2) and ((($p[1] // "") | test(" ")))
          then ($p[0] + "." + ((($p[1] | split(" "))[0]))
                + (if ($p | length) > 2 then "." + ($p[2:] | join(".")) else "" end))
          else . end;
      def newname:
        (sub("-[0-9]+$"; "")) as $base
        | ($base
            | sub("-Argo-vless-ws$"; ".Argo")
            | sub("-Argo-vmess-ws$"; ".Argo")
            | sub("-Argo-VLESS-WS$"; ".Argo")
            | sub("-Argo-VMESS-WS$"; ".Argo")
            | sub("\\.Argo\\.Vless\\.ws\\.tls$"; ".Argo")
            | sub("\\.Argo\\.Vmess\\.ws\\.tls$"; ".Argo")
            | sub("-VLESS-XHTTP$"; ".Vless.xhttp.reality")
            | sub("-VLESS-Reality$"; ".Reality")
            | sub("-Trojan-Reality$"; ".Trojan.Reality")
            | sub("-HY2$"; ".Hy2")
            | sub("-TUIC$"; ".Tuic")
            | sub("-AnyTLS$"; ".AnyTls")
            | sub("-Mieru$"; ".Mieru")
            | sub("-SS2022$"; ".SS2022")) as $conv
        | if $conv == $base
          then (if test("\\.(Hy2|Tuic|Reality|AnyTls|Mieru|SS2022|Argo|Trojan\\.Reality|Vless\\.xhttp\\.reality)$") then fix_isp else . end)
          else (($conv | sub("^(?<cc>[A-Za-z]{2})-"; "\(.cc).")) | fix_isp)
          end;
      .nodes |= (reduce .[] as $n ({seen:{}, out:[]};
          ($n.name // "") as $raw
          | (if $raw == "" then "" else ($raw | newname) end) as $nm
          | if $nm == "" then .out += [$n]
            else
              (.seen[$nm] // 0) as $c
              | (if $c == 0 then $nm else "\($nm).\($c + 1)" end) as $final
              | .seen[$nm] = ($c + 1)
              | .out += [$n + {name: $final}]
            end) | .out)' "$METADATA_FILE" > "$tmp" && [ -s "$tmp" ]; then
    mv "$tmp" "$METADATA_FILE"
    _info "节点名已迁移为点分风格(地区.运营商.协议)，共 ${n} 个。"
  else
    rm -f "$tmp"
  fi
}

# ---------------- 元数据初始化 ----------------
_init_metadata() {
  mkdir -p "$MIHOMO_DIR" "$SUB_DIR" "$CERTS_DIR"
  chmod 700 "$MIHOMO_DIR" 2>/dev/null
  if [ ! -s "$METADATA_FILE" ]; then
    cat > "$METADATA_FILE" <<EOF
{"uuid":"$(_gen_uuid)","nodes":[],"argo":{"enabled":false}}
EOF
  fi
}

# 追加一个节点到 metadata
_add_node_meta() {
  local json="$1"
  local tmp="${METADATA_FILE}.tmp"
  jq --argjson node "$json" '.nodes += [$node]' "$METADATA_FILE" > "$tmp" && mv "$tmp" "$METADATA_FILE"
}

# 按 tag 删除节点
_del_node_meta() {
  local tag="$1"
  local tmp="${METADATA_FILE}.tmp"
  jq --arg t "$tag" '.nodes |= map(select(.tag != $t))' "$METADATA_FILE" > "$tmp" && mv "$tmp" "$METADATA_FILE"
}

# ---------------- 配置生成 ----------------
# 从 metadata.json 重建 config.yaml（listeners 块）与客户端订阅
_regen_config() {
  local up
  up=$(jq -r '.argo.enabled // false' "$METADATA_FILE")
  LISTEN_ADDR=$(_listen_addr)
  {
    echo "# 由 mihomo-lite 自动生成，请勿手动编辑"
    echo "mixed-port: 7890"
    echo "allow-lan: false"
    echo "mode: rule"
    echo "log-level: warning"
    echo "ipv6: true"
    echo "listeners:"
    jq -c '.nodes[]?' "$METADATA_FILE" | while IFS= read -r n; do
      _emit_listener "$n"
    done
  } > "$CONFIG_FILE"
  _build_links
  chmod 600 "$CONFIG_FILE" 2>/dev/null
}

# 生成单个服务端 listener（输入: 节点 JSON）
_emit_listener() {
  local n="$1"
  local tag proto port
  tag=$(jq -r '.tag' <<<"$n"); proto=$(jq -r '.proto' <<<"$n"); port=$(jq -r '.port' <<<"$n")
  case "$proto" in
    vless-xhttp)
      local xuuid xpk xsid xsni xpath xmode
      xuuid=$(jq -r '.uuid' <<<"$n"); xpk=$(jq -r '.private_key' <<<"$n")
      xsid=$(jq -r '.short_id' <<<"$n"); xsni=$(jq -r '.sni' <<<"$n")
      xpath=$(jq -r '.ws_path // "/"' <<<"$n"); xmode=$(jq -r '.xhttp_mode // "auto"' <<<"$n")
      cat <<EOF
  - name: "${tag}"
    type: vless
    port: ${port}
    listen: ${LISTEN_ADDR}
    udp: true
    users:
      - username: "u1"
        uuid: "${xuuid}"
    xhttp-config:
      path: "${xpath}"
      mode: ${xmode}
      x-padding-bytes: "100-1000"
    reality-config:
      dest: "${xsni}:443"
      private-key: "${xpk}"
      short-id:
        - "${xsid}"
      server-names:
        - "${xsni}"
EOF
      ;;
    vless-reality)
      local uuid pk sid sni flow enc
      uuid=$(jq -r '.uuid' <<<"$n"); pk=$(jq -r '.private_key' <<<"$n")
      sid=$(jq -r '.short_id' <<<"$n"); sni=$(jq -r '.sni' <<<"$n")
      flow=$(jq -r '.flow // ""' <<<"$n"); enc=$(jq -r '.decryption // ""' <<<"$n")
      cat <<EOF
  - name: "${tag}"
    type: vless
    port: ${port}
    listen: ${LISTEN_ADDR}
    udp: true
    users:
      - username: "u1"
        uuid: "${uuid}"
$( [ -n "$flow" ] && echo "        flow: ${flow}" )
$( [ -n "$enc" ] && echo "        decryption: \"${enc}\"" )
    reality-config:
      dest: "${sni}:443"
      private-key: "${pk}"
      short-id:
        - "${sid}"
      server-names:
        - "${sni}"
EOF
      ;;
    vless-ws)
      local uuid path
      uuid=$(jq -r '.uuid' <<<"$n"); path=$(jq -r '.ws_path' <<<"$n")
      cat <<EOF
  - name: "${tag}"
    type: vless
    port: ${port}
    listen: 127.0.0.1
    udp: true
    users:
      - username: "u1"
        uuid: "${uuid}"
    ws-path: "${path}"
    allow-insecure: true
EOF
      ;;
    vmess-ws)
      local uuid path
      uuid=$(jq -r '.uuid' <<<"$n"); path=$(jq -r '.ws_path' <<<"$n")
      cat <<EOF
  - name: "${tag}"
    type: vmess
    port: ${port}
    listen: 127.0.0.1
    udp: true
    users:
      - username: "u1"
        uuid: "${uuid}"
        alterId: 0
    ws-path: "${path}"
    allow-insecure: true
EOF
      ;;
    hysteria2)
      local pass obfs obfspass crt key masq
      pass=$(jq -r '.password' <<<"$n"); obfs=$(jq -r '.obfs // ""' <<<"$n")
      obfspass=$(jq -r '.obfs_password // ""' <<<"$n")
      crt=$(jq -r '.cert' <<<"$n"); key=$(jq -r '.key' <<<"$n")
      masq=$(jq -r '.masquerade // ""' <<<"$n")
      cat <<EOF
  - name: "${tag}"
    type: hysteria2
    port: ${port}
    listen: ${LISTEN_ADDR}
    users:
      u1: "${pass}"
$( [ -n "$obfs" ] && printf '    obfs: %s\n    obfs-password: "%s"\n' "$obfs" "$obfspass" )
    certificate: "${crt}"
    private-key: "${key}"
    alpn:
      - h3
$( [ -n "$masq" ] && printf '    masquerade: "%s"\n' "$masq" )
EOF
      ;;
    tuic)
      local uuid pass crt key
      uuid=$(jq -r '.uuid' <<<"$n"); pass=$(jq -r '.password' <<<"$n")
      crt=$(jq -r '.cert' <<<"$n"); key=$(jq -r '.key' <<<"$n")
      cat <<EOF
  - name: "${tag}"
    type: tuic
    port: ${port}
    listen: ${LISTEN_ADDR}
    users:
      "${uuid}": "${pass}"
    certificate: "${crt}"
    private-key: "${key}"
    congestion-controller: bbr
    max-idle-time: 15000
    authentication-timeout: 1000
    alpn:
      - h3
    max-udp-relay-packet-size: 1500
EOF
      ;;
    anytls)
      local user pass crt key
      user=$(jq -r '.username' <<<"$n"); pass=$(jq -r '.password' <<<"$n")
      crt=$(jq -r '.cert' <<<"$n"); key=$(jq -r '.key' <<<"$n")
      cat <<EOF
  - name: "${tag}"
    type: anytls
    port: ${port}
    listen: ${LISTEN_ADDR}
    users:
      "${user}": "${pass}"
    certificate: "${crt}"
    private-key: "${key}"
EOF
      ;;
    mieru)
      local user pass transport port_field
      user=$(jq -r '.username' <<<"$n"); pass=$(jq -r '.password' <<<"$n")
      transport=$(jq -r '.transport // "TCP"' <<<"$n")
      # 端口段: mieru listener 支持 port: "a-b"，段内每端口各开一个监听
      port_field=$(jq -r '.port_range // empty' <<<"$n"); [ -z "$port_field" ] && port_field="$port"
      cat <<EOF
  - name: "${tag}"
    type: mieru
    port: "${port_field}"
    listen: ${LISTEN_ADDR}
    transport: ${transport}
    users:
      "${user}": "${pass}"
EOF
      ;;
    ss2022)
      local cipher pass
      cipher=$(jq -r '.cipher' <<<"$n"); pass=$(jq -r '.password' <<<"$n")
      cat <<EOF
  - name: "${tag}"
    type: shadowsocks
    port: ${port}
    listen: ${LISTEN_ADDR}
    cipher: ${cipher}
    password: "${pass}"
    udp: true
EOF
      ;;
    trojan-reality)
      local pass pk sid sni
      pass=$(jq -r '.password' <<<"$n"); pk=$(jq -r '.private_key' <<<"$n")
      sid=$(jq -r '.short_id' <<<"$n"); sni=$(jq -r '.sni' <<<"$n")
      cat <<EOF
  - name: "${tag}"
    type: trojan
    port: ${port}
    listen: ${LISTEN_ADDR}
    udp: true
    users:
      - username: "u1"
        password: "${pass}"
    reality-config:
      dest: "${sni}:443"
      private-key: "${pk}"
      short-id:
        - "${sid}"
      server-names:
        - "${sni}"
EOF
      ;;
  esac
}

# ---------------- 分享链接与客户端订阅 ----------------
_build_links() {
  local ip; ip=$(_get_public_ip)
  local links_file="${SUB_DIR}/links.txt" yaml_file="${SUB_DIR}/clash.yaml"
  local argo_file="${SUB_DIR}/argo.txt"
  : > "$links_file"; : > "$argo_file"
  {
    echo "# mihomo-lite 客户端配置（Clash/Mihomo 格式）自动生成"
    echo "# 若节点使用 IPv6 地址，客户端顶层需要 ipv6: true 才能连通"
    echo "ipv6: true"
    echo "proxies:"
  } > "$yaml_file"
  jq -c '.nodes[]?' "$METADATA_FILE" | while IFS= read -r n; do
    local tag proto port link=""
    tag=$(jq -r '.name // .tag' <<<"$n"); proto=$(jq -r '.proto' <<<"$n"); port=$(jq -r '.port' <<<"$n")
    local enc_name
    local ipv host="" ip=""
    case "$proto" in
      # Argo 节点对外走 Cloudflare 域名, 不解析本机 IP(省掉无谓的 IPv6 探测与告警)
      vless-ws|vmess-ws) ;;
      *)
        ipv=$(jq -r '.ip_ver // "v4"' <<<"$n")
        ip=$(_resolve_node_ip "$ipv")
        if [[ "$ip" == *:* ]]; then host="[$ip]"; else host="$ip"; fi
        ;;
    esac
    # 链接 fragment 必须是 percent-encoded 原文; 用 base64 客户端会把节点名显示成乱码
    enc_name=$(_url_encode "$tag")
    case "$proto" in
      vless-xhttp)
        local xuuid xpbk xsid xsni xpath xmode
        xuuid=$(jq -r '.uuid' <<<"$n"); xpbk=$(jq -r '.public_key' <<<"$n")
        xsid=$(jq -r '.short_id' <<<"$n"); xsni=$(jq -r '.sni' <<<"$n")
        xpath=$(jq -r '.ws_path // "/"' <<<"$n"); xmode=$(jq -r '.xhttp_mode // "auto"' <<<"$n")
        # XHTTP 与 Vision 互斥(flow 必须留空)，链接用 type=xhttp + mode 参数
        link="vless://${xuuid}@${host}:${port}?encryption=none&security=reality&sni=${xsni}&fp=chrome&pbk=${xpbk}&sid=${xsid}&type=xhttp&path=$(_url_encode "$xpath")&mode=${xmode}#${enc_name}"
        printf '  - name: "%s"
    type: vless
    server: "%s"
    port: %s
    uuid: %s
    udp: true
    tls: true
    servername: %s
    client-fingerprint: chrome
    network: xhttp
    xhttp-opts:
      path: "%s"
      mode: %s
    reality-opts:
      public-key: %s
      short-id: "%s"
' "$tag" "$ip" "$port" "$xuuid" "$xsni" "$xpath" "$xmode" "$xpbk" "$xsid" >> "$yaml_file"
        ;;
      vless-reality)
        local uuid pbk sid sni
        uuid=$(jq -r '.uuid' <<<"$n"); pbk=$(jq -r '.public_key' <<<"$n")
        sid=$(jq -r '.short_id' <<<"$n"); sni=$(jq -r '.sni' <<<"$n")
        link="vless://${uuid}@${host}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${pbk}&sid=${sid}&type=tcp#${enc_name}"
        {
          printf '  - name: "%s"\n    type: vless\n    server: "%s"\n    port: %s\n    uuid: %s\n    udp: true\n    tls: true\n    flow: xtls-rprx-vision\n    servername: %s\n    client-fingerprint: chrome\n    network: tcp\n    reality-opts:\n      public-key: %s\n      short-id: "%s"\n' "$tag" "$ip" "$port" "$uuid" "$sni" "$pbk" "$sid"
        } >> "$yaml_file"
        ;;
      vless-ws|vmess-ws)
        local uuid path domain ws_proto
        uuid=$(jq -r '.uuid' <<<"$n"); path=$(jq -r '.ws_path' <<<"$n")
        domain=$(jq -r '.argo_domain // ""' <<<"$n")
        # 兼容旧数据/固定隧道首次添加: 节点上没写 argo_domain 时回退到隧道全局域名
        [ -z "$domain" ] && domain=$(jq -r '.argo.domain // ""' "$METADATA_FILE" 2>/dev/null)
        [ -z "$domain" ] && continue
        if [ "$proto" = "vless-ws" ]; then
          # sni 显式写成隧道域名: CF 边缘的证书就是这个域, 有的客户端(旧 v2rayN/部分安卓内核)
          # 不会从 host 推导 TLS 的 server_name, 缺 sni 会握手失败或落到证书不匹配
          # fp 统一 uTLS chrome, 与 Reality 系列节点保持一致, 避免 JA3/JA4 一眼看出是裸 TLS 客户端
          link="vless://${uuid}@${domain}:443?encryption=none&security=tls&sni=${domain}&fp=chrome&host=${domain}&type=ws&path=$(_url_encode "$path")#${enc_name}"
          printf '  - name: "%s"\n    type: vless\n    server: "%s"\n    port: 443\n    uuid: %s\n    udp: true\n    tls: true\n    servername: %s\n    client-fingerprint: chrome\n    network: ws\n    ws-opts:\n      path: "%s"\n      headers:\n        Host: %s\n' "$tag" "$domain" "$uuid" "$domain" "$path" "$domain" >> "$yaml_file"
        else
          local vj
          vj=$(jq -cn --arg v "2" --arg u "$uuid" --arg d "$domain" --arg t "$tag" --arg p "$path" '{v:$v,ps:$t,add:$d,port:"443",id:$u,aid:"0",scy:"auto",net:"ws",type:"none",host:$d,path:$p,tls:"tls",sni:$d,fp:"chrome"}')
          link="vmess://$(_b64_nopad "$vj")"
          printf '  - name: "%s"\n    type: vmess\n    server: "%s"\n    port: 443\n    uuid: %s\n    alterId: 0\n    cipher: auto\n    udp: true\n    tls: true\n    servername: %s\n    client-fingerprint: chrome\n    network: ws\n    ws-opts:\n      path: "%s"\n      headers:\n        Host: %s\n' "$tag" "$domain" "$uuid" "$domain" "$path" "$domain" >> "$yaml_file"
        fi
        ;;
      hysteria2)
        local pass sni obfs obfp
        pass=$(jq -r '.password' <<<"$n"); sni=$(jq -r '.sni' <<<"$n")
        obfs=$(jq -r '.obfs // ""' <<<"$n"); obfp=$(jq -r '.obfs_password // ""' <<<"$n")
        link="hy2://${pass}@${host}:${port}?sni=${sni}&insecure=1"
        [ -n "$obfs" ] && link="${link}&obfs=salamander&obfs-password=${obfp}"
        link="${link}#${enc_name}"
        {
          printf '  - name: "%s"\n    type: hysteria2\n    server: "%s"\n    port: %s\n    password: %s\n    sni: %s\n    skip-cert-verify: true\n' "$tag" "$ip" "$port" "$pass" "$sni"
          [ -n "$obfs" ] && printf '    obfs: salamander\n    obfs-password: "%s"\n' "$obfp"
        } >> "$yaml_file"
        ;;
      tuic)
        local uuid pass sni
        uuid=$(jq -r '.uuid' <<<"$n"); pass=$(jq -r '.password' <<<"$n"); sni=$(jq -r '.sni' <<<"$n")
        link="tuic://${uuid}:${pass}@${host}:${port}?sni=${sni}&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#${enc_name}"
        printf '  - name: "%s"\n    type: tuic\n    server: "%s"\n    port: %s\n    uuid: %s\n    password: "%s"\n    sni: %s\n    skip-cert-verify: true\n    congestion-controller: bbr\n    alpn:\n      - h3\n    udp: true\n' "$tag" "$ip" "$port" "$uuid" "$pass" "$sni" >> "$yaml_file"
        ;;
      anytls)
        local user pass sni
        user=$(jq -r '.username' <<<"$n"); pass=$(jq -r '.password' <<<"$n"); sni=$(jq -r '.sni' <<<"$n")
        link="anytls://${user}:${pass}@${host}:${port}?sni=${sni}&fp=chrome&insecure=1#${enc_name}"
        printf '  - name: "%s"\n    type: anytls\n    server: "%s"\n    port: %s\n    username: \"%s\"\n    password: "%s"\n    sni: %s\n    client-fingerprint: chrome\n    skip-cert-verify: true\n' "$tag" "$ip" "$port" "$user" "$pass" "$sni" >> "$yaml_file"
        ;;
      mieru)
        local user pass transport
        user=$(jq -r '.username' <<<"$n"); pass=$(jq -r '.password' <<<"$n")
        transport=$(jq -r '.transport // "TCP"' <<<"$n" | tr 'a-z' 'A-Z')
        # mieru 暂无通用分享链接规范，仅输出客户端 Clash 配置
        # 端口段必须写 port-range（不可与 port 同时书写），单端口写 port
        local rng port_line
        rng=$(jq -r '.port_range // empty' <<<"$n")
        if [ -n "$rng" ]; then port_line="port-range: \"${rng}\""; else port_line="port: ${port}"; fi
        printf '  - name: "%s"\n    type: mieru\n    server: "%s"\n    %s\n    username: "%s"\n    password: "%s"\n    transport: %s\n' "$tag" "$ip" "$port_line" "$user" "$pass" "$transport" >> "$yaml_file"
        ;;
      ss2022)
        local cipher pass userinfo
        cipher=$(jq -r '.cipher' <<<"$n"); pass=$(jq -r '.password' <<<"$n")
        userinfo=$(_b64_nopad "${cipher}:${pass}")
        link="ss://${userinfo}@${host}:${port}#${enc_name}"
        printf '  - name: "%s"\n    type: ss\n    server: "%s"\n    port: %s\n    cipher: %s\n    password: "%s"\n    udp: true\n' "$tag" "$ip" "$port" "$cipher" "$pass" >> "$yaml_file"
        ;;
      trojan-reality)
        local pass pbk sid sni
        pass=$(jq -r '.password' <<<"$n"); pbk=$(jq -r '.public_key' <<<"$n")
        sid=$(jq -r '.short_id' <<<"$n"); sni=$(jq -r '.sni' <<<"$n")
        link="trojan://${pass}@${host}:${port}?security=reality&sni=${sni}&fp=chrome&pbk=${pbk}&sid=${sid}&type=tcp#${enc_name}"
        printf '  - name: "%s"\n    type: trojan\n    server: "%s"\n    port: %s\n    password: "%s"\n    udp: true\n    sni: %s\n    client-fingerprint: chrome\n    reality-opts:\n      public-key: %s\n      short-id: "%s"\n' "$tag" "$ip" "$port" "$pass" "$sni" "$pbk" "$sid" >> "$yaml_file"
        ;;
    esac
    [ -n "$link" ] && echo "$link" >> "$links_file"
    # Argo 节点单独存一份, 方便在【Argo 管理 → 4】里只看到隧道节点的链接
    case "$proto" in
      vless-ws|vmess-ws) [ -n "$link" ] && echo "$link" >> "$argo_file" ;;
    esac
  done
  chmod 600 "$links_file" "$yaml_file" 2>/dev/null
}

_show_links() {
  _build_links
  local v4 v6
  v4=$(_get_ip4); v6=$(_get_ip6)
  echo ""
  echo -e "${CYAN}================ 节点分享链接 (IPv4: ${v4:-无}  IPv6: ${v6:-无}) ================${NC}"
  if [ -s "${SUB_DIR}/links.txt" ]; then
    cat "${SUB_DIR}/links.txt"
  else
    _warn "暂无节点，请先添加。"
  fi
  echo -e "${CYAN}=============================================================${NC}"
  echo "分享链接文件: ${SUB_DIR}/links.txt"
  echo "Clash/Mihomo 客户端配置: ${SUB_DIR}/clash.yaml"
  # mieru 节点只有 yaml 配置，没有分享链接，做一次提示
  local has_mieru
  has_mieru=$(jq '[.nodes[]? | select(.proto == "mieru")] | length' "$METADATA_FILE" 2>/dev/null)
  [ "${has_mieru:-0}" -gt 0 ] 2>/dev/null && _warn "Mieru 节点无通用分享链接，请直接使用 clash.yaml 中的配置。"
  # Argo 节点没有隧道域名时不会生成链接, 明确说清原因, 否则看起来像"节点根本不存在"
  local ws_count ws_domain
  ws_count=$(jq '[.nodes[]? | select(.proto == "vless-ws" or .proto == "vmess-ws")] | length' "$METADATA_FILE" 2>/dev/null)
  if [ "${ws_count:-0}" -gt 0 ] 2>/dev/null; then
    ws_domain=$(jq -r '.argo.domain // ""' "$METADATA_FILE" 2>/dev/null)
    if [ -z "$ws_domain" ]; then
      _warn "Argo 节点因缺少隧道域名未生成链接，请到【2 Argo 管理 → 4】查看并补域名。"
    else
      _info "Argo 节点链接单独存放在 ${SUB_DIR}/argo.txt，也可在【2 Argo 管理 → 4】查看。"
    fi
  fi
}

# ---------------- 核心安装 ----------------
_detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l|armv7) echo "armv7" ;;
    *) _error "不支持的架构: $(uname -m)"; return 1 ;;
  esac
}

_fetch() { curl -LsSf --connect-timeout 15 --max-time 300 -o "$2" "$1"; }

# 带镜像回退的下载：直连失败或产物不是有效 gzip 时自动换镜像重试
# 可用环境变量 GH_PROXY 覆盖镜像前缀（默认 gh-proxy.com），如 GH_PROXY=https://ghfast.top/
_fetch_gh() {
  local url="$1" out="$2" mirror="${GH_PROXY:-https://gh-proxy.com/}"
  rm -f "$out"
  _fetch "$url" "$out" 2>/dev/null
  if gzip -t "$out" 2>/dev/null; then return 0; fi
  _warn "直连下载失败或产物损坏，尝试镜像: ${mirror}"
  rm -f "$out"
  _fetch "${mirror}${url}" "$out" 2>/dev/null
  gzip -t "$out" 2>/dev/null
}

# 确保 mihomo 核心已安装(任何"要写 listener"的操作前调用)
# 未安装时当场询问是否安装; 拒绝或安装失败返回非 0, 由调用方中止流程
_ensure_core() {
  [ -x "$MIHOMO_BIN" ] && return 0
  _warn "检测到 mihomo 核心未安装。"
  local ic
  read -rp "是否现在安装 mihomo 核心? [Y/n]: " ic || ic=""
  if [[ ! "$ic" =~ ^[Nn]$ ]]; then
    install_core || { _error "核心安装失败，请检查网络后重试。"; return 1; }
    return 0
  fi
  _error "未安装核心，无法生成监听配置；已取消本次操作。"
  return 1
}

install_core() {
  local arch; arch=$(_detect_arch) || return 1
  _info "获取 mihomo 最新版本号..."
  local tag
  tag=$(curl -fsSL --connect-timeout 15 "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest" | jq -r '.tag_name // empty')
  [ -z "$tag" ] && { _error "获取 mihomo 版本号失败，请检查网络。"; return 1; }
  local fname url
  # CPU 能力检测：mihomo 官方 amd64 资产分两档
  #   mihomo-linux-amd64-v3-{tag}.gz          → GOAMD64=v3，需要 AVX2/BMI2/FMA
  #   mihomo-linux-amd64-compatible-{tag}.gz  → 纯兼容版（老 QEMU/老虚拟机可跑）
  # 注意：默认的 mihomo-linux-amd64-{tag}.gz 新版已默认 GOAMD64=v3，老 CPU 执行会报
  # "v3 microarchitecture support" 错误，fallback 必须用 compatible 版
  if [ "$arch" = "amd64" ] && grep -qm1 avx2 /proc/cpuinfo 2>/dev/null \
     && grep -qm1 bmi2 /proc/cpuinfo 2>/dev/null && grep -qm1 fma /proc/cpuinfo 2>/dev/null; then
    fname="mihomo-linux-amd64-v3-${tag}.gz"
    _info "CPU 支持 x86-64-v3 (AVX2/BMI2/FMA)，使用 v3 优化内核。"
  else
    # compatible 资产只有 amd64 有（arm64/armv7 无此分档，用默认版即可）
    if [ "$arch" = "amd64" ]; then
      fname="mihomo-linux-amd64-compatible-${tag}.gz"
      _info "CPU 不支持 x86-64-v3，使用 compatible 兼容内核。"
    else
      fname="mihomo-linux-${arch}-${tag}.gz"
    fi
  fi
  url="https://github.com/MetaCubeX/mihomo/releases/download/${tag}/${fname}"
  _info "下载 mihomo ${tag} (${arch})..."
  local tmp="${MIHOMO_DIR}/mihomo.dl.gz"
  if ! _fetch_gh "$url" "$tmp"; then
    _error "mihomo 下载失败：直连与镜像均未获得有效压缩包（可能被墙或链路劫持）。"
    _info "可尝试: GH_PROXY=自定义镜像前缀 bash $0 重试。"
    rm -f "$tmp"
    return 1
  fi
  gzip -dc "$tmp" > "${MIHOMO_BIN}.new" && rm -f "$tmp"
  chmod +x "${MIHOMO_BIN}.new"
  # 校验二进制真实可执行且版本正确
  local ver
  ver=$("${MIHOMO_BIN}.new" -v 2>/dev/null | head -n1)
  [[ "$ver" == *"Mihomo"* ]] || { _error "核心版本校验失败: ${ver:-无输出}"; rm -f "${MIHOMO_BIN}.new"; return 1; }
  mv -f "${MIHOMO_BIN}.new" "$MIHOMO_BIN"
  _success "mihomo 核心已安装: ${ver}"
  # 不随核心安装 cloudflared：只在添加 Argo 节点且本机没有时才按需安装，
  # 避免干扰原机已有的 Cloudflare 部署。
  _create_services
  _restart_all
}

# cloudflared 二进制定位：优先复用本机已有的安装，绝不覆盖。
# 常见路径: /usr/local/bin (本脚本管理位) → PATH → /usr/bin (apt 等包管理器安装)
_cloudflared_bin() {
  local p
  for p in "$CLOUDFLARED_BIN" "$(command -v cloudflared 2>/dev/null)" /usr/bin/cloudflared /usr/local/bin/cloudflared; do
    [ -n "$p" ] && [ -x "$p" ] && { echo "$p"; return 0; }
  done
  return 1
}

install_cloudflared() {
  # 已有任何位置安装的 cloudflared 一律复用，避免破坏原机已有的 Cloudflare 部署
  local existing
  existing=$(_cloudflared_bin) && { _info "检测到本机已有 cloudflared (${existing})，直接复用，不重新下载。"; return 0; }
  local arch; arch=$(_detect_arch) || return 1
  # cloudflared 的 ARM 32 位资产名是 linux-arm（不是 armv7），需单独映射
  local cf_arch="$arch"
  [ "$arch" = "armv7" ] && cf_arch="arm"
  _info "下载 cloudflared (${arch})..."
  local url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${cf_arch}"
  local mirror="${GH_PROXY:-https://gh-proxy.com/}"
  rm -f "${CLOUDFLARED_BIN}.new"
  _fetch "$url" "${CLOUDFLARED_BIN}.new" 2>/dev/null
  # 完整性校验：ELF magic + 大于 10MB；失败换镜像重试
  if ! { head -c 4 "${CLOUDFLARED_BIN}.new" 2>/dev/null | grep -q ELF && [ "$(stat -c%s "${CLOUDFLARED_BIN}.new" 2>/dev/null || echo 0)" -gt 10485760 ]; }; then
    _warn "直连下载失败或产物损坏，尝试镜像: ${mirror}"
    rm -f "${CLOUDFLARED_BIN}.new"
    _fetch "${mirror}${url}" "${CLOUDFLARED_BIN}.new" 2>/dev/null
  fi
  if ! { head -c 4 "${CLOUDFLARED_BIN}.new" 2>/dev/null | grep -q ELF && [ "$(stat -c%s "${CLOUDFLARED_BIN}.new" 2>/dev/null || echo 0)" -gt 10485760 ]; }; then
    _error "cloudflared 下载失败：直连与镜像均未获得有效二进制。可尝试: GH_PROXY=自定义镜像前缀 bash $0 重试。"
    rm -f "${CLOUDFLARED_BIN}.new"
    return 1
  fi
  chmod +x "${CLOUDFLARED_BIN}.new"
  mv -f "${CLOUDFLARED_BIN}.new" "$CLOUDFLARED_BIN"
  _success "cloudflared 已安装。"
}

# ---------------- 服务管理 ----------------
_create_services() {
  if [ "$INIT_SYSTEM" = "systemd" ]; then
    cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=mihomo-lite core
After=network.target

[Service]
Type=simple
ExecStart=${MIHOMO_BIN} -d ${MIHOMO_DIR}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    cat > /etc/systemd/system/${ARGO_SERVICE_NAME}.service <<EOF
[Unit]
Description=mihomo-lite argo tunnel
After=network.target

[Service]
Type=simple
ExecStart=${MIHOMO_DIR}/run-argo.sh
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME} ${ARGO_SERVICE_NAME} >/dev/null 2>&1
  elif [ "$INIT_SYSTEM" = "openrc" ]; then
    cat > /etc/init.d/${SERVICE_NAME} <<EOF
#!/sbin/openrc-run
name="${SERVICE_NAME}"
command="${MIHOMO_BIN}"
command_args="-d ${MIHOMO_DIR}"
command_background="yes"
pidfile="/run/${SERVICE_NAME}.pid"
output_log="${CORE_LOG}"
error_log="${CORE_LOG}"
depend() { need net; }
EOF
    chmod +x /etc/init.d/${SERVICE_NAME}
    cat > /etc/init.d/${ARGO_SERVICE_NAME} <<EOF
#!/sbin/openrc-run
name="${ARGO_SERVICE_NAME}"
command="${MIHOMO_DIR}/run-argo.sh"
command_background="yes"
pidfile="/run/${ARGO_SERVICE_NAME}.pid"
output_log="${ARGO_LOG}"
error_log="${ARGO_LOG}"
depend() { need net; }
EOF
    chmod +x /etc/init.d/${ARGO_SERVICE_NAME}
  fi
}

# 直跑模式 / systemd 辅助启动脚本（固定隧道与临时隧道共用）
# 协议来源优先级: 环境变量 ARGO_PROTOCOL > metadata 里 .argo.protocol(添加时选的) > 默认 http2
# 选定协议先跑 20 秒, 退出则自动换另一条并记日志; ARGO_NO_FALLBACK=1 时只跑选定协议
# 连接 CF 边缘的 IP 版本: metadata 里 .argo.edge_ip (4 / 6 / auto)，auto 时不加参数由 cloudflared 自选
_write_argo_runner() {
  local mode="$1" token="$2" port="$3"
  local proto_meta primary other proto_list edge edge_flag=""
  proto_meta=$(jq -r '.argo.protocol // ""' "$METADATA_FILE" 2>/dev/null)
  primary="${ARGO_PROTOCOL:-$proto_meta}"
  case "$primary" in
    http2|quic) ;;
    *) primary="http2" ;;
  esac
  # 选定协议先上; 20 秒内退出说明这条路不通(常见: 机房封 UDP 7844, quic 直接失败),
  # 自动换另一条并在日志里写清楚。ARGO_NO_FALLBACK=1 时只跑选定协议。
  if [ "${ARGO_NO_FALLBACK:-0}" = "1" ]; then
    proto_list="$primary"
  else
    other="quic"; [ "$primary" = "quic" ] && other="http2"
    proto_list="$primary $other"
  fi
  edge=$(jq -r '.argo.edge_ip // "auto"' "$METADATA_FILE" 2>/dev/null)
  [ -n "${ARGO_EDGE_IP:-}" ] && edge="$ARGO_EDGE_IP"
  case "$edge" in
    4|6) edge_flag=" --edge-ip-version ${edge}" ;;
    *)   edge_flag="" ;;
  esac
  local cfbin token_q
  token_q=$(printf '%s' "$token" | sed "s/'/'\\\\''/g")   # 单引号转义, 防止 token 打断生成的脚本
  cfbin=$(_cloudflared_bin) || { _error "cloudflared 未安装。"; return 1; }
  if [ "$mode" = "token" ] && [ -z "$token" ]; then
    _error "固定隧道 token 为空, 无法启动。"
    return 1
  fi
  {
    echo "#!/bin/bash"
    echo "exec > >(tee -a '${ARGO_LOG}') 2>&1"
    echo "PROTO_LIST='${proto_list}'"
    echo "EDGE_FLAG='${edge_flag}'"
    echo "for p in \$PROTO_LIST; do"
    echo "  echo \"[argo] 启动 cloudflared, 协议: \$p, 边缘 IP: ${edge}\""
    if [ "$mode" = "token" ]; then
      # 固定隧道必须走 run 子命令: cloudflared tunnel 本身没有 --token 这个 flag,
      # 直接 tunnel --token 会被当成非法参数、只打印帮助就退出(日志里就是一大段 --help)。
      # 而临时隧道的 --url 是 tunnel 命令自带的简写, 所以临时能起、固定起不来。
      echo "  ${cfbin} tunnel --no-autoupdate run --protocol \"\$p\" \$EDGE_FLAG --token '${token_q}' &"
    else
      echo "  ${cfbin} tunnel --no-autoupdate --protocol \"\$p\"\$EDGE_FLAG --url http://127.0.0.1:${port} &"
    fi
    echo "  pid=\$!"
    echo "  sleep 20"
    echo "  if kill -0 \$pid 2>/dev/null; then"
    echo "    wait \$pid; exit \$?"
    echo "  fi"
    echo "  echo \"[argo] 协议 \$p 在 20 秒内退出, 切换下一个协议重试\""
    echo "  wait \$pid 2>/dev/null"
    echo "done"
    echo "echo '[argo] 所有协议均启动失败'"
    echo "exit 1"
  } > "${MIHOMO_DIR}/run-argo.sh"
  chmod 700 "${MIHOMO_DIR}/run-argo.sh"
}

# Argo 启动校验: cloudflared 起不来时把日志尾巴直接打出来, 别只留一句"没起来"
_argo_fail_hint() {
  local port="${1:-}"
  echo "    排查:"
  echo "      1) 完整日志: ${ARGO_LOG}；systemctl status ${ARGO_SERVICE_NAME} --no-pager -l"
  echo "      2) quic=UDP/7844, http2=TCP/7844 —— 机房封 UDP 就选 http2"
  echo "      3) 面板 Public Hostname: Type=HTTP, URL=127.0.0.1:${port:-回源端口}"
  if grep -qiE 'invalid tunnel secret|failed to (parse|decode) token|unauthorized|tunnel not found' "$ARGO_LOG" 2>/dev/null; then
    echo "      → 命中 token 错误: 回面板重新复制 token, 粘贴时不要带空格/换行/引号"
  fi
  if grep -qiE 'show help|^NAME:|^USAGE:|flag provided but not defined|incorrect Usage' "$ARGO_LOG" 2>/dev/null; then
    echo "      → 命中命令被拒(日志里是 cloudflared 的帮助文本): 说明启动参数不对, 不是网络问题"
    echo "      → 固定隧道正确写法是 'cloudflared tunnel --no-autoupdate --protocol http2 run --token <token>'"
    echo "      → 手工验证: /etc/mihomo-lite/run-argo.sh 直接 bash 跑一次看输出"
  fi
  if grep -qiE 'context deadline|no recent network activity|i/o timeout|dial tcp|failed to dial' "$ARGO_LOG" 2>/dev/null; then
    echo "      → 命中网络超时: 换协议(http2/quic)或检查 7844 出站是否被墙"
  fi
}

_argo_start_check() {
  local port="${1:-}" i
  sleep 3
  if ! _service_active "$ARGO_SERVICE_NAME"; then
    _error "cloudflared 没起来。最近日志:"
    tail -n 15 "$ARGO_LOG" 2>/dev/null | sed 's/^/    /'
    _argo_fail_hint "$port"
    return 1
  fi
  # 进程活着 != 隧道通了: 固定隧道要等 "Registered tunnel connection"
  for i in $(seq 1 12); do
    grep -q "Registered tunnel connection" "$ARGO_LOG" 2>/dev/null && { _success "cloudflared 已连上 CF 边缘。"; return 0; }
    sleep 1
  done
  _warn "cloudflared 在跑，但 12 秒内没看到 'Registered tunnel connection'。最近日志:"
  tail -n 12 "$ARGO_LOG" 2>/dev/null | sed 's/^/    /'
  _argo_fail_hint "$port"
  return 1
}

_start_service() {
  local name="$1"
  case "$INIT_SYSTEM" in
    systemd)
      # 启动失败不能静默: 单元缺失/ExecStart 路径不对/权限问题都在这里暴露
      if ! systemctl start "$name" >/dev/null 2>&1; then
        _error "systemctl start ${name} 失败"
        systemctl status "$name" --no-pager -l 2>&1 | tail -n 5 | sed 's/^/    /'
      fi
      ;;
    openrc)
      rc-service "$name" start >/dev/null 2>&1 || { _error "rc-service ${name} start 失败"; rc-service "$name" status 2>&1 | tail -n 3 | sed 's/^/    /'; }
      ;;
    direct)
      case "$name" in
        ${SERVICE_NAME})
          [ -f "${MIHOMO_DIR}/core.pid" ] && kill "$(cat "${MIHOMO_DIR}/core.pid")" 2>/dev/null
          nohup "${MIHOMO_BIN}" -d "${MIHOMO_DIR}" >> "${CORE_LOG}" 2>&1 &
          echo $! > "${MIHOMO_DIR}/core.pid"
          ;;
        ${ARGO_SERVICE_NAME})
          [ -f "${MIHOMO_DIR}/argo.pid" ] && kill "$(cat "${MIHOMO_DIR}/argo.pid")" 2>/dev/null
          nohup "${MIHOMO_DIR}/run-argo.sh" &
          echo $! > "${MIHOMO_DIR}/argo.pid"
          ;;
      esac
      ;;
  esac
}

_stop_service() {
  local name="$1"
  case "$INIT_SYSTEM" in
    systemd) systemctl stop "$name" ;;
    openrc)  rc-service "$name" stop ;;
    direct)
      local pidfile="${MIHOMO_DIR}/core.pid"
      [ "$name" = "${ARGO_SERVICE_NAME}" ] && pidfile="${MIHOMO_DIR}/argo.pid"
      [ -f "$pidfile" ] && { kill "$(cat "$pidfile")" 2>/dev/null; rm -f "$pidfile"; }
      ;;
  esac
}

_service_active() {
  case "$INIT_SYSTEM" in
    systemd) systemctl is-active "$1" >/dev/null 2>&1 ;;
    openrc)  rc-service "$1" status >/dev/null 2>&1 ;;
    direct)
      local pidfile="${MIHOMO_DIR}/core.pid"
      [ "$1" = "${ARGO_SERVICE_NAME}" ] && pidfile="${MIHOMO_DIR}/argo.pid"
      [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null
      ;;
  esac
}

# 临时隧道(trycloudflare)每次启动都会分配新域名: 重启 Argo 后把新域名同步回
# metadata 与订阅(links/clash.yaml), 否则旧域名的节点会全部失效
_sync_temp_argo_domain() {
  local mark="${1:-0}"
  [ "$(jq -r '.argo.mode // ""' "$METADATA_FILE" 2>/dev/null)" = "temp" ] || return 0
  local old d i
  old=$(jq -r '.argo.domain // ""' "$METADATA_FILE")
  for i in $(seq 1 20); do
    d=$(tail -n +$((mark+1)) "$ARGO_LOG" 2>/dev/null | grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' | tail -n1 | sed 's|https://||')
    [ -n "$d" ] && [ "$d" != "$old" ] && break
    sleep 1
  done
  if [ -n "$d" ] && [ "$d" != "$old" ]; then
    jq --arg d "$d" '.argo.domain = $d
      | .nodes |= map(if (.proto == "vless-ws" or .proto == "vmess-ws") then .argo_domain = $d else . end)'       "$METADATA_FILE" > "${METADATA_FILE}.tmp" && mv "${METADATA_FILE}.tmp" "$METADATA_FILE"
    _warn "临时隧道域名已变更: ${old:-无} → ${d}（已同步节点与订阅）"
    _build_links >/dev/null 2>&1
  fi
  return 0
}


_restart_all() {
  # 配置校验不通过则不重启
  if [ -x "$MIHOMO_BIN" ] && [ -s "$CONFIG_FILE" ]; then
    if ! "${MIHOMO_BIN}" -t -d "${MIHOMO_DIR}" >/dev/null 2>&1; then
      _error "配置校验失败（mihomo -t），不重启服务。"
      "${MIHOMO_BIN}" -t -d "${MIHOMO_DIR}" 2>&1 | tail -n 5
      return 1
    fi
  fi
  _stop_service "$SERVICE_NAME"; _start_service "$SERVICE_NAME"
  if jq -e '.argo.enabled == true' "$METADATA_FILE" >/dev/null 2>&1; then
    local argo_mark=0
    [ -f "$ARGO_LOG" ] && argo_mark=$(wc -l < "$ARGO_LOG" 2>/dev/null || echo 0)
    _stop_service "$ARGO_SERVICE_NAME"; _start_service "$ARGO_SERVICE_NAME"
  fi
  # 启动后存活校验：mihomo -t 查不出 psk 之类的运行期 listen 错误，用进程状态兜底
  sleep 2
  if ! _service_active "$SERVICE_NAME"; then
    _error "核心启动失败，最近日志："
    [ "$INIT_SYSTEM" = "systemd" ] && journalctl -u ${SERVICE_NAME} -n 3 --no-pager | grep -i error || tail -n 3 "${CORE_LOG}"
    return 1
  fi
  _sync_temp_argo_domain "${argo_mark:-0}"
  _success "服务已重启。"
}

# ---------------- 节点添加 ----------------
_ask_port() {
  local prompt="$1" default="$2" allow="${3:-}" p
  # 默认端口随机化(参考 singbox-lite): 传 "rand" 时在 10000-65535 内挑一个空闲端口,
  # 回车即用随机值, 也可手动输入覆盖
  if [ "$default" = "rand" ]; then
    local i rp
    for i in $(seq 1 50); do
      rp=$(shuf -i 10000-65535 -n 1 2>/dev/null || echo $(( (RANDOM % 55536) + 10000 )))
      if ! _check_port_conflict "$rp"; then default="$rp"; break; fi
    done
    [ "$default" = "rand" ] && default=10000
  fi
  read -rp "${prompt} [${default}]: " p
  p="${p:-$default}"
  # allow: 本脚本自己的 argo 回源口, 会被自己的 listener 占着, 沿用不算冲突
  if [ -n "$allow" ] && [ "$p" = "$allow" ]; then
    ASK_PORT_RESULT="$p"
    return 0
  fi
  if _check_port_conflict "$p"; then return 1; fi
  ASK_PORT_RESULT="$p"
}

# 传输层选择(仅 mieru): 传当前值, 结果存 ASK_TRANSPORT_RESULT; 空输入保留当前值
# 添加与修改共用同一套解析, 避免两处规则漂移
_ask_transport() {
  local cur t
  cur=$(printf '%s' "${1:-TCP}" | tr 'a-z' 'A-Z' | tr -d '[:space:]')
  [ "$cur" = "UDP" ] || cur="TCP"
  read -rp "传输层 1) TCP  2) UDP [当前 ${cur}]: " t || t=""
  t=$(printf '%s' "${t%$'\r'}" | tr -d '[:space:]' | tr 'a-z' 'A-Z')
  case "$t" in
    1|TCP) ASK_TRANSPORT_RESULT="TCP" ;;
    2|UDP) ASK_TRANSPORT_RESULT="UDP" ;;
    "")    ASK_TRANSPORT_RESULT="$cur" ;;
    *)     _warn "输入 '${t}' 无法识别，保留 ${cur}。"; ASK_TRANSPORT_RESULT="$cur" ;;
  esac
  _info "传输层: ${ASK_TRANSPORT_RESULT}"
}

# [1] VLESS + XHTTP + Reality（首选：XHTTP 把流量拆成标准 HTTP 请求序列，抗主动探测强，可套 CDN）
_add_vless_xhttp() {
  _ask_port "请输入 VLESS-XHTTP-Reality 端口" rand || return 1
  local port="$ASK_PORT_RESULT" sni uuid pk pub sid path mode
  sni=$(_pick_sni)
  read -rp "伪装 SNI [${sni}]: " s; sni="${s:-$sni}"
  uuid=$(_gen_uuid)
  local kp
  kp=$("${MIHOMO_BIN}" generate reality-keypair 2>/dev/null)
  pk=$(awk '/PrivateKey/{print $2}' <<<"$kp")
  pub=$(awk '/PublicKey/{print $2}' <<<"$kp")
  [ -z "$pk" ] || [ -z "$pub" ] && { _error "Reality 密钥对生成失败。"; return 1; }
  sid=$(_gen_hex 4)
  # 随机路径，防御固定路径指纹
  path="/$(_gen_hex 6)"
  read -rp "XHTTP 路径 [${path}]: " p; path="${p:-$path}"
  echo "传输模式: 1) auto (推荐, 自动选 stream-up/packet-up)  2) packet-up  3) stream-up"
  read -rp "选择 [1]: " m
  case "$m" in
    2) mode="packet-up" ;;
    3) mode="stream-up" ;;
    *) mode="auto" ;;
  esac
  _ask_ip_ver
  _ask_node_name "$(_proto_label vless-xhttp)"
  local node
  node=$(jq -cn --arg tag "vless-x-${port}" --arg name "$NODE_NAME" --arg port "$port" --arg ipver "$IP_VER" \
    --arg uuid "$uuid" --arg pk "$pk" --arg pub "$pub" --arg sid "$sid" --arg sni "$sni" \
    --arg path "$path" --arg mode "$mode" \
    '{tag:$tag,name:$name,ip_ver:$ipver,proto:"vless-xhttp",port:($port|tonumber),uuid:$uuid,private_key:$pk,public_key:$pub,short_id:$sid,sni:$sni,ws_path:$path,xhttp_mode:$mode}')
  _add_node_meta "$node"
  _regen_config; _restart_all; _show_links
}

# [2] VLESS + TCP + Reality + Vision
_add_vless_reality() {
  _ask_port "请输入 VLESS-Reality 端口" rand || return 1
  local port="$ASK_PORT_RESULT" sni uuid pk pub sid enc=""
  sni=$(_pick_sni)
  read -rp "伪装 SNI [${sni}]: " s; sni="${s:-$sni}"
  uuid=$(_gen_uuid)
  # 用 mihomo 自带命令生成 reality 密钥对，保证公私钥匹配
  local kp
  kp=$("${MIHOMO_BIN}" generate reality-keypair 2>/dev/null)
  pk=$(awk '/PrivateKey/{print $2}' <<<"$kp")
  pub=$(awk '/PublicKey/{print $2}' <<<"$kp")
  [ -z "$pk" ] || [ -z "$pub" ] && { _error "Reality 密钥对生成失败。"; return 1; }
  sid=$(_gen_hex 4)
  read -rp "是否启用 VLESS Encryption (后量子加密)? [y/N]: " e
  if [[ "$e" =~ ^[Yy]$ ]]; then
    _info "运行 '${MIHOMO_BIN} generate vless-x25519' 查看服务端 decryption 字符串："
    "${MIHOMO_BIN}" generate vless-x25519 2>/dev/null || _warn "当前核心版本不支持该命令，跳过。"
    read -rp "粘贴服务端 decryption 字符串 (留空跳过): " enc
  fi
  _ask_ip_ver
  _ask_node_name "$(_proto_label vless-reality)"
  local node
  node=$(jq -cn --arg tag "vless-r-${port}" --arg name "$NODE_NAME" --arg port "$port" --arg ipver "$IP_VER" \
    --arg uuid "$uuid" --arg pk "$pk" --arg pub "$pub" --arg sid "$sid" --arg sni "$sni" --arg dec "$enc" \
    '{tag:$tag,name:$name,ip_ver:$ipver,proto:"vless-reality",port:($port|tonumber),uuid:$uuid,private_key:$pk,public_key:$pub,short_id:$sid,sni:$sni,decryption:(if $dec=="" then null else $dec end)}')
  _add_node_meta "$node"
  _regen_config; _restart_all; _show_links
}

# [2] Hysteria2
_add_hysteria2() {
  _ask_port "请输入 Hysteria2 端口 (UDP)" rand || return 1
  local port="$ASK_PORT_RESULT" sni pass obfs obfp cert masq
  sni=$(_pick_sni)
  read -rp "SNI [${sni}]: " s; sni="${s:-$sni}"
  pass=$(_gen_hex 16)
  read -rp "认证密码 [${pass}]: " p; pass="${p:-$pass}"
  obfs="salamander"; obfp=$(_gen_hex 8)
  read -rp "Salamander 混淆密码 [${obfp}]: " o; obfp="${o:-$obfp}"
  read -rp "伪装站 masquerade (可空, 如 https://news.ycombinator.com): " m; masq="$m"
  local ck; ck=$(_gen_selfsigned_cert "$sni" "hy2-${port}") || return 1
  local crt="${ck%%|*}" key="${ck##*|}"
  _ask_ip_ver
  _ask_node_name "$(_proto_label hysteria2)"
  local node
  node=$(jq -cn --arg tag "hy2-${port}" --arg name "$NODE_NAME" --arg port "$port" --arg pass "$pass" --arg ipver "$IP_VER" \
    --arg obfs "$obfs" --arg obfp "$obfp" --arg crt "$crt" --arg key "$key" --arg sni "$sni" --arg masq "$masq" \
    '{tag:$tag,name:$name,ip_ver:$ipver,proto:"hysteria2",port:($port|tonumber),password:$pass,obfs:$obfs,obfs_password:$obfp,cert:$crt,key:$key,sni:$sni,masquerade:(if $masq=="" then null else $masq end)}')
  _add_node_meta "$node"
  _regen_config; _restart_all; _show_links
}

# [3] TUIC v5
_add_tuic() {
  _ask_port "请输入 TUIC v5 端口 (UDP)" rand || return 1
  local port="$ASK_PORT_RESULT" sni uuid pass
  sni=$(_pick_sni)
  read -rp "SNI [${sni}]: " s; sni="${s:-$sni}"
  uuid=$(_gen_uuid); pass=$(_gen_hex 16)
  read -rp "认证密码 [${pass}]: " p; pass="${p:-$pass}"
  local ck; ck=$(_gen_selfsigned_cert "$sni" "tuic-${port}") || return 1
  _ask_ip_ver
  _ask_node_name "$(_proto_label tuic)"
  local node
  node=$(jq -cn --arg tag "tuic-${port}" --arg name "$NODE_NAME" --arg port "$port" --arg ipver "$IP_VER" \
    --arg uuid "$uuid" --arg pass "$pass" --arg crt "${ck%%|*}" --arg key "${ck##*|}" --arg sni "$sni" \
    '{tag:$tag,name:$name,ip_ver:$ipver,proto:"tuic",port:($port|tonumber),uuid:$uuid,password:$pass,cert:$crt,key:$key,sni:$sni}')
  _add_node_meta "$node"
  _regen_config; _restart_all; _show_links
}

# [4] AnyTLS
_add_anytls() {
  _ask_port "请输入 AnyTLS 端口" rand || return 1
  local port="$ASK_PORT_RESULT" sni user pass
  sni=$(_pick_sni)
  read -rp "SNI [${sni}]: " s; sni="${s:-$sni}"
  user="u$(_gen_hex 3)"; pass=$(_gen_hex 16)   # 用户名不限于 u1, 每次随机生成
  read -rp "认证用户名 [${user}]: " mu || mu=""
  mu=$(printf '%s' "${mu%$\r}" | tr -d '[:space:]'); [ -n "$mu" ] && user="$mu"
  read -rp "认证密码 [${pass}]: " p; pass="${p:-$pass}"
  local ck; ck=$(_gen_selfsigned_cert "$sni" "anytls-${port}") || return 1
  _ask_ip_ver
  _ask_node_name "$(_proto_label anytls)"
  local node
  node=$(jq -cn --arg tag "anytls-${port}" --arg name "$NODE_NAME" --arg port "$port" --arg ipver "$IP_VER" \
    --arg user "$user" --arg pass "$pass" --arg crt "${ck%%|*}" --arg key "${ck##*|}" --arg sni "$sni" \
    '{tag:$tag,name:$name,ip_ver:$ipver,proto:"anytls",port:($port|tonumber),username:$user,password:$pass,cert:$crt,key:$key,sni:$sni}')
  _add_node_meta "$node"
  _regen_config; _restart_all; _show_links
}

# [5] Mieru
_add_mieru() {
  _ask_port_range || return 1
  local port="$ASK_PORT_RESULT" range="${ASK_RANGE_RESULT:-}" user pass transport
  _ask_transport "TCP"; transport="$ASK_TRANSPORT_RESULT"
  user="u$(_gen_hex 3)"; pass=$(_gen_hex 16)   # 用户名任意, 每次随机生成
  read -rp "认证用户名 [${user}]: " mu || mu=""
  mu=$(printf '%s' "${mu%$\r}" | tr -d '[:space:]'); [ -n "$mu" ] && user="$mu"
  read -rp "认证密码 [${pass}]: " p; pass="${p:-$pass}"
  _ask_ip_ver
  _ask_node_name "$(_proto_label mieru)"
  local node
  node=$(jq -cn --arg tag "mieru-${port}" --arg name "$NODE_NAME" --arg port "$port" --arg ipver "$IP_VER" \
    --arg user "$user" --arg pass "$pass" --arg tr "$transport" --arg range "$range" \
    '{tag:$tag,name:$name,ip_ver:$ipver,proto:"mieru",port:($port|tonumber),username:$user,password:$pass,transport:$tr} | if $range == "" then . else .port_range = $range end')
  _add_node_meta "$node"
  _regen_config; _restart_all; _show_links
}

# [6] Shadowsocks 2022
_add_ss2022() {
  _ask_port "请输入 SS2022 端口" rand || return 1
  local port="$ASK_PORT_RESULT" cipher pass len
  echo "可选加密方式: 1) 2022-blake3-aes-128-gcm (16字节)  2) 2022-blake3-aes-256-gcm (32字节)  3) 2022-blake3-chacha20-poly1305 (32字节)"
  read -rp "选择 [1]: " c
  case "$c" in
    2) cipher="2022-blake3-aes-256-gcm"; len=32 ;;
    3) cipher="2022-blake3-chacha20-poly1305"; len=32 ;;
    *) cipher="2022-blake3-aes-128-gcm"; len=16 ;;
  esac
  pass=$(openssl rand -base64 "$len" 2>/dev/null | tr -d '\n')
  read -rp "密码 (须为 ${len} 字节 base64) [${pass}]: " p; pass="${p:-$pass}"
  # SS2022 服务端会严格校验 psk：必须是合法 base64 且解码后长度精确匹配，否则 listener 运行时报 decode psk 错
  local decoded_len
  decoded_len=$(printf '%s' "$pass" | base64 -d 2>/dev/null | wc -c)
  [ "$decoded_len" = "$len" ] || { _error "密码不是合法 base64 或解码长度不等于 ${len} 字节，请重新添加。"; return 1; }
  _ask_ip_ver
  _ask_node_name "$(_proto_label ss2022)"
  local node
  node=$(jq -cn --arg tag "ss-${port}" --arg name "$NODE_NAME" --arg port "$port" --arg ipver "$IP_VER" \
    --arg cipher "$cipher" --arg pass "$pass" \
    '{tag:$tag,name:$name,ip_ver:$ipver,proto:"ss2022",port:($port|tonumber),cipher:$cipher,password:$pass}')
  _add_node_meta "$node"
  _regen_config; _restart_all; _show_links
}

# [7] Trojan + Reality
_add_trojan_reality() {
  _ask_port "请输入 Trojan-Reality 端口" rand || return 1
  local port="$ASK_PORT_RESULT" sni pass pk pub sid
  sni=$(_pick_sni)
  read -rp "伪装 SNI [${sni}]: " s; sni="${s:-$sni}"
  pass=$(_gen_hex 16)
  read -rp "认证密码 [${pass}]: " p; pass="${p:-$pass}"
  local kp
  kp=$("${MIHOMO_BIN}" generate reality-keypair 2>/dev/null)
  pk=$(awk '/PrivateKey/{print $2}' <<<"$kp")
  pub=$(awk '/PublicKey/{print $2}' <<<"$kp")
  [ -z "$pk" ] || [ -z "$pub" ] && { _error "Reality 密钥对生成失败。"; return 1; }
  sid=$(_gen_hex 4)
  _ask_ip_ver
  _ask_node_name "$(_proto_label trojan-reality)"
  local node
  node=$(jq -cn --arg tag "trojan-r-${port}" --arg name "$NODE_NAME" --arg port "$port" --arg ipver "$IP_VER" \
    --arg pass "$pass" --arg pk "$pk" --arg pub "$pub" --arg sid "$sid" --arg sni "$sni" \
    '{tag:$tag,name:$name,ip_ver:$ipver,proto:"trojan-reality",port:($port|tonumber),password:$pass,private_key:$pk,public_key:$pub,short_id:$sid,sni:$sni}')
  _add_node_meta "$node"
  _regen_config; _restart_all; _show_links
}

# ---------------- Argo 隧道节点 ----------------
# 说明：添加时询问 cloudflared 传输协议 (1) http2/TCP 最稳  2) quic/UDP)，
# 选择结果写入 metadata.argo.protocol，run-argo.sh 按该值启动，不再自动回退。
# 环境变量 ARGO_PROTOCOL 仍可强制覆盖。

# 创建本机 WS 监听节点（Argo 回源用），供新隧道与复用已有隧道两条路径共用
_create_argo_ws_listener() {
  local proto
  echo "1) VLESS + WS  2) VMess + WS"
  read -rp "选择 Argo 节点协议 [1]: " c
  [[ "$c" = "2" ]] && proto="vmess-ws" || proto="vless-ws"
  local cur_port
  cur_port=$(jq -r 'if .argo.enabled == true then (.argo.port // "") else "" end' "$METADATA_FILE" 2>/dev/null)
  _ask_port "本机 WS 监听端口 (Argo 回源端口, 仅 127.0.0.1)" "${cur_port:-8888}" "$cur_port" || return 1
  local port="$ASK_PORT_RESULT" uuid path
  uuid=$(_gen_uuid)
  path="/$(_gen_hex 8)"
  # 复用外部 cloudflared 时协议由用户自己的隧道配置决定, 这里不问; WS 监听只在 127.0.0.1
  IP_VER="v4"
  _ask_node_name "$(_proto_label "$proto")"
  local node
  node=$(jq -cn --arg tag "argo-${port}" --arg name "$NODE_NAME" --arg port "$port" --arg ipver "$IP_VER" \
    --arg proto "$proto" --arg uuid "$uuid" --arg path "$path" \
    '{tag:$tag,name:$name,ip_ver:$ipver,proto:$proto,port:($port|tonumber),uuid:$uuid,ws_path:$path}')
  _add_node_meta "$node"
  _regen_config; _restart_all
  CREATED_ARGO_PORT="$port"
}

# 复用本机已有的外部 cloudflared 隧道：只添加本地 WS 监听 + 指导用户在 CF 面板加路由
_reuse_external_tunnel() {
  _create_argo_ws_listener || return 1
  local port="$CREATED_ARGO_PORT" host
  _info "════ Cloudflare 面板操作指引 ════"
  _info "1. 登录 Cloudflare Zero Trust 控制台 → Networks → Tunnels"
  _info "2. 选择你已有的隧道 → Public Hostname → Add a public hostname"
  _info "3. Subdomain 填子域 (如 argo2)，Domain 选你的域名"
  _info "4. Type 选 HTTP，URL 填 127.0.0.1:${port}，保存"
  read -rp "添加完成后输入该 Public Hostname 完整域名 (留空可稍后再补): " host
  if [ -n "$host" ]; then
    local tmp="${METADATA_FILE}.tmp"
    jq --arg t "argo-${port}" --arg d "$host" '.nodes |= map(if .tag == $t then .argo_domain = $d else . end)' "$METADATA_FILE" > "$tmp" && mv "$tmp" "$METADATA_FILE"
  fi
  _build_links
  _show_links
  return 0
}

# ---------------- 节点修改 ----------------
# 按协议开放可改字段, 空输入=保留原值; 值全部经 --arg 传给 jq, 不做字符串拼接
_modify_node_menu() {
  local count
  count=$(jq '.nodes | length' "$METADATA_FILE" 2>/dev/null || echo 0)
  [ "$count" = "0" ] && { _warn "暂无节点。"; return; }
  # Argo 节点(vless-ws/vmess-ws)与隧道绑定, 端口/域名/回源都由隧道决定,
  # 不在这里改, 也不生成条目 —— 统一走【Argo 管理 → 3 修改】
  local map
  map=$(jq -r '.nodes | to_entries
        | map(select(.value.proto != "vless-ws" and .value.proto != "vmess-ws"))
        | to_entries[]
        | "\(.key+1)\t\(.value.key)\t[\(.value.value.proto)] \(.value.value.name)\t\(.value.value.port_range // .value.value.port)"' "$METADATA_FILE")
  if [ -z "$map" ]; then
    _warn "没有可修改的节点。Argo 节点请在【Argo 管理 → 3 修改】里调整。"
    return
  fi
  echo "当前节点:"
  printf '%s\n' "$map" | awk -F'\t' '{printf "  %s) %s  端口:%s\n", $1, $3, $4}'
  echo "  (Argo 节点不在此列表，改端口/域名请走【Argo 管理 → 3 修改】)"
  read -rp "输入要修改的编号 (0 取消): " i || return
  [[ "$i" =~ ^[0-9]+$ ]] || return
  [ "$i" = "0" ] && return
  local idx
  idx=$(printf '%s\n' "$map" | awk -F'\t' -v n="$i" '$1 == n {print $2; exit}')
  [ -z "$idx" ] && { _error "编号无效。"; return; }
  local proto tag name port
  proto=$(jq -r --argjson i "$idx" '.nodes[$i].proto // empty' "$METADATA_FILE")
  [ -z "$proto" ] && { _error "编号无效。"; return; }
  tag=$(jq -r --argjson i "$idx" '.nodes[$i].tag' "$METADATA_FILE")
  name=$(jq -r --argjson i "$idx" '.nodes[$i].name' "$METADATA_FILE")
  port=$(jq -r --argjson i "$idx" '.nodes[$i].port' "$METADATA_FILE")

  local new_name="$name" new_port="$port" v
  read -rp "节点名称 [${name}]: " v || v=""
  v=$(_normalize_name "$v")
  [ -n "$v" ] && new_name="$v"
  # 改名后做一次去重(排除自身), 否则客户端 proxies 会撞名
  if [ "$new_name" != "$name" ]; then
    local clash
    clash=$(jq -r --arg nm "$new_name" '[.nodes[]? | select(.name == $nm)] | length' "$METADATA_FILE" 2>/dev/null)
    if [ "${clash:-0}" -gt 0 ] 2>/dev/null; then
      _warn "名称 ${new_name} 已被其它节点使用，保留原名 ${name}。"
      new_name="$name"
    fi
  fi
  _info "节点名称: ${new_name}"
  read -rp "端口 [${port}]: " v
  if [ -n "$v" ] && [ "$v" != "$port" ]; then
    # _check_port_conflict 约定: 返回 0=冲突, 返回 1=可用
    if _check_port_conflict "$v"; then return 1; fi
    new_port="$v"
  fi

  # 对外 IP 版本(双栈机器可选)
  local ip_ver_cur ip_ver_new
  ip_ver_cur=$(jq -r --argjson i "$idx" '.nodes[$i].ip_ver // "v4"' "$METADATA_FILE")
  read -rp "对外 IP 版本 (4/6) [${ip_ver_cur#v}]: " v
  case "$v" in
    4) ip_ver_new="v4" ;;
    6) ip_ver_new="v6" ;;
    *) ip_ver_new="$ip_ver_cur" ;;
  esac

  # 需要更新的值(默认=原值)与对应的 jq filter 片段
  local sni uuid pass obfp path domain transport range
  local filter=""
  case "$proto" in
    vless-xhttp)
      sni=$(jq -r --argjson i "$idx" '.nodes[$i].sni // ""' "$METADATA_FILE")
      read -rp "伪装 SNI [${sni}]: " v; sni="${v:-$sni}"
      uuid=$(jq -r --argjson i "$idx" '.nodes[$i].uuid' "$METADATA_FILE")
      read -rp "重新生成 UUID? [y/N]: " u
      [[ "$u" =~ ^[Yy]$ ]] && uuid=$(_gen_uuid)
      path=$(jq -r --argjson i "$idx" '.nodes[$i].ws_path // "/"' "$METADATA_FILE")
      read -rp "重新生成 XHTTP 路径? [y/N]: " u
      [[ "$u" =~ ^[Yy]$ ]] && path="/$(_gen_hex 6)"
      filter=' | .sni = $sni | .uuid = $uuid | .ws_path = $path'
      ;;
    vless-reality)
      sni=$(jq -r --argjson i "$idx" '.nodes[$i].sni // ""' "$METADATA_FILE")
      read -rp "伪装 SNI [${sni}]: " v; sni="${v:-$sni}"
      uuid=$(jq -r --argjson i "$idx" '.nodes[$i].uuid' "$METADATA_FILE")
      read -rp "重新生成 UUID? [y/N]: " u
      [[ "$u" =~ ^[Yy]$ ]] && uuid=$(_gen_uuid)
      filter=' | .sni = $sni | .uuid = $uuid'
      ;;
    hysteria2)
      pass=$(jq -r --argjson i "$idx" '.nodes[$i].password // ""' "$METADATA_FILE")
      obfp=$(jq -r --argjson i "$idx" '.nodes[$i].obfs_password // ""' "$METADATA_FILE")
      read -rp "认证密码 [${pass}]: " v; pass="${v:-$pass}"
      read -rp "混淆密码 [${obfp}]: " v; obfp="${v:-$obfp}"
      filter=' | .password = $pass | .obfs_password = $obfp'
      ;;
    tuic|anytls)
      pass=$(jq -r --argjson i "$idx" '.nodes[$i].password // ""' "$METADATA_FILE")
      read -rp "认证密码 [${pass}]: " v; pass="${v:-$pass}"
      filter=' | .password = $pass'
      ;;
    mieru)
      user=$(jq -r --argjson i "$idx" '.nodes[$i].username // "u1"' "$METADATA_FILE")
      read -rp "认证用户名 [${user}]: " v; user="${v:-$user}"
      pass=$(jq -r --argjson i "$idx" '.nodes[$i].password // ""' "$METADATA_FILE")
      read -rp "认证密码 [${pass}]: " v; pass="${v:-$pass}"
      # 传输层可在线切换: TCP <-> UDP, 回车保留当前值
      _ask_transport "$(jq -r --argjson i "$idx" '.nodes[$i].transport // "TCP"' "$METADATA_FILE")"
      transport="$ASK_TRANSPORT_RESULT"
      # 端口段: 回车保留 / 输入 a-b 改成端口段 / 输入 - 取消端口段(回到单端口)
      local rng_cur a b cnt
      rng_cur=$(jq -r --argjson i "$idx" '.nodes[$i].port_range // ""' "$METADATA_FILE")
      echo "当前监听: ${rng_cur:-${new_port}（单端口）}"
      read -rp "端口段 (a-b 设置 / - 取消 / 回车保留) [${rng_cur:-无}]: " v || v=""
      v=$(printf '%s' "${v%$'
'}" | tr -d '[:space:]')
      if [ "$v" = "-" ]; then
        range=""
        _info "已取消端口段，改为单端口 ${new_port}。"
      elif [ -n "$v" ]; then
        if ! [[ "$v" =~ ^([0-9]+)-([0-9]+)$ ]]; then
          _error "格式应为 a-b，未做修改。"
          return 1
        fi
        a="${BASH_REMATCH[1]}"; b="${BASH_REMATCH[2]}"
        { [ "$a" -ge 1 ] && [ "$b" -le 65535 ] && [ "$a" -lt "$b" ]; } || { _error "端口段无效 (需 1 <= a < b <= 65535)，未做修改。"; return 1; }
        cnt=$(( b - a + 1 ))
        if [ "$cnt" -gt "$MAX_RANGE_PORTS" ]; then
          _error "范围 ${cnt} 个端口超过上限 ${MAX_RANGE_PORTS}，未做修改。"
          return 1
        fi
        _check_port_conflict "$a" && return 1
        _check_port_conflict "$b" && return 1
        range="$v"
        new_port="$a"
        _info "端口段: ${a}-${b}（共 ${cnt} 个）"
      else
        range="$rng_cur"
        if [ -n "$range" ] && [ "${range%%-*}" != "$new_port" ]; then
          _warn "端口已改为 ${new_port}，与端口段 ${range} 不一致，已取消端口段。"
          range=""
        fi
      fi
      filter=' | .username = $user | .password = $pass | .transport = $transport | .port_range = (if $range == "" then null else $range end)'
      ;;
    ss2022)
      pass=$(jq -r --argjson i "$idx" '.nodes[$i].password // ""' "$METADATA_FILE")
      local len
      len=$(jq -r --argjson i "$idx" '.nodes[$i].cipher | if test("aes-128") then 16 else 32 end' "$METADATA_FILE")
      read -rp "密码 (${len} 字节 base64) [${pass}]: " v; pass="${v:-$pass}"
      local dlen
      dlen=$(printf '%s' "$pass" | base64 -d 2>/dev/null | wc -c)
      [ "$dlen" = "$len" ] || { _error "密码不是合法 base64 或长度不等于 ${len} 字节，未做修改。"; return 1; }
      filter=' | .password = $pass'
      ;;
    trojan-reality)
      pass=$(jq -r --argjson i "$idx" '.nodes[$i].password // ""' "$METADATA_FILE")
      sni=$(jq -r --argjson i "$idx" '.nodes[$i].sni // ""' "$METADATA_FILE")
      read -rp "认证密码 [${pass}]: " v; pass="${v:-$pass}"
      read -rp "伪装 SNI [${sni}]: " v; sni="${v:-$sni}"
      filter=' | .password = $pass | .sni = $sni'
      ;;
    vless-ws|vmess-ws)
      uuid=$(jq -r --argjson i "$idx" '.nodes[$i].uuid' "$METADATA_FILE")
      path=$(jq -r --argjson i "$idx" '.nodes[$i].ws_path // ""' "$METADATA_FILE")
      domain=$(jq -r --argjson i "$idx" '.nodes[$i].argo_domain // ""' "$METADATA_FILE")
      read -rp "重新生成 UUID? [y/N]: " u
      [[ "$u" =~ ^[Yy]$ ]] && uuid=$(_gen_uuid)
      read -rp "重新生成 WS 路径? [y/N]: " u
      [[ "$u" =~ ^[Yy]$ ]] && path="/$(_gen_hex 8)"
      read -rp "Argo 域名 [${domain:-未设置}]: " v; domain="${v:-$domain}"
      filter=' | .uuid = $uuid | .ws_path = $path | .argo_domain = (if $domain == "" then null else $domain end)'
      ;;
    *)
      _warn "该协议暂不支持在线修改字段，仅可改名称与端口。"
      ;;
  esac

  # 端口变更时 tag 同步重生成 (tag 形如 前缀-端口)
  local new_tag="$tag"
  [ "$new_port" != "$port" ] && new_tag="${tag%-$port}-${new_port}"

  local tmp="${METADATA_FILE}.tmp"
  if jq --argjson i "$idx" \
        --arg name "$new_name" \
        --arg user "${user:-}" \
        --argjson port "$new_port" \
        --arg tag "$new_tag" \
        --arg ipver "$ip_ver_new" \
        --arg sni "${sni:-}" \
        --arg uuid "${uuid:-}" \
        --arg pass "${pass:-}" \
        --arg obfp "${obfp:-}" \
        --arg path "${path:-}" \
        --arg domain "${domain:-}" \
        --arg transport "${transport:-}" \
        --arg range "${range:-}" \
        ".nodes[\$i] |= (.name = \$name | .port = \$port | .tag = \$tag | .ip_ver = \$ipver${filter})" \
        "$METADATA_FILE" > "$tmp" && [ -s "$tmp" ]; then
    mv "$tmp" "$METADATA_FILE"
  else
    rm -f "$tmp"
    _error "修改写入失败，未做任何更改。"
    return 1
  fi
  _regen_config; _restart_all; _show_links
  _success "节点已修改。"
}


# ---------------- Argo 节点/隧道删除 ----------------
_delete_argo_menu() {
  local ws_nodes
  ws_nodes=$(jq -r '[.nodes[]? | select(.proto == "vless-ws" or .proto == "vmess-ws")] | length' "$METADATA_FILE")
  local argo_enabled
  argo_enabled=$(jq -r '.argo.enabled // false' "$METADATA_FILE")
  echo "当前 Argo 隧道: $([ "$argo_enabled" = "true" ] && echo "已配置 ($(jq -r '.argo.mode' "$METADATA_FILE") 模式, 域名: $(jq -r '.argo.domain // "未探测"' "$METADATA_FILE"))" || echo "无 (未由本脚本管理)")"
  echo "当前 Argo WS 节点数: ${ws_nodes}"
  echo " 1) 删除 Argo 节点 (仅删本地 WS 监听, 隧道保留)"
  echo " 2) 删除 Argo 隧道 (停止并清除本脚本管理的 cloudflared, 同时删除全部 Argo 节点)"
  echo " 0) 返回"
  read -rp "选择: " d || return
  case "$d" in
    1) _delete_argo_node ;;
    2) _delete_argo_tunnel ;;
    0) ;;
    *) _error "无效输入。" ;;
  esac
}

_delete_argo_node() {
  local tags
  tags=$(jq -r '.nodes[]? | select(.proto == "vless-ws" or .proto == "vmess-ws") | "\(.tag)\t\(.name)\t\(.port)"' "$METADATA_FILE")
  [ -z "$tags" ] && { _warn "暂无 Argo 节点。"; return; }
  echo "当前 Argo 节点:"
  echo "$tags" | awk -F'\t' '{print "  " NR ") " $2 "  端口:" $3 "  (" $1 ")"}'
  read -rp "输入要删除的编号: " i
  local tag
  tag=$(echo "$tags" | sed -n "${i}p" | cut -f1)
  [ -z "$tag" ] && { _error "编号无效。"; return; }
  _del_node_meta "$tag"
  _regen_config; _restart_all
  _success "Argo 节点已删除。"
  # 临时隧道只映射一个端口：删掉映射节点后隧道已无意义，询问是否一并清除
  if [ "$(jq -r '.argo.mode // ""' "$METADATA_FILE")" = "temp" ]; then
    local remaining
    remaining=$(jq -r '[.nodes[]? | select(.proto == "vless-ws" or .proto == "vmess-ws")] | length' "$METADATA_FILE")
    if [ "$remaining" = "0" ] || [ "$(jq -r '.argo.port // 0' "$METADATA_FILE")" = "$(jq -r --arg t "$tag" '.nodes[]? | select(.tag == $t) | .port // 0' "$METADATA_FILE" | head -1)" ]; then
      read -rp "临时隧道的映射节点已删除，是否同时停止并清除该隧道? [Y/n]: " s
      [[ "$s" =~ ^[Nn]$ ]] || _delete_argo_tunnel
    fi
  fi
}

_delete_argo_tunnel() {
  # 停止并禁用本脚本管理的 cloudflared；外部/复用的隧道不受影响
  _stop_service "$ARGO_SERVICE_NAME"
  if [ "$INIT_SYSTEM" = "systemd" ]; then
    systemctl disable ${ARGO_SERVICE_NAME} >/dev/null 2>&1
  elif [ "$INIT_SYSTEM" = "openrc" ]; then
    rc-update del ${ARGO_SERVICE_NAME} >/dev/null 2>&1
  fi
  rm -f "${MIHOMO_DIR}/run-argo.sh" "${MIHOMO_DIR}/argo.pid"
  # 删除全部 Argo WS 节点
  jq -r '.nodes[]? | select(.proto == "vless-ws" or .proto == "vmess-ws") | .tag' "$METADATA_FILE" | while read -r t; do _del_node_meta "$t"; done
  local tmp="${METADATA_FILE}.tmp"
  jq '.argo = {enabled:false}' "$METADATA_FILE" > "$tmp" && mv "$tmp" "$METADATA_FILE"
  : > "$ARGO_LOG" 2>/dev/null
  _regen_config; _restart_all
  _success "Argo 隧道及全部 Argo 节点已删除。"
}

_add_argo_node() {
  _ensure_core || return 1
  # ── 已有隧道检测（两层）────────────────────────────────
  # 第一层：本脚本管理的隧道（metadata.argo）
  local existing_mode existing_domain existing_port
  existing_mode=$(jq -r '.argo.mode // ""' "$METADATA_FILE")
  existing_domain=$(jq -r '.argo.domain // ""' "$METADATA_FILE")
  existing_port=$(jq -r '.argo.port // ""' "$METADATA_FILE")
  # 第二层：本机已由其他方式部署的 cloudflared 隧道（系统服务/独立进程/官方 token 部署）
  # 仅当本脚本没有自管隧道时才检测，避免两层同时提示
  local ext_src="" ext_conf="/etc/cloudflared/config.yml"
  if ! jq -e '.argo.enabled == true' "$METADATA_FILE" >/dev/null 2>&1; then
    # 本脚本自管 argo 的 cloudflared 进程不算外部（按 PID 排除，不用文件痕迹一刀切——
    # 卸载残留的 service 单元会让外部隧道被误跳过）
    local our_pids=" "
    local p
    [ -f "${MIHOMO_DIR}/argo.pid" ] && our_pids+="$(cat "${MIHOMO_DIR}/argo.pid" 2>/dev/null) "
    [ "$INIT_SYSTEM" = "systemd" ] && our_pids+="$(systemctl show -p MainPID --value ${ARGO_SERVICE_NAME} 2>/dev/null) "
    if systemctl is-active cloudflared >/dev/null 2>&1; then
      ext_src="systemd 服务 cloudflared"
    elif [ -f "$ext_conf" ] || [ -f /etc/cloudflared/token ]; then
      ext_src="cloudflared 配置 (${ext_conf} / token)"
    else
      for p in $(pgrep -x cloudflared 2>/dev/null); do
        case " $our_pids " in *" $p "*) continue ;; esac
        ext_src="独立 cloudflared 进程 (PID ${p})"
        break
      done
    fi
  fi
  if [ -n "$ext_src" ]; then
    _success "检测到本机已有 cloudflared 隧道在运行 (来源: ${ext_src})。"
    [ -f "$ext_conf" ] && _info "隧道配置: ${ext_conf}"
    echo " 1) 复用已有隧道 (只添加本地 WS 监听, 在 CF 面板为新端口添加 Public Hostname)"
    echo " 2) 新建隧道 (Token/临时隧道, 由本脚本管理, 不影响已有隧道)"
    read -rp "选择 [1]: " tc
    if [[ ! "$tc" = "2" ]]; then
      _reuse_external_tunnel
      return $?
    fi
    _info "将与已有隧道并行新建独立隧道 (cloudflared 多实例可共存)。"
  fi
  if jq -e '.argo.enabled == true' "$METADATA_FILE" >/dev/null 2>&1; then
    if [ "$existing_mode" = "token" ]; then
      _success "检测到本机已有固定隧道 (域名: ${existing_domain:-未填写})，直接复用。"
      _create_argo_ws_listener || return 1
      local port="$CREATED_ARGO_PORT" host
      if [ "$port" = "$existing_port" ]; then
        # 同端口：直接沿用隧道已有域名
        local tmp="${METADATA_FILE}.tmp"
        jq --arg d "$existing_domain" '.nodes |= map(if (.proto == "vless-ws" or .proto == "vmess-ws") then .argo_domain = $d else . end)' "$METADATA_FILE" > "$tmp" && mv "$tmp" "$METADATA_FILE"
        _build_links
      else
        _info "════ Cloudflare 面板操作指引 ════"
        _info "1. 登录 Cloudflare Zero Trust 控制台 → Networks → Tunnels"
        _info "2. 点击你现有的隧道 → Public Hostname → Add a public hostname"
        _info "3. Subdomain 填子域 (如 argo2)，Domain 选你的域名"
        _info "4. Type 选 HTTP，URL 填 127.0.0.1:${port}，保存"
        read -rp "添加完成后输入该 Public Hostname 完整域名 (留空可稍后用菜单3查看前手动补充): " host
        if [ -n "$host" ]; then
          local tmp="${METADATA_FILE}.tmp"
          jq --arg t "argo-${port}" --arg d "$host" '.nodes |= map(if .tag == $t then .argo_domain = $d else . end)' "$METADATA_FILE" > "$tmp" && mv "$tmp" "$METADATA_FILE"
          _build_links
        fi
      fi
      _show_links
      return 0
    else
      _warn "检测到本机已有临时隧道 (域名: ${existing_domain:-探测中}，映射端口 ${existing_port})。"
      _warn "临时隧道只能映射一个回源端口，新增节点需要重建隧道（域名会变化）。"
      read -rp "是否重建临时隧道? [y/N]: " r
      [[ "$r" =~ ^[Yy]$ ]] || { _info "已取消。"; return 0; }
    fi
  fi
  local proto mode token domain cur_port
  echo "1) VLESS + WS  2) VMess + WS"
  read -rp "选择 Argo 节点协议 [1]: " c
  [[ "$c" = "2" ]] && proto="vmess-ws" || proto="vless-ws"
  cur_port=$(jq -r 'if .argo.enabled == true then (.argo.port // "") else "" end' "$METADATA_FILE" 2>/dev/null)
  _ask_port "本机 WS 监听端口 (Argo 回源端口, 仅 127.0.0.1)" "${cur_port:-8888}" "$cur_port" || return 1
  local port="$ASK_PORT_RESULT" uuid path
  uuid=$(_gen_uuid)
  path="/$(_gen_hex 8)"
  echo "1) 临时隧道 (trycloudflare.com, 域名随机)  2) 固定隧道 (Cloudflare Tunnel Token)"
  read -rp "选择隧道模式 [1]: " m
  # Argo 节点对外只走 Cloudflare 域名, 与本机对外 IP 版本无关; 这里问的是 cloudflared 的传输协议
  _ask_argo_protocol
  IP_VER="v4"
  _ask_node_name "$(_proto_label "$proto")"
  if [[ "$m" = "2" ]]; then
    read -rp "粘贴 Cloudflare Tunnel Token: " token
    token=$(_clean_token "$token")
    [ -z "$token" ] && { _error "Token 不能为空。"; return 1; }
    if ! printf '%s' "$token" | grep -qE '^[A-Za-z0-9_=.-]+$'; then
      _error "Token 含非法字符(空格/引号/换行?)，请重新复制后粘贴。"
      return 1
    fi
    _info "Token 长度 ${#token}，首尾 ${token:0:6}…${token: -6}"
    read -rp "固定隧道域名 (如 argo.example.com): " domain
    [ -z "$domain" ] && { _error "固定隧道必须填写域名。"; return 1; }
    mode="token"
    _info "面板路径: Zero Trust → Networks → Tunnels → 该隧道 → Public Hostname，Type=HTTP，URL=127.0.0.1:${port}"
  else
    mode="temp"; domain=""
    _info "临时隧道域名将在启动后自动探测。"
  fi
  # 按需安装：本机没有任何 cloudflared 时才下载，已有则复用
  if ! _cloudflared_bin >/dev/null; then
    _info "本机没有 cloudflared，开始安装..."
    install_cloudflared || { _error "cloudflared 安装失败，Argo 无法启动。"; return 1; }
  fi
  # 删除旧的 argo 节点（一个隧道只挂一个 ws 节点）
  jq -r '.nodes[]? | select(.proto == "vless-ws" or .proto == "vmess-ws") | .tag' "$METADATA_FILE" | while read -r t; do _del_node_meta "$t"; done
  local node
  node=$(jq -cn --arg tag "argo-${port}" --arg name "$NODE_NAME" --arg port "$port" \
    --arg proto "$proto" --arg uuid "$uuid" --arg path "$path" --arg ipver "$IP_VER" --arg domain "$domain" \
    '{tag:$tag,name:$name,ip_ver:$ipver,proto:$proto,port:($port|tonumber),uuid:$uuid,ws_path:$path,argo_domain:(if $domain == "" then null else $domain end)}')
  _add_node_meta "$node"
  # 更新 argo 状态
  local tmp="${METADATA_FILE}.tmp"
  jq --arg mode "$mode" --arg token "$token" --arg domain "$domain" --argjson port "$port" --arg protocol "$ARGO_PROTO_RESULT" \
    '.argo = ((.argo // {}) + {enabled:true, mode:$mode, token:$token, domain:$domain, port:$port, protocol:$protocol})' "$METADATA_FILE" > "$tmp" && mv "$tmp" "$METADATA_FILE"
  _write_argo_runner "$mode" "$token" "$port" || { _error "生成 run-argo.sh 失败(cloudflared 缺失?)"; return 1; }
  _create_services
  _regen_config; _restart_all
  _argo_start_check "$port"
  [ "$mode" = "temp" ] && _probe_temp_domain
  _show_links
}

# 探测临时隧道域名并写回 metadata（用于分享链接）
_probe_temp_domain() {
  _info "等待 Argo 临时隧道域名发布 (最长 30s)..."
  local domain=""
  for i in $(seq 1 30); do
    d=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$ARGO_LOG" 2>/dev/null | tail -n1 | sed 's|https://||')
    [ -n "$domain" ] && break
    sleep 1
  done
  if [ -n "$domain" ]; then
    local tmp="${METADATA_FILE}.tmp"
    jq --arg d "$domain" '.argo.domain = $d | .nodes |= map(if (.proto == "vless-ws" or .proto == "vmess-ws") then .argo_domain = $d else . end)' "$METADATA_FILE" > "$tmp" && mv "$tmp" "$METADATA_FILE"
    _success "临时隧道域名: ${domain}"
    _build_links
  else
    _error "未能从日志中获取临时隧道域名，请查看 ${ARGO_LOG}"
  fi
}

# ---------------- Argo 配置修改 ----------------
# 可改: 回源监听端口(WS 端口, 隧道指向同步)、隧道域名、连接 CF 边缘的 IP 版本(4/6/auto)
# Argo 节点与隧道是一体的, 所以这部分从【节点修改】里移出来单独放这里
_modify_argo_menu() {
  _ensure_core || return 1
  if [ "$(jq -r '.argo.enabled // false' "$METADATA_FILE")" != "true" ]; then
    _warn "尚未配置 Argo 隧道，请先在【Argo 管理 → 1 添加】里创建。"
    return 1
  fi
  local mode token domain port edge new_port new_domain new_edge v
  local cur_name new_name cur_proto new_proto
  mode=$(jq -r '.argo.mode // "temp"' "$METADATA_FILE")
  token=$(jq -r '.argo.token // ""' "$METADATA_FILE")
  domain=$(jq -r '.argo.domain // ""' "$METADATA_FILE")
  port=$(jq -r '.argo.port // 8888' "$METADATA_FILE")
  edge=$(jq -r '.argo.edge_ip // "auto"' "$METADATA_FILE")
  cur_proto=$(jq -r '.argo.protocol // "http2"' "$METADATA_FILE")
  cur_name=$(jq -r '[.nodes[]? | select(.proto == "vless-ws" or .proto == "vmess-ws") | .name][0] // ""' "$METADATA_FILE")

  echo "当前 Argo 配置:"
  echo "  模式: ${mode}   回源端口: ${port}"
  echo "  节点名称: ${cur_name:-未设置}"
  echo "  域名: ${domain:-未设置(临时隧道启动后自动探测)}"
  echo "  传输协议: ${cur_proto}  (http2=TCP/7844  quic=UDP/7844)"
  echo "  连接 CF 边缘: ${edge}  (4=仅IPv4  6=仅IPv6  auto=cloudflared 自选)"
  echo ""

  # 0) 节点名称(Argo 节点不在【节点修改】列表里, 改名只能在这里)
  new_name="$cur_name"
  read -rp "节点名称 [${cur_name:-地区.运营商.Argo}]: " v || v=""
  v=$(_normalize_name "$v")
  [ -n "$v" ] && new_name="$v"
  if [ -n "$new_name" ] && [ "$new_name" != "$cur_name" ]; then
    local clash
    clash=$(jq -r --arg nm "$new_name" '[.nodes[]? | select(.proto != "vless-ws" and .proto != "vmess-ws") | select(.name == $nm)] | length' "$METADATA_FILE" 2>/dev/null)
    if [ "${clash:-0}" -gt 0 ] 2>/dev/null; then
      _warn "名称 ${new_name} 已被其它节点使用，保留原名 ${cur_name}。"
      new_name="$cur_name"
    fi
  fi

  # 1) 回源监听端口
  new_port="$port"
  read -rp "回源监听端口 (WS, 仅 127.0.0.1) [${port}]: " v || v=""
  v=$(printf '%s' "${v%$'\r'}" | tr -d '[:space:]')
  if [ -n "$v" ] && [ "$v" != "$port" ]; then
    [[ "$v" =~ ^[0-9]+$ ]] || { _error "端口 ${v} 无效 (1-65535)。"; return 1; }
    # _check_port_conflict 约定: 返回 0=冲突(自带报错), 返回 1=可用
    if _check_port_conflict "$v"; then return 1; fi
    new_port="$v"
  fi

  # 2) 隧道域名(固定隧道填 Public Hostname; 临时隧道留空, 启动后自动探测)
  new_domain="$domain"
  read -rp "隧道域名 [${domain:-空}]: " v || v=""
  v=$(_normalize_name "$v")
  [ -n "$v" ] && new_domain="$v"

  # 3) 连接 CF 边缘的 IP 版本
  new_edge="$edge"
  echo "连接 CF 边缘的 IP 版本: 1) 仅 IPv4  2) 仅 IPv6  3) auto (cloudflared 自选)"
  read -rp "选择 [当前 ${edge}]: " v || v=""
  v=$(printf '%s' "${v%$'\r'}" | tr -d '[:space:]' | tr 'a-z' 'A-Z')
  case "$v" in
    1|4|V4|IPV4) new_edge="4" ;;
    2|6|V6|IPV6) new_edge="6" ;;
    3|AUTO)      new_edge="auto" ;;
    "")          new_edge="$edge" ;;
    *)           _warn "输入 '${v}' 无法识别，保留 ${edge}。"; new_edge="$edge" ;;
  esac

  # 4) 传输协议: http2(TCP/7844) 与 quic(UDP/7844) 之间切换
  new_proto="$cur_proto"
  echo "Argo 传输协议: 1) http2 (TCP/7844)  2) quic (UDP/7844)"
  read -rp "选择 [当前 ${cur_proto}]: " v || v=""
  v=$(printf '%s' "${v%$'\r'}" | tr -d '[:space:]' | tr 'a-z' 'A-Z')
  case "$v" in
    1|HTTP2|H2) new_proto="http2" ;;
    2|QUIC)     new_proto="quic" ;;
    "")         new_proto="$cur_proto" ;;
    *)          _warn "输入 '${v}' 无法识别，保留 ${cur_proto}。"; new_proto="$cur_proto" ;;
  esac
  if [ -n "${ARGO_PROTOCOL:-}" ] && [ "${ARGO_PROTOCOL}" != "$new_proto" ]; then
    _warn "环境变量 ARGO_PROTOCOL=${ARGO_PROTOCOL} 优先级更高，会盖掉这里的 ${new_proto}。"
  fi

  # 写回: argo 状态 + WS 节点(名称/端口/tag), tag 形如 argo-端口, 端口变了要同步
  local tmp="${METADATA_FILE}.tmp"
  if jq --argjson port "$new_port" --arg edge "$new_edge" --arg nm "$new_name" \
        --arg proto "$new_proto" \
        --arg oldtag "argo-${port}" --arg newtag "argo-${new_port}" \
        '.argo.port = $port | .argo.edge_ip = $edge | .argo.protocol = $proto
         | .nodes |= map(
             if (.proto == "vless-ws" or .proto == "vmess-ws")
             then .port = $port
                  | .name = (if $nm == "" then .name else $nm end)
                  | .tag = (if .tag == $oldtag then $newtag else .tag end)
             else . end)' "$METADATA_FILE" > "$tmp" && [ -s "$tmp" ]; then
    mv "$tmp" "$METADATA_FILE"
  else
    rm -f "$tmp"
    _error "写入失败，未做任何更改。"
    return 1
  fi
  # 域名单独写, 空输入保留原值(临时隧道靠探测回填, 不能清空)
  if [ -n "$new_domain" ] && [ "$new_domain" != "$domain" ]; then
    tmp="${METADATA_FILE}.tmp"
    jq --arg d "$new_domain" '.argo.domain = $d
       | .nodes |= map(if (.proto == "vless-ws" or .proto == "vmess-ws") then .argo_domain = $d else . end)' \
       "$METADATA_FILE" > "$tmp" && mv "$tmp" "$METADATA_FILE"
  fi

  _write_argo_runner "$mode" "$token" "$new_port" || { _error "生成 run-argo.sh 失败(cloudflared 缺失?)"; return 1; }
  _regen_config
  [ "$mode" = "temp" ] && : > "$ARGO_LOG"
  _restart_all
  _argo_start_check "$new_port"
  if [ "$mode" = "temp" ]; then
    _info "临时隧道端口变更后域名会重新分配，等待探测..."
    _probe_temp_domain
  elif [ "$new_port" != "$port" ]; then
    _warn "固定隧道需在 CF 面板把 Public Hostname 的 URL 改成 127.0.0.1:${new_port}，否则回源失败。"
  fi
  _show_links
  _success "Argo 配置已更新 (名称 ${new_name:-未变} / 端口 ${new_port} / 协议 ${new_proto} / 边缘 IP ${new_edge} / 域名 ${new_domain:-待探测})。"
  if [ "$new_proto" != "$cur_proto" ]; then
    _info "协议已切到 ${new_proto}。若 20 秒内连不上, 会自动回退到另一条协议并写进 ${ARGO_LOG}；想严格只用 ${new_proto}: ARGO_NO_FALLBACK=1"
  fi
}

# 查看 Argo 隧道与节点(Argo 节点与隧道绑定, 不单独出现在节点修改里, 统一在这里看)
_show_argo_overview() {
  if [ "$(jq -r '.argo.enabled // false' "$METADATA_FILE")" != "true" ]; then
    _warn "尚未配置 Argo 隧道，请先在【Argo 管理 → 1 添加】里创建。"
    return 1
  fi
  local mode port domain proto edge ws_count
  mode=$(jq -r '.argo.mode // "temp"' "$METADATA_FILE")
  port=$(jq -r '.argo.port // 8888' "$METADATA_FILE")
  domain=$(jq -r '.argo.domain // ""' "$METADATA_FILE")
  proto=$(jq -r '.argo.protocol // "http2→quic 回退"' "$METADATA_FILE")
  edge=$(jq -r '.argo.edge_ip // "auto"' "$METADATA_FILE")
  ws_count=$(jq -r '[.nodes[]? | select(.proto == "vless-ws" or .proto == "vmess-ws")] | length' "$METADATA_FILE")

  echo ""
  echo -e "${CYAN}================ Argo 隧道 ================${NC}"
  echo "  模式: ${mode}   回源端口: ${port}"
  echo "  域名: ${domain:-未设置(临时隧道启动后自动探测)}"
  echo "  传输协议: ${proto}   边缘 IP: ${edge}"
  if _service_active "$ARGO_SERVICE_NAME"; then
    _success "cloudflared 运行中"
  else
    _warn "cloudflared 未运行 (菜单 6 重启 / 菜单 9 看日志)"
  fi
  echo "  WS 节点数: ${ws_count}"
  echo ""
  echo "  节点:"
  jq -r '.nodes[]? | select(.proto == "vless-ws" or .proto == "vmess-ws")
         | "   - [\(.proto)] \(.name)  回源 127.0.0.1:\(.port)  域名:\(.argo_domain // "未绑定")"' "$METADATA_FILE"
  echo ""
  echo -e "${CYAN}================ Argo 节点链接 ================${NC}"
  _build_links
  if [ -s "${SUB_DIR}/argo.txt" ]; then
    cat "${SUB_DIR}/argo.txt"
  else
    _warn "暂无 Argo 链接：节点缺少隧道域名。固定隧道在【2→3 修改】里填域名，临时隧道重启后等探测。"
  fi
  echo -e "${CYAN}=============================================${NC}"
  echo "文件: ${SUB_DIR}/argo.txt"
}

# Argo 诊断: 一次把"为什么不起来"该看的都打出来, 不用来回猜
_argo_doctor() {
  local cfbin port
  port=$(jq -r '.argo.port // 8888' "$METADATA_FILE" 2>/dev/null)
  echo -e "${CYAN}================ Argo 诊断 ================${NC}"
  echo "init: ${INIT_SYSTEM}   回源端口: ${port}"
  if cfbin=$(_cloudflared_bin); then
    echo "cloudflared: ${cfbin}"
    echo "  $("$cfbin" --version 2>&1 | head -n1)"
  else
    _error "cloudflared: 未找到 (安装: 菜单 2 → 1 会自动装)"
  fi
  echo "metadata .argo:"
  jq -c '.argo // {}
         | if (.token // "") != ""
           then .token = ((.token[0:6]) + "…" + (.token[-6:]) + " (len " + ((.token | length) | tostring) + ")")
           else . end' "$METADATA_FILE" 2>/dev/null | sed 's/^/    /'
  echo "run-argo.sh:"
  if [ -f "${MIHOMO_DIR}/run-argo.sh" ]; then
    ls -l "${MIHOMO_DIR}/run-argo.sh" | awk '{print "    " $1, $NF}'
    sed -n '1,8p' "${MIHOMO_DIR}/run-argo.sh" | sed 's/--token .*/--token ****/' | sed 's/^/    /'
  else
    _error "    不存在 (说明还没成功生成过)"
  fi
  echo "systemd 单元:"
  if [ -f "/etc/systemd/system/${ARGO_SERVICE_NAME}.service" ]; then
    grep -E 'Type|ExecStart|Restart' "/etc/systemd/system/${ARGO_SERVICE_NAME}.service" | sed 's/^/    /'
  else
    _error "    未创建 (/etc/systemd/system/${ARGO_SERVICE_NAME}.service)"
  fi
  echo "服务状态:"
  systemctl status "${ARGO_SERVICE_NAME}" --no-pager -l 2>&1 | head -n 8 | sed 's/^/    /'
  echo "退出信息:"
  systemctl show -p Result -p ExecMainStatus -p NRestarts "${ARGO_SERVICE_NAME}" 2>/dev/null | sed 's/^/    /'
  echo "journal (最近 15 行, run-argo.sh 自身语法错会出现在这里):"
  journalctl -u "${ARGO_SERVICE_NAME}" -n 15 --no-pager 2>/dev/null | sed 's/^/    /' || echo "    (无 journal)"
  echo "日志 ${ARGO_LOG}:"
  if [ -s "$ARGO_LOG" ]; then
    tail -n 20 "$ARGO_LOG" | sed 's/^/    /'
  else
    _warn "    空或不存在 —— run-argo.sh 一次都没执行过"
  fi
  echo "端口监听:"
  if ss -lntu 2>/dev/null | awk '{print $5}' | grep -qE "[:.]${port}([[:space:]]|$)"; then
    ss -lntu 2>/dev/null | awk -v p=":$port" '$5 ~ p {print "    " $0}'
  else
    echo "    ${port} 未监听 (mihomo 核心没起或 listener 未生成)"
  fi
  echo -e "${CYAN}===========================================${NC}"
}

# 重新获取临时隧道（域名会变，链接随之更新）
_renew_temp_argo() {
  if [ "$(jq -r '.argo.mode // ""' "$METADATA_FILE")" != "temp" ]; then
    _warn "当前不是临时隧道模式。"; return 1
  fi
  : > "$ARGO_LOG"
  _stop_service "$ARGO_SERVICE_NAME"; _start_service "$ARGO_SERVICE_NAME"
  _argo_start_check "$(jq -r '.argo.port // 8888' "$METADATA_FILE")"
  _probe_temp_domain
}

# ---------------- 节点删除 ----------------
_delete_node_menu() {
  local count
  count=$(jq '.nodes | length' "$METADATA_FILE" 2>/dev/null || echo 0)
  [ "$count" = "0" ] && { _warn "暂无节点。"; return; }
  echo "当前节点:"
  jq -r '.nodes | to_entries[] | "  \(.key+1)) [\(.value.proto)] \(.value.name)  端口:\(.value.port_range // .value.port)"' "$METADATA_FILE"
  read -rp "输入要删除的编号 (0 取消): " i
  [[ "$i" =~ ^[0-9]+$ ]] || return
  [ "$i" = "0" ] && return
  local tag
  tag=$(jq -r --argjson i "$((i-1))" '.nodes[$i].tag // empty' "$METADATA_FILE")
  [ -z "$tag" ] && { _error "编号无效。"; return; }
  _del_node_meta "$tag"
  _regen_config; _restart_all
  _success "节点已删除。"
}

# ---------------- 脚本自更新 ----------------
_update_script() {
  local target="/usr/local/bin/mh"
  # 已装到常驻路径则原地更新，否则安装到 /usr/local/bin/mh
  [ -x "$SELF_SCRIPT_PATH" ] && [[ "$SELF_SCRIPT_PATH" == /usr/local/bin/* ]] && target="$SELF_SCRIPT_PATH"
  local cur_ver="$SCRIPT_VERSION"
  # 附加时间戳参数穿透 raw.githubusercontent 的 CDN 缓存(否则会拿到几分钟前的旧文件)
  local bust="?t=$(date +%s)"
  local url="${GITHUB_RAW_URL}${bust}"
  _info "更新脚本: ${GITHUB_RAW_URL} → ${target} (当前 v${cur_ver})"
  local mirror="${GH_PROXY:-https://gh-proxy.com/}"
  local tmp="${MIHOMO_DIR}/mh.update"
  rm -f "$tmp"
  _fetch "$url" "$tmp" || _fetch "${mirror}${url}" "$tmp" || _fetch "https://ghfast.top/${url}" "$tmp"
  if ! { [ -s "$tmp" ] && head -n1 "$tmp" | grep -q "^#!/bin/bash" && bash -n "$tmp" 2>/dev/null; }; then
    _error "脚本下载或校验失败，未做任何更改。"
    rm -f "$tmp"
    return 1
  fi
  local new_ver
  new_ver=$(grep -m1 '^SCRIPT_VERSION=' "$tmp" | cut -d'"' -f2)
  chmod +x "$tmp"
  mv -f "$tmp" "$target"
  if [ -n "$new_ver" ] && [ "$new_ver" = "$cur_ver" ]; then
    _warn "远端版本仍是 v${new_ver}，已按最新内容覆盖 ${target}（若刚发版请等 1-2 分钟后重试）。"
    _info "重新运行 mh 生效。"
  else
    _success "脚本已更新: v${cur_ver} → v${new_ver:-未知}，正在重载新版本…"
    # 文件已被替换, 但当前进程内存里跑的还是旧代码(旧函数/旧 SCRIPT_VERSION),
    # 不 exec 就得退出重进才看得到新版本号。这里直接用新脚本替换当前进程。
    if [ -x "$target" ]; then
      exec "$target"
    elif [ -f "$target" ]; then
      exec bash "$target"
    else
      _warn "目标不可执行，无法自动重载，请手动重新运行 mh。"
    fi
  fi
}

# ---------------- 卸载 ----------------
_uninstall() {
  read -rp "确认卸载 mihomo-lite (核心/服务/配置全部删除)? [y/N]: " c
  [[ "$c" =~ ^[Yy]$ ]] || return
  _stop_service "$ARGO_SERVICE_NAME"; _stop_service "$SERVICE_NAME"
  case "$INIT_SYSTEM" in
    systemd)
      systemctl disable --now ${SERVICE_NAME} ${ARGO_SERVICE_NAME} >/dev/null 2>&1
      rm -f /etc/systemd/system/${SERVICE_NAME}.service /etc/systemd/system/${ARGO_SERVICE_NAME}.service
      systemctl daemon-reload
      ;;
    openrc) rm -f /etc/init.d/${SERVICE_NAME} /etc/init.d/${ARGO_SERVICE_NAME} ;;
  esac
  rm -f "$MIHOMO_BIN"
  # cloudflared 可能属于原机已有部署，卸载本脚本时不删除
  rm -rf "$MIHOMO_DIR"
  rm -f /usr/local/bin/mh /usr/local/bin/ml
  _success "mihomo-lite 已卸载。"
  exit 0
}

# ---------------- 菜单 ----------------
_menu_status() {
  echo -e "${CYAN}--- 运行状态 ---${NC}"
  echo "init: ${INIT_SYSTEM}"
  if [ -x "$MIHOMO_BIN" ]; then
    echo -e "核心: $(${MIHOMO_BIN} -v 2>/dev/null | head -n1)"
  else
    echo "核心: 未安装"
  fi
  _service_active "$SERVICE_NAME" && _success "mihomo 核心运行中" || _warn "mihomo 核心未运行"
  if jq -e '.argo.enabled == true' "$METADATA_FILE" >/dev/null 2>&1; then
    local aproto aedge
    aproto=$(jq -r '.argo.protocol // "http2→quic 回退"' "$METADATA_FILE")
    aedge=$(jq -r '.argo.edge_ip // "auto"' "$METADATA_FILE")
    if _service_active "$ARGO_SERVICE_NAME"; then
      _success "Argo 隧道运行中 (协议 ${aproto} / 边缘 IP ${aedge})"
    else
      _warn "Argo 隧道未运行 (协议 ${aproto} / 边缘 IP ${aedge})"
      echo "        菜单 6 重启；仍失败看菜单 9 日志，或菜单 2→3 检查端口/域名"
    fi
    local d; d=$(jq -r '.argo.domain // ""' "$METADATA_FILE")
    [ -n "$d" ] && echo "Argo 域名: ${d}"
  fi
  local count; count=$(jq '.nodes | length // 0' "$METADATA_FILE" 2>/dev/null)
  echo "节点数量: ${count:-0}"
}

_show_menu() {
  echo ""
  echo -e "${GREEN}======== mihomo-lite 管理脚本 v${SCRIPT_VERSION} ========${NC}"
  echo " 1. 添加节点 (XHTTP-Reality/Reality/HY2/TUIC/AnyTLS/Mieru/SS2022/Trojan)"
  echo " 2. Argo 隧道管理 (添加/删除/修改节点与隧道, 传输协议 http2/quic 可选)"
  echo " 3. 查看节点链接"
  echo " 4. 删除节点"
  echo " 5. 修改节点"
  echo " 6. 重启服务"
  echo " 7. 停止服务"
  echo " 8. 查看运行状态"
  echo " 9. 查看实时日志"
  echo "10. 重新获取 Argo 临时隧道域名"
  echo "11. 安装/更新 mihomo 核心"
  echo "12. 更新脚本 (mh)"
  echo "13. 卸载"
  echo " 0. 退出"
}

_show_logs() {
  echo "1) 核心日志  2) Argo 日志"
  read -rp "选择 [1]: " c
  if [ "$c" = "2" ]; then
    tail -n 50 "$ARGO_LOG" 2>/dev/null || _warn "暂无 Argo 日志。"
  else
    if [ "$INIT_SYSTEM" = "systemd" ]; then journalctl -u ${SERVICE_NAME} -n 50 --no-pager; else tail -n 50 "$CORE_LOG" 2>/dev/null; fi
  fi
}

_main_menu() {
  while true; do
    _menu_status
    _show_menu
    read -rp "请选择: " choice || { echo ""; _info "输入结束，退出。"; exit 0; }
    case "$choice" in
      1)
        # 添加节点前检查核心是否已安装，未安装可当场确认安装
        _ensure_core || continue
        echo " 1) VLESS+XHTTP+Reality  【推荐·首选】"
        echo " 2) VLESS+Reality+Vision (TCP)"
        echo " 3) Hysteria2"
        echo " 4) TUIC v5"
        echo " 5) AnyTLS"
        echo " 6) Mieru"
        echo " 7) SS2022"
        echo " 8) Trojan+Reality"
        echo " 0) 返回"
        read -rp "协议: " p
        case "$p" in
          1) _add_vless_xhttp ;; 2) _add_vless_reality ;;
          3) _add_hysteria2 ;; 4) _add_tuic ;;
          5) _add_anytls ;; 6) _add_mieru ;; 7) _add_ss2022 ;;
          8) _add_trojan_reality ;;
          0) ;;
          *) _error "无效输入。" ;;
        esac
        ;;
      2)
        echo " 1) 添加 Argo 节点"
        echo " 2) 删除 Argo 节点 / Argo 隧道"
        echo " 3) 修改 Argo 配置 (回源端口 / 隧道域名 / 传输协议 / 连接 CF 的 IP 版本)"
        echo " 4) 查看 Argo 隧道与节点链接"
        echo " 5) 诊断 (cloudflared / 单元 / 日志 / 端口 一次看全)"
        echo " 0) 返回"
        read -rp "Argo 管理: " a || break
        case "$a" in
          1) _add_argo_node ;;
          2) _delete_argo_menu ;;
          3) _modify_argo_menu ;;
          4) _show_argo_overview ;;
          5) _argo_doctor ;;
          0) ;;
          *) _error "无效输入。" ;;
        esac
        ;;
      3) _show_links ;;
      4) _delete_node_menu ;;
      5) _modify_node_menu ;;
      6) _restart_all ;;
      7) _stop_service "$SERVICE_NAME"; _stop_service "$ARGO_SERVICE_NAME"; _success "已停止。" ;;
      8) _menu_status ;;
      9) _show_logs ;;
      10) _renew_temp_argo ;;
      11) install_core ;;
      12) _update_script ;;
      13) _uninstall ;;
      0) exit 0 ;;
      *) _error "无效输入。" ;;
    esac
  done
}

main() {
  _check_root
  _install_dependencies || exit 1
  _detect_init_system
  _init_metadata
  _migrate_node_names
  mkdir -p "$MIHOMO_DIR" "$SUB_DIR" "$CERTS_DIR"
  # 生成直跑模式的 argo 启动脚本（若已有 argo 配置）
  if jq -e '.argo.enabled == true' "$METADATA_FILE" >/dev/null 2>&1; then
    local mode token port runner bak
    mode=$(jq -r '.argo.mode // "temp"' "$METADATA_FILE")
    token=$(jq -r '.argo.token // ""' "$METADATA_FILE")
    port=$(jq -r '.argo.port // 8888' "$METADATA_FILE")
    [ "$mode" = "temp" ] && token=""
    runner="${MIHOMO_DIR}/run-argo.sh"
    bak=""
    [ -f "$runner" ] && { bak=$(mktemp); cp -f "$runner" "$bak" 2>/dev/null; }
    _write_argo_runner "$mode" "$token" "$port"
    # 脚本升级后启动命令可能变了(如固定隧道改用 run 子命令), 内容有变就重启一次 argo 服务
    if [ -n "$bak" ] && ! cmp -s "$bak" "$runner" && _service_active "$ARGO_SERVICE_NAME"; then
      _stop_service "$ARGO_SERVICE_NAME"
      _start_service "$ARGO_SERVICE_NAME" >/dev/null 2>&1 \
        && _info "Argo 启动脚本已更新，服务已按新参数重启"
    fi
    [ -n "$bak" ] && rm -f "$bak"
  fi
  if [ -x "$MIHOMO_BIN" ] && [ ! -s "$CONFIG_FILE" ]; then
    _regen_config
  fi
  if [ ! -x "$MIHOMO_BIN" ]; then
    _warn "mihomo 核心未安装，请先选择菜单【10】安装核心。"
  fi
  _main_menu
}

# 快捷命令参数
case "${1:-}" in
  links) _check_root; _install_dependencies >/dev/null 2>&1; _detect_init_system; _init_metadata; _show_links; exit 0 ;;
  renew) _check_root; _install_dependencies >/dev/null 2>&1; _detect_init_system; _init_metadata; _renew_temp_argo; exit 0 ;;
esac

main
