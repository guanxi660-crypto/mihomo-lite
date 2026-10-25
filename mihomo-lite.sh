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
#   8. VLESS/VMess + WS + Argo 隧道（cloudflared --protocol auto：优先 QUIC，连不上自动回退 http2）
# 支持: Debian/Ubuntu(systemd) / Alpine(OpenRC) / 无 init 直跑模式
# 需 root 权限运行
#=============================================================================
umask 077
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}"

SCRIPT_VERSION="1.2.0"
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
DEFAULT_SNI_LIST="www.amd.com www.cloudflare.com www.amazon.com www.microsoft.com"

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
  local need=""
  for c in curl jq openssl ss; do command -v "$c" >/dev/null 2>&1 || need="$need $c"; done
  [ -z "$need" ] && return 0
  _info "安装基础依赖:$need"
  if command -v apt >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1
    apt-get install -y --no-install-recommends curl jq openssl iproute2 cron >/dev/null 2>&1
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache curl jq openssl iproute2 cronie 2>/dev/null || apk add --no-cache curl jq openssl iproute2
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl jq openssl iproute2 cronie >/dev/null 2>&1
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl jq openssl iproute2 cronie >/dev/null 2>&1
  else
    _error "无法识别的包管理器，请手动安装:$need"; return 1
  fi
  for c in curl jq openssl; do
    command -v "$c" >/dev/null 2>&1 || { _error "缺少 $c，请手动安装后重试。"; return 1; }
  done
}

# ---------------- 工具函数 ----------------
_gen_uuid()    { cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16 | sed 's/\(.\{8\}\)\(.\{4\}\)\(.\{4\}\)\(.\{4\}\)/\1-\2-\3-\4-/'; }
_gen_hex()     { openssl rand -hex "$1" 2>/dev/null; }
_url_encode()  { printf '%s' "$1" | jq -sRr @uri; }
_b64_nopad()   { printf '%s' "$1" | base64 | tr -d '\n\r' | sed 's/=//g'; }

_get_public_ip() {
  local ip
  ip=$(timeout 5 curl -4fsS --max-time 4 https://icanhazip.com 2>/dev/null || timeout 5 curl -4fsS --max-time 4 https://ipinfo.io/ip 2>/dev/null)
  [ -z "$ip" ] && ip=$(timeout 5 curl -6fsS --max-time 4 https://icanhazip.com 2>/dev/null)
  printf '%s' "$ip"
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

# 随机选取一个默认 SNI
_pick_sni() { echo "$DEFAULT_SNI_LIST" | tr ' ' '\n' | shuf -n1 2>/dev/null || echo "www.cloudflare.com"; }

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
    vless-reality)
      local uuid pk sid sni flow enc
      uuid=$(jq -r '.uuid' <<<"$n"); pk=$(jq -r '.private_key' <<<"$n")
      sid=$(jq -r '.short_id' <<<"$n"); sni=$(jq -r '.sni' <<<"$n")
      flow=$(jq -r '.flow // ""' <<<"$n"); enc=$(jq -r '.decryption // ""' <<<"$n")
      cat <<EOF
  - name: "${tag}"
    type: vless
    port: ${port}
    listen: 0.0.0.0
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
    listen: 0.0.0.0
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
    listen: 0.0.0.0
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
    listen: 0.0.0.0
    users:
      "${user}": "${pass}"
    certificate: "${crt}"
    private-key: "${key}"
EOF
      ;;
    mieru)
      local user pass transport
      user=$(jq -r '.username' <<<"$n"); pass=$(jq -r '.password' <<<"$n")
      transport=$(jq -r '.transport // "TCP"' <<<"$n")
      cat <<EOF
  - name: "${tag}"
    type: mieru
    port: ${port}
    listen: 0.0.0.0
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
    listen: 0.0.0.0
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
    listen: 0.0.0.0
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
  : > "$links_file"
  {
    echo "# mihomo-lite 客户端配置（Clash/Mihomo 格式）自动生成"
    echo "proxies:"
  } > "$yaml_file"
  jq -c '.nodes[]?' "$METADATA_FILE" | while IFS= read -r n; do
    local tag proto port link=""
    tag=$(jq -r '.name // .tag' <<<"$n"); proto=$(jq -r '.proto' <<<"$n"); port=$(jq -r '.port' <<<"$n")
    local enc_tag enc_name
    enc_tag=$(_b64_nopad "$tag")
    case "$proto" in
      vless-reality)
        local uuid pbk sid sni
        uuid=$(jq -r '.uuid' <<<"$n"); pbk=$(jq -r '.public_key' <<<"$n")
        sid=$(jq -r '.short_id' <<<"$n"); sni=$(jq -r '.sni' <<<"$n")
        link="vless://${uuid}@${ip}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${pbk}&sid=${sid}&type=tcp#${enc_tag}"
        {
          printf '  - name: "%s"\n    type: vless\n    server: %s\n    port: %s\n    uuid: %s\n    udp: true\n    tls: true\n    flow: xtls-rprx-vision\n    servername: %s\n    client-fingerprint: chrome\n    network: tcp\n    reality-opts:\n      public-key: %s\n      short-id: "%s"\n' "$tag" "$ip" "$port" "$uuid" "$sni" "$pbk" "$sid"
        } >> "$yaml_file"
        ;;
      vless-ws|vmess-ws)
        local uuid path domain ws_proto
        uuid=$(jq -r '.uuid' <<<"$n"); path=$(jq -r '.ws_path' <<<"$n")
        domain=$(jq -r '.argo_domain // ""' <<<"$n")
        [ -z "$domain" ] && continue
        if [ "$proto" = "vless-ws" ]; then
          link="vless://${uuid}@${domain}:443?encryption=none&security=tls&type=ws&host=${domain}&path=$(_url_encode "$path")#arg-${enc_tag}"
          printf '  - name: "%s"\n    type: vless\n    server: %s\n    port: 443\n    uuid: %s\n    udp: true\n    tls: true\n    servername: %s\n    network: ws\n    ws-opts:\n      path: "%s"\n      headers:\n        Host: %s\n' "$tag" "$domain" "$uuid" "$domain" "$path" "$domain" >> "$yaml_file"
        else
          local vj
          vj=$(jq -cn --arg v "2" --arg u "$uuid" --arg d "$domain" --arg t "$tag" --arg p "$path" '{v:$v,ps:("arg-"+$t),add:$d,port:"443",id:$u,aid:"0",scy:"auto",net:"ws",type:"none",host:$d,path:$p,tls:"tls"}')
          link="vmess://$(_b64_nopad "$vj")"
          printf '  - name: "%s"\n    type: vmess\n    server: %s\n    port: 443\n    uuid: %s\n    alterId: 0\n    cipher: auto\n    udp: true\n    tls: true\n    servername: %s\n    network: ws\n    ws-opts:\n      path: "%s"\n      headers:\n        Host: %s\n' "$tag" "$domain" "$uuid" "$domain" "$path" "$domain" >> "$yaml_file"
        fi
        ;;
      hysteria2)
        local pass sni obfs obfp
        pass=$(jq -r '.password' <<<"$n"); sni=$(jq -r '.sni' <<<"$n")
        obfs=$(jq -r '.obfs // ""' <<<"$n"); obfp=$(jq -r '.obfs_password // ""' <<<"$n")
        link="hy2://${pass}@${ip}:${port}?sni=${sni}&insecure=1"
        [ -n "$obfs" ] && link="${link}&obfs=salamander&obfs-password=${obfp}"
        link="${link}#${enc_tag}"
        {
          printf '  - name: "%s"\n    type: hysteria2\n    server: %s\n    port: %s\n    password: %s\n    sni: %s\n    skip-cert-verify: true\n' "$tag" "$ip" "$port" "$pass" "$sni"
          [ -n "$obfs" ] && printf '    obfs: salamander\n    obfs-password: "%s"\n' "$obfp"
        } >> "$yaml_file"
        ;;
      tuic)
        local uuid pass sni
        uuid=$(jq -r '.uuid' <<<"$n"); pass=$(jq -r '.password' <<<"$n"); sni=$(jq -r '.sni' <<<"$n")
        link="tuic://${uuid}:${pass}@${ip}:${port}?sni=${sni}&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#${enc_tag}"
        printf '  - name: "%s"\n    type: tuic\n    server: %s\n    port: %s\n    uuid: %s\n    password: "%s"\n    sni: %s\n    skip-cert-verify: true\n    congestion-controller: bbr\n    alpn:\n      - h3\n    udp: true\n' "$tag" "$ip" "$port" "$uuid" "$pass" "$sni" >> "$yaml_file"
        ;;
      anytls)
        local user pass sni
        user=$(jq -r '.username' <<<"$n"); pass=$(jq -r '.password' <<<"$n"); sni=$(jq -r '.sni' <<<"$n")
        link="anytls://${user}:${pass}@${ip}:${port}?sni=${sni}&insecure=1#${enc_tag}"
        printf '  - name: "%s"\n    type: anytls\n    server: %s\n    port: %s\n    username: %s\n    password: "%s"\n    sni: %s\n    skip-cert-verify: true\n' "$tag" "$ip" "$port" "$user" "$pass" "$sni" >> "$yaml_file"
        ;;
      mieru)
        local user pass transport
        user=$(jq -r '.username' <<<"$n"); pass=$(jq -r '.password' <<<"$n")
        transport=$(jq -r '.transport // "TCP"' <<<"$n" | tr 'A-Z' 'a-z')
        # mieru 暂无通用分享链接规范，仅输出客户端 Clash 配置
        printf '  - name: "%s"\n    type: mieru\n    server: %s\n    port: %s\n    username: "%s"\n    password: "%s"\n    transport: %s\n' "$tag" "$ip" "$port" "$user" "$pass" "$transport" >> "$yaml_file"
        ;;
      ss2022)
        local cipher pass userinfo
        cipher=$(jq -r '.cipher' <<<"$n"); pass=$(jq -r '.password' <<<"$n")
        userinfo=$(_b64_nopad "${cipher}:${pass}")
        link="ss://${userinfo}@${ip}:${port}#${enc_tag}"
        printf '  - name: "%s"\n    type: ss\n    server: %s\n    port: %s\n    cipher: %s\n    password: "%s"\n    udp: true\n' "$tag" "$ip" "$port" "$cipher" "$pass" >> "$yaml_file"
        ;;
      trojan-reality)
        local pass pbk sid sni
        pass=$(jq -r '.password' <<<"$n"); pbk=$(jq -r '.public_key' <<<"$n")
        sid=$(jq -r '.short_id' <<<"$n"); sni=$(jq -r '.sni' <<<"$n")
        link="trojan://${pass}@${ip}:${port}?security=reality&sni=${sni}&fp=chrome&pbk=${pbk}&sid=${sid}&type=tcp#${enc_tag}"
        printf '  - name: "%s"\n    type: trojan\n    server: %s\n    port: %s\n    password: "%s"\n    udp: true\n    sni: %s\n    client-fingerprint: chrome\n    reality-opts:\n      public-key: %s\n      short-id: "%s"\n' "$tag" "$ip" "$port" "$pass" "$sni" "$pbk" "$sid" >> "$yaml_file"
        ;;
    esac
    [ -n "$link" ] && echo "$link" >> "$links_file"
  done
  chmod 600 "$links_file" "$yaml_file" 2>/dev/null
}

_show_links() {
  _build_links
  local ip; ip=$(_get_public_ip)
  echo ""
  echo -e "${CYAN}================ 节点分享链接 (服务器 IP: ${ip}) ================${NC}"
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

install_core() {
  local arch; arch=$(_detect_arch) || return 1
  _info "获取 mihomo 最新版本号..."
  local tag
  tag=$(curl -fsSL --connect-timeout 15 "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest" | jq -r '.tag_name // empty')
  [ -z "$tag" ] && { _error "获取 mihomo 版本号失败，请检查网络。"; return 1; }
  local fname="mihomo-linux-${arch}-${tag}.gz"
  local url="https://github.com/MetaCubeX/mihomo/releases/download/${tag}/${fname}"
  _info "下载 mihomo ${tag} (${arch})..."
  local tmp="${MIHOMO_DIR}/mihomo.dl.gz"
  _fetch "$url" "$tmp" || { _error "下载 mihomo 失败: ${url}"; return 1; }
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
  _info "下载 cloudflared (${arch})..."
  local url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}"
  _fetch "$url" "${CLOUDFLARED_BIN}.new" || { _error "下载 cloudflared 失败"; return 1; }
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
# 协议选择：默认 auto（优先 QUIC，连接失败自动回退 http2/TCP）。
# 如所在环境 UDP 被劫持导致 QUIC 数据面静默失效（注册成功但边缘 530），
# 可用环境变量 ARGO_PROTOCOL=http2 强制 TCP，脚本无需改动。
_write_argo_runner() {
  local mode="$1" token="$2" port="$3"
  local proto="${ARGO_PROTOCOL:-auto}"
  local cfbin
  cfbin=$(_cloudflared_bin) || { _error "cloudflared 未安装。"; return 1; }
  {
    echo "#!/bin/bash"
    echo "exec > >(tee -a '${ARGO_LOG}') 2>&1"
    if [ "$mode" = "token" ]; then
      echo "exec ${cfbin} tunnel --no-autoupdate --protocol '${proto}' --token '${token}'"
    else
      echo "exec ${cfbin} tunnel --no-autoupdate --protocol '${proto}' --url http://127.0.0.1:${port}"
    fi
  } > "${MIHOMO_DIR}/run-argo.sh"
  chmod 700 "${MIHOMO_DIR}/run-argo.sh"
}

_start_service() {
  local name="$1"
  case "$INIT_SYSTEM" in
    systemd) systemctl start "$name" ;;
    openrc)  rc-service "$name" start ;;
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
    _stop_service "$ARGO_SERVICE_NAME"; _start_service "$ARGO_SERVICE_NAME"
  fi
  # 启动后存活校验：mihomo -t 查不出 psk 之类的运行期 listen 错误，用进程状态兜底
  sleep 2
  if ! _service_active "$SERVICE_NAME"; then
    _error "核心启动失败，最近日志："
    [ "$INIT_SYSTEM" = "systemd" ] && journalctl -u ${SERVICE_NAME} -n 3 --no-pager | grep -i error || tail -n 3 "${CORE_LOG}"
    return 1
  fi
  _success "服务已重启。"
}

# ---------------- 节点添加 ----------------
_ask_port() {
  local prompt="$1" default="$2" p
  read -rp "${prompt} [${default}]: " p
  p="${p:-$default}"
  if _check_port_conflict "$p"; then return 1; fi
  ASK_PORT_RESULT="$p"
}

# [1] VLESS + Reality + Vision
_add_vless_reality() {
  _ask_port "请输入 VLESS-Reality 端口" 443 || return 1
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
  local node
  node=$(jq -cn --arg tag "vless-r-${port}" --arg name "VLESS-Reality-${port}" --arg port "$port" \
    --arg uuid "$uuid" --arg pk "$pk" --arg pub "$pub" --arg sid "$sid" --arg sni "$sni" --arg dec "$enc" \
    '{tag:$tag,name:$name,proto:"vless-reality",port:($port|tonumber),uuid:$uuid,private_key:$pk,public_key:$pub,short_id:$sid,sni:$sni,decryption:(if $dec=="" then null else $dec end)}')
  _add_node_meta "$node"
  _regen_config; _restart_all; _show_links
}

# [2] Hysteria2
_add_hysteria2() {
  _ask_port "请输入 Hysteria2 端口 (UDP)" 8443 || return 1
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
  local node
  node=$(jq -cn --arg tag "hy2-${port}" --arg name "HY2-${port}" --arg port "$port" --arg pass "$pass" \
    --arg obfs "$obfs" --arg obfp "$obfp" --arg crt "$crt" --arg key "$key" --arg sni "$sni" --arg masq "$masq" \
    '{tag:$tag,name:$name,proto:"hysteria2",port:($port|tonumber),password:$pass,obfs:$obfs,obfs_password:$obfp,cert:$crt,key:$key,sni:$sni,masquerade:(if $masq=="" then null else $masq end)}')
  _add_node_meta "$node"
  _regen_config; _restart_all; _show_links
}

# [3] TUIC v5
_add_tuic() {
  _ask_port "请输入 TUIC v5 端口 (UDP)" 8444 || return 1
  local port="$ASK_PORT_RESULT" sni uuid pass
  sni=$(_pick_sni)
  read -rp "SNI [${sni}]: " s; sni="${s:-$sni}"
  uuid=$(_gen_uuid); pass=$(_gen_hex 16)
  read -rp "认证密码 [${pass}]: " p; pass="${p:-$pass}"
  local ck; ck=$(_gen_selfsigned_cert "$sni" "tuic-${port}") || return 1
  local node
  node=$(jq -cn --arg tag "tuic-${port}" --arg name "TUIC-${port}" --arg port "$port" \
    --arg uuid "$uuid" --arg pass "$pass" --arg crt "${ck%%|*}" --arg key "${ck##*|}" --arg sni "$sni" \
    '{tag:$tag,name:$name,proto:"tuic",port:($port|tonumber),uuid:$uuid,password:$pass,cert:$crt,key:$key,sni:$sni}')
  _add_node_meta "$node"
  _regen_config; _restart_all; _show_links
}

# [4] AnyTLS
_add_anytls() {
  _ask_port "请输入 AnyTLS 端口" 8445 || return 1
  local port="$ASK_PORT_RESULT" sni user pass
  sni=$(_pick_sni)
  read -rp "SNI [${sni}]: " s; sni="${s:-$sni}"
  user="u1"; pass=$(_gen_hex 16)
  read -rp "认证密码 [${pass}]: " p; pass="${p:-$pass}"
  local ck; ck=$(_gen_selfsigned_cert "$sni" "anytls-${port}") || return 1
  local node
  node=$(jq -cn --arg tag "anytls-${port}" --arg name "AnyTLS-${port}" --arg port "$port" \
    --arg user "$user" --arg pass "$pass" --arg crt "${ck%%|*}" --arg key "${ck##*|}" --arg sni "$sni" \
    '{tag:$tag,name:$name,proto:"anytls",port:($port|tonumber),username:$user,password:$pass,cert:$crt,key:$key,sni:$sni}')
  _add_node_meta "$node"
  _regen_config; _restart_all; _show_links
}

# [5] Mieru
_add_mieru() {
  _ask_port "请输入 Mieru 端口" 29101 || return 1
  local port="$ASK_PORT_RESULT" user pass transport
  read -rp "传输层 TCP/UDP [TCP]: " t; transport="${t^^}"; [[ "$transport" == "UDP" ]] || transport="TCP"
  user="u1"; pass=$(_gen_hex 16)
  read -rp "认证密码 [${pass}]: " p; pass="${p:-$pass}"
  local node
  node=$(jq -cn --arg tag "mieru-${port}" --arg name "Mieru-${port}" --arg port "$port" \
    --arg user "$user" --arg pass "$pass" --arg tr "$transport" \
    '{tag:$tag,name:$name,proto:"mieru",port:($port|tonumber),username:$user,password:$pass,transport:$tr}')
  _add_node_meta "$node"
  _regen_config; _restart_all; _show_links
}

# [6] Shadowsocks 2022
_add_ss2022() {
  _ask_port "请输入 SS2022 端口" 8388 || return 1
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
  local node
  node=$(jq -cn --arg tag "ss-${port}" --arg name "SS2022-${port}" --arg port "$port" \
    --arg cipher "$cipher" --arg pass "$pass" \
    '{tag:$tag,name:$name,proto:"ss2022",port:($port|tonumber),cipher:$cipher,password:$pass}')
  _add_node_meta "$node"
  _regen_config; _restart_all; _show_links
}

# [7] Trojan + Reality
_add_trojan_reality() {
  _ask_port "请输入 Trojan-Reality 端口" 8446 || return 1
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
  local node
  node=$(jq -cn --arg tag "trojan-r-${port}" --arg name "Trojan-Reality-${port}" --arg port "$port" \
    --arg pass "$pass" --arg pk "$pk" --arg pub "$pub" --arg sid "$sid" --arg sni "$sni" \
    '{tag:$tag,name:$name,proto:"trojan-reality",port:($port|tonumber),password:$pass,private_key:$pk,public_key:$pub,short_id:$sid,sni:$sni}')
  _add_node_meta "$node"
  _regen_config; _restart_all; _show_links
}

# ---------------- Argo 隧道节点 ----------------
# 说明：cloudflared 使用 --protocol auto，默认优先 QUIC，被墙/UDP 不通时自动回退 http2(TCP)

# 创建本机 WS 监听节点（Argo 回源用），供新隧道与复用已有隧道两条路径共用
_create_argo_ws_listener() {
  local proto
  echo "1) VLESS + WS  2) VMess + WS"
  read -rp "选择 Argo 节点协议 [1]: " c
  [[ "$c" = "2" ]] && proto="vmess-ws" || proto="vless-ws"
  _ask_port "本机 WS 监听端口 (Argo 回源端口, 仅 127.0.0.1)" 8001 || return 1
  local port="$ASK_PORT_RESULT" uuid path
  uuid=$(_gen_uuid)
  path="/$(_gen_hex 8)"
  local node
  node=$(jq -cn --arg tag "argo-${port}" --arg name "Argo-${proto}" --arg port "$port" \
    --arg proto "$proto" --arg uuid "$uuid" --arg path "$path" \
    '{tag:$tag,name:$name,proto:$proto,port:($port|tonumber),uuid:$uuid,ws_path:$path}')
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
  # ── 已有隧道检测（两层）────────────────────────────────
  # 第一层：本脚本管理的隧道（metadata.argo）
  local existing_mode existing_domain existing_port
  existing_mode=$(jq -r '.argo.mode // ""' "$METADATA_FILE")
  existing_domain=$(jq -r '.argo.domain // ""' "$METADATA_FILE")
  existing_port=$(jq -r '.argo.port // ""' "$METADATA_FILE")
  # 第二层：本机已由其他方式部署的 cloudflared 隧道（系统服务/独立进程）
  # 仅当本脚本没有自管隧道时才检测，避免两层同时提示
  local ext_src="" ext_conf="/etc/cloudflared/config.yml"
  if ! jq -e '.argo.enabled == true' "$METADATA_FILE" >/dev/null 2>&1; then
    # 本脚本痕迹（服务单元/启动脚本/pidfile）存在说明是自己的残留进程，不算外部隧道
    local our_trace=0
    { [ -f /etc/systemd/system/${ARGO_SERVICE_NAME}.service ] || [ -f /etc/init.d/${ARGO_SERVICE_NAME} ] || [ -f "${MIHOMO_DIR}/run-argo.sh" ] || [ -f "${MIHOMO_DIR}/argo.pid" ]; } && our_trace=1
    if [ "$our_trace" = "0" ]; then
      if systemctl is-active cloudflared >/dev/null 2>&1; then
        ext_src="systemd 服务 cloudflared"
      elif pgrep -f "cloudflared tunnel" >/dev/null 2>&1; then
        ext_src="独立 cloudflared 进程"
      elif [ -f "$ext_conf" ]; then
        ext_src="配置文件 ${ext_conf}"
      fi
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
  local proto mode token domain
  echo "1) VLESS + WS  2) VMess + WS"
  read -rp "选择 Argo 节点协议 [1]: " c
  [[ "$c" = "2" ]] && proto="vmess-ws" || proto="vless-ws"
  _ask_port "本机 WS 监听端口 (Argo 回源端口, 仅 127.0.0.1)" 8001 || return 1
  local port="$ASK_PORT_RESULT" uuid path
  uuid=$(_gen_uuid)
  path="/$(_gen_hex 8)"
  echo "1) 临时隧道 (trycloudflare.com, 域名随机)  2) 固定隧道 (Cloudflare Tunnel Token)"
  read -rp "选择隧道模式 [1]: " m
  if [[ "$m" = "2" ]]; then
    read -rp "粘贴 Cloudflare Tunnel Token: " token
    [ -z "$token" ] && { _error "Token 不能为空。"; return 1; }
    read -rp "固定隧道域名 (如 argo.example.com): " domain
    [ -z "$domain" ] && { _error "固定隧道必须填写域名。"; return 1; }
    mode="token"
    _info "面板路径: Zero Trust → Networks → Tunnels → 该隧道 → Public Hostname，Type=HTTP，URL=127.0.0.1:${port}"
  else
    mode="temp"; domain=""
    _info "临时隧道域名将在启动后自动探测。"
  fi
  # 按需安装：本机没有任何 cloudflared 时才下载，已有则复用
  _cloudflared_bin >/dev/null || install_cloudflared || return 1
  # 删除旧的 argo 节点（一个隧道只挂一个 ws 节点）
  jq -r '.nodes[]? | select(.proto == "vless-ws" or .proto == "vmess-ws") | .tag' "$METADATA_FILE" | while read -r t; do _del_node_meta "$t"; done
  local node
  node=$(jq -cn --arg tag "argo-${port}" --arg name "Argo-${proto}" --arg port "$port" \
    --arg proto "$proto" --arg uuid "$uuid" --arg path "$path" \
    '{tag:$tag,name:$name,proto:$proto,port:($port|tonumber),uuid:$uuid,ws_path:$path}')
  _add_node_meta "$node"
  # 更新 argo 状态
  local tmp="${METADATA_FILE}.tmp"
  jq --arg mode "$mode" --arg token "$token" --arg domain "$domain" --argjson port "$port" \
    '.argo = {enabled:true, mode:$mode, token:$token, domain:$domain, port:$port}' "$METADATA_FILE" > "$tmp" && mv "$tmp" "$METADATA_FILE"
  _write_argo_runner "$mode" "$token" "$port"
  _create_services
  _regen_config; _restart_all
  if [ "$mode" = "temp" ]; then
    _probe_temp_domain
  fi
  _show_links
}

# 探测临时隧道域名并写回 metadata（用于分享链接）
_probe_temp_domain() {
  _info "等待 Argo 临时隧道域名发布 (最长 30s)..."
  local domain=""
  for i in $(seq 1 30); do
    domain=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$ARGO_LOG" 2>/dev/null | tail -n1 | sed 's|https://||')
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

# 重新获取临时隧道（域名会变，链接随之更新）
_renew_temp_argo() {
  if [ "$(jq -r '.argo.mode // ""' "$METADATA_FILE")" != "temp" ]; then
    _warn "当前不是临时隧道模式。"; return 1
  fi
  : > "$ARGO_LOG"
  _stop_service "$ARGO_SERVICE_NAME"; _start_service "$ARGO_SERVICE_NAME"
  _probe_temp_domain
}

# ---------------- 节点删除 ----------------
_delete_node_menu() {
  local count
  count=$(jq '.nodes | length' "$METADATA_FILE" 2>/dev/null || echo 0)
  [ "$count" = "0" ] && { _warn "暂无节点。"; return; }
  echo "当前节点:"
  jq -r '.nodes | to_entries[] | "  \(.key+1)) [\(.value.proto)] \(.value.name)  端口:\(.value.port)"' "$METADATA_FILE"
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
  rm -f /usr/local/bin/ml
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
    _service_active "$ARGO_SERVICE_NAME" && _success "Argo 隧道运行中 (protocol=auto)" || _warn "Argo 隧道未运行"
    local d; d=$(jq -r '.argo.domain // ""' "$METADATA_FILE")
    [ -n "$d" ] && echo "Argo 域名: ${d}"
  fi
  local count; count=$(jq '.nodes | length // 0' "$METADATA_FILE" 2>/dev/null)
  echo "节点数量: ${count:-0}"
}

_show_menu() {
  echo ""
  echo -e "${GREEN}======== mihomo-lite 管理脚本 v${SCRIPT_VERSION} ========${NC}"
  echo " 1. 添加节点 (Reality/HY2/TUIC/AnyTLS/Mieru/SS2022/Trojan)"
  echo " 2. Argo 隧道管理 (添加/删除节点与隧道, protocol=auto QUIC优先)"
  echo " 3. 查看节点链接"
  echo " 4. 删除节点"
  echo " 5. 重启服务"
  echo " 6. 停止服务"
  echo " 7. 查看运行状态"
  echo " 8. 查看实时日志"
  echo " 9. 重新获取 Argo 临时隧道域名"
  echo "10. 安装/更新 mihomo 核心"
  echo "11. 卸载"
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
        if [ ! -x "$MIHOMO_BIN" ]; then
          _warn "检测到 mihomo 核心未安装。"
          read -rp "是否现在安装 mihomo 核心? [Y/n]: " ic
          if [[ ! "$ic" =~ ^[Nn]$ ]]; then
            install_core || { _error "核心安装失败，请检查网络后重试。"; continue; }
          else
            _warn "未安装核心，节点添加后将无法运行。"
          fi
        fi
        echo " 1) VLESS+Reality+Vision"
        echo " 2) Hysteria2"
        echo " 3) TUIC v5"
        echo " 4) AnyTLS"
        echo " 5) Mieru"
        echo " 6) SS2022"
        echo " 7) Trojan+Reality"
        echo " 0) 返回"
        read -rp "协议: " p
        case "$p" in
          1) _add_vless_reality ;; 2) _add_hysteria2 ;; 3) _add_tuic ;;
          4) _add_anytls ;; 5) _add_mieru ;; 6) _add_ss2022 ;;
          7) _add_trojan_reality ;;
          0) ;;
          *) _error "无效输入。" ;;
        esac
        ;;
      2)
        echo " 1) 添加 Argo 节点"
        echo " 2) 删除 Argo 节点 / Argo 隧道"
        echo " 0) 返回"
        read -rp "Argo 管理: " a || break
        case "$a" in
          1) _add_argo_node ;;
          2) _delete_argo_menu ;;
          0) ;;
          *) _error "无效输入。" ;;
        esac
        ;;
      3) _show_links ;;
      4) _delete_node_menu ;;
      5) _restart_all ;;
      6) _stop_service "$SERVICE_NAME"; _stop_service "$ARGO_SERVICE_NAME"; _success "已停止。" ;;
      7) _menu_status ;;
      8) _show_logs ;;
      9) _renew_temp_argo ;;
      10) install_core ;;
      11) _uninstall ;;
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
  mkdir -p "$MIHOMO_DIR" "$SUB_DIR" "$CERTS_DIR"
  # 生成直跑模式的 argo 启动脚本（若已有 argo 配置）
  if jq -e '.argo.enabled == true' "$METADATA_FILE" >/dev/null 2>&1; then
    local mode token port
    mode=$(jq -r '.argo.mode // "temp"' "$METADATA_FILE")
    token=$(jq -r '.argo.token // ""' "$METADATA_FILE")
    port=$(jq -r '.argo.port // 8001' "$METADATA_FILE")
    [ "$mode" = "temp" ] && token=""
    _write_argo_runner "$mode" "$token" "$port"
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
