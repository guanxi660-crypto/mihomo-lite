#!/bin/bash
# 探测 mihomo v1.19.33 实际支持的 listeners 类型(用 -t 配置校验判定)
D=/tmp/probe; rm -rf $D; mkdir -p $D
for t in snell sudoku trusttunnel shadowquic anytls mieru vless vmess hysteria2 tuic; do
cat > $D/c.yaml <<YAML
mixed-port: 17890
listeners:
  - name: t1
    type: $t
    port: 29999
    listen: 127.0.0.1
YAML
out=$(mihomo -t -d $D -f $D/c.yaml 2>&1)
if echo "$out" | grep -qiE "configuration test is successful|success"; then
  echo "$t : 支持"
else
  echo "$t : 不支持 -> $(echo "$out" | head -2 | tr '\n' ' ' | cut -c1-140)"
fi
done
