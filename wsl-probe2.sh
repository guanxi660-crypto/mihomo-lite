#!/bin/bash
D=/tmp/probe2; rm -rf $D; mkdir -p $D
for t in snell sudoku trusttunnel shadowquic anytls mieru vless vmess hysteria2 tuic ss trojan; do
cat > $D/c.yaml <<YAML
mixed-port: 17890
listeners:
  - name: t1
    type: $t
    port: 29999
    listen: 127.0.0.1
YAML
out=$(mihomo -t -d $D -f $D/c.yaml 2>&1 | grep -viE "^time=.*level=info" | head -3 | tr '\n' ' ')
echo "$t => ${out:0:160}"
done
