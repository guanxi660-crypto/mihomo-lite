"""回归契约:临时域名续期、双栈 v6 监听、UDP 端口冲突、节点名 YAML 转义。

对应外部审计编号 M1/M2/M3/M4;运行方式:
    bash -c 'cd tests && python3 -m unittest test_mihomo -v'
"""
import json
import socket
import unittest
from shell_harness import run_shell


class MihomoContracts(unittest.TestCase):
    def test_temporary_domain_refresh_updates_existing_node(self):
        metadata = {"argo": {"domain": "old.trycloudflare.com"}, "nodes": [
            {"proto": "vless-ws", "argo_domain": "old.trycloudflare.com"}]}
        out = run_shell('_build_links() { :; }; _probe_temp_domain; cat "$METADATA_FILE"',
                        metadata, {"argo.log": "https://new-audit.trycloudflare.com\n"})
        actual = json.loads(out)
        self.assertEqual(actual["argo"]["domain"], "new-audit.trycloudflare.com")
        self.assertEqual(actual["nodes"][0]["argo_domain"], "new-audit.trycloudflare.com")

    def test_dual_stack_ipv6_node_has_ipv6_listener(self):
        node = {"tag": "audit", "name": "audit", "proto": "mieru", "port": 32123,
                "ip_ver": "v6", "username": "test", "password": "test", "transport": "TCP"}
        out = run_shell('''
ip() { printf 'inet 192.0.2.1/24\ninet6 2001:db8::1/64\n'; }
_get_ip6() { echo 2001:db8::1; }
_build_links() { :; }
_regen_config
cat "$CONFIG_FILE"
''', {"nodes": [node]})
        self.assertIn("listen: ::", out)

    def test_udp_port_inside_range_is_rejected(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
            out = run_shell(f'''
if _validate_range "{port - 1}-{port + 1}"; then echo ACCEPT; else echo REJECT; fi
''', {"nodes": []})
        self.assertEqual(out.strip(), "REJECT")

    def test_quoted_name_round_trips_in_clash_yaml(self):
        node = {"tag": "audit", "name": 'TW "home"', "proto": "mieru", "port": 32123,
                "ip_ver": "v4", "username": "test", "password": "test", "transport": "TCP"}
        out = run_shell('''
_get_public_ip() { echo 192.0.2.1; }
_resolve_node_ip() { echo 192.0.2.1; }
_build_links
cat "$SUB_DIR/clash.yaml"
''', {"nodes": [node]})
        # JSON 字符串是 YAML 的合法子集;双引号形式必须保留内嵌引号的转义。
        # 存量 metadata(升级前写入的引号名)不经过 _normalize_name,输出端必须转义。
        name_line = next(line for line in out.splitlines() if "- name:" in line)
        self.assertEqual(json.loads(name_line.split(": ", 1)[1]), node["name"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
