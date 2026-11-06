"""隔离加载 mihomo-lite.sh 的函数做契约测试。

run_shell 移除脚本入口 main 调用后以 bash 执行注入的 body；
所有状态文件重定向到临时目录,不触碰真实安装路径与服务。
"""
import json
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "mihomo-lite.sh"


def run_shell(body, metadata=None, files=None, stdin=""):
    source = SCRIPT.read_text()
    lines = source.rstrip().splitlines()
    assert lines[-1].startswith("main"), "入口改动时须重新检查隔离方式"
    source = "\n".join(lines[:-1])
    with tempfile.TemporaryDirectory(prefix="mihomo-lite-test-") as folder:
        root = Path(folder)
        (root / "metadata.json").write_text(json.dumps(metadata or {}))
        for name, content in (files or {}).items():
            (root / name).write_text(content)
        setup = f'''
AUDIT_DIR={shlex.quote(folder)}
APP_DIR="$AUDIT_DIR"; MIHOMO_DIR="$AUDIT_DIR"; SUB_DIR="$AUDIT_DIR"
METADATA_FILE="$AUDIT_DIR/metadata.json"
CONFIG_FILE="$AUDIT_DIR/config.yaml"; CONFIG_JSON="$AUDIT_DIR/server.json"
RUNTIME_DIR="$AUDIT_DIR/run"; ARGO_LOG="$AUDIT_DIR/argo.log"
CORE_LOG="$AUDIT_DIR/core.log"; CERTS_DIR="$AUDIT_DIR"
_info() {{ :; }}; _success() {{ :; }}; _warn() {{ :; }}
sleep() {{ :; }}
'''
        command = source + "\n" + setup + "\n" + body
        result = subprocess.run(["bash", "-c", command], input=stdin,
                                text=True, capture_output=True, timeout=15)
        if result.returncode:
            raise AssertionError(f"隔离命令 exit={result.returncode}\n{result.stderr}\n{result.stdout}")
        return result.stdout
