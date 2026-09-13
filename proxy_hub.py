# -*- coding: utf-8 -*-
"""
proxy_hub.py — 免费公开节点聚合 + 测活 + IP归属分类订阅生成器
流程：拉取源 -> 解析协议 -> 去重 -> TCP连通性测活 -> IP地理归属 -> 分类生成订阅
用法：
  python proxy_hub.py --out subs                 # 完整流程
  python proxy_hub.py --out subs --skip-test     # 跳过测活（快速出全量订阅）
  python proxy_hub.py --out subs --limit 3000    # 限制测活节点数
仅依赖 requests（Python 3.8+）。无云端 API 费用，地理查询用 ip-api 免费批量接口。
"""
import argparse
import base64
import concurrent.futures as cf
import json
import re
import socket
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs, unquote

import requests

# ====== 源列表（2026-09-13 实测可用；失效源已剔除）======
SOURCES = [
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/3inker/v2ray-subscription/main/subs/all_ru.txt",
]
SUPPORTED_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "hy2://")

# 机房/云厂商关键词（用于"住宅"粗筛，基于 IP 归属的 org/isp/as 文本）
DATACENTER_HINTS = re.compile(
    r"(amazon|amazonis|microsoft|azure|google llc|google cloud|oracle|cloudflare|cdn|"
    r"hetzner|ovh|digitalocean|vultr|linode|akeyfi|akamai|fastly|digital ocean|"
    r"hosting|servers|data ?center|hostinger|contabo|ionos|scaleway|upcloud|"
    r"choopa|buyvm|rackspawn|serverpoint|psychz|nexa|%20technologies|equinix|"
    r"tencent|alibaba|huawei|bytedance|cloud|gcore|bunny|jch|selectel|timeweb)",
    re.I,
)
# 已知机房 ASN（补充判断）
DATACENTER_ASNS = {
    13335, 14061, 16509, 14061, 20473, 9009, 24940, 16276, 20069, 63949,
    14061, 46606, 54856, 36351, 20473, 8100, 198605, 212429, 202425,
}


def log(msg):
    print(msg, flush=True)


# ---------------- 拉取与解析 ----------------

def fetch_all(limit_per_source=20000):
    lines, seen_raw = [], set()
    for src in SOURCES:
        try:
            r = requests.get(src, timeout=25, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code != 200:
                log(f"[源跳过] {r.status_code} {src}")
                continue
            n = 0
            for ln in r.text.splitlines():
                ln = ln.strip()
                if ln.startswith(SUPPORTED_SCHEMES) and ln not in seen_raw:
                    seen_raw.add(ln)
                    lines.append(ln)
                    n += 1
                    if n >= limit_per_source:
                        break
            log(f"[源OK] {n} 条  {src}")
        except Exception as e:
            log(f"[源失败] {src} -> {e}")
    return lines


def parse_vmess(url):
    body = url[len("vmess://"):]
    # 兼容标准 base64 与 uuid@host 风格
    try:
        data = json.loads(base64.b64decode(body + "=" * (-len(body) % 4)))
        return {
            "type": "vmess", "server": data.get("add", ""), "port": int(data.get("port", 0)),
            "uuid": data.get("id", ""), "aid": data.get("aid", "0"), "security": data.get("scy", "auto"),
            "net": data.get("net", "tcp"), "host": data.get("host", ""), "path": data.get("path", ""),
            "tls": data.get("tls", ""), "sni": data.get("sni", ""), "name": data.get("ps", ""),
        }
    except Exception:
        return None


def parse_generic(url, scheme):
    try:
        u = urlparse(url)
        server = u.hostname or ""
        port = u.port or 443
        user = unquote(u.username or "")
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        name = unquote(u.fragment) if u.fragment else f"{scheme}-{server}"
        d = {
            "type": scheme, "server": server, "port": port, "name": name,
            "net": q.get("type") or q.get("net") or "tcp",
            "host": q.get("host", ""), "path": unquote(q.get("path", "")),
            "tls": "tls" if q.get("security") in ("tls", "insecur") or scheme == "hy2" else "",
            "sni": q.get("sni", ""), "insecure": q.get("insecure", "0"),
        }
        if scheme in ("vless", "trojan"):
            d["uuid"] = user
        elif scheme == "ss":
            # ss://base64(method:password)@host 或 ss://method:password@host
            if "@" in u.netloc:
                cred = unquote(u.netloc.split("@")[0])
                if ":" not in cred:
                    try:
                        cred = base64.b64decode(cred + "=" * (-len(cred) % 4)).decode()
                    except Exception:
                        return None
                m, _, p = cred.partition(":")
                d["method"], d["password"] = m, p
                d["uuid"] = p
            else:
                return None
        elif scheme == "hy2":
            d["uuid"] = user
            d["sni"] = d["sni"] or server
        return d if server and port else None
    except Exception:
        return None


def parse_line(url):
    if url.startswith("vmess://"):
        return parse_vmess(url)
    scheme = url.split("://")[0]
    return parse_generic(url, scheme)


# ---------------- 测活（TCP 连通性） ----------------

def tcp_alive(node, timeout=3.0):
    try:
        with socket.create_connection((node["server"], node["port"]), timeout=timeout):
            return True
    except Exception:
        return False


def test_nodes(nodes, workers=400, limit=None):
    pool = nodes[:limit] if limit else nodes
    log(f"[测活] 开始 TCP 测活 {len(pool)} 个节点，并发 {workers} ...")
    alive = []
    t0 = time.time()
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        results = ex.map(tcp_alive, pool)
        for node, ok in zip(pool, results):
            if ok:
                alive.append(node)
    log(f"[测活] 存活 {len(alive)}/{len(pool)}（{time.time()-t0:.0f}s）")
    return alive, pool


# ---------------- IP 归属（ip-api 免费批量，100 IP/请求） ----------------

def geo_ips(ips):
    """返回 {ip: info_dict}；失败返回空。ip-api 免费批量接口按请求顺序返回，用索引配对。"""
    out = {}
    ips = list({i for i in ips if i})
    fields = "status,country,countryCode,isp,org,as,asname,proxy,mobile,hosting"
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        try:
            r = requests.post(
                "http://ip-api.com/batch",
                json=[{"query": ip, "fields": fields} for ip in chunk],
                timeout=30,
            )
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, dict):  # 错误响应
                    log(f"[geo错误响应] {str(data)[:120]}")
                else:
                    for ip, item in zip(chunk, data):
                        if isinstance(item, dict) and item.get("status") == "success":
                            out[ip] = item
            time.sleep(1.4)  # 免费限频 45 req/min
        except Exception as e:
            log(f"[geo失败] chunk {i}: {e}")
    return out


def is_residential(info):
    """住宅粗筛：非机房、非代理标注、非云厂商；宁可误杀不误放。"""
    if not info:
        return False
    if info.get("hosting") or info.get("proxy") or info.get("mobile"):
        return False
    org_text = " ".join(str(info.get(k, "")) for k in ("isp", "org", "as", "asname"))
    if DATACENTER_HINTS.search(org_text):
        return False
    m = re.search(r"AS(\d+)", str(info.get("as", "")))
    if m and int(m.group(1)) in DATACENTER_ASNS:
        return False
    return True


# ---------------- 输出 ----------------

def to_vmess_url(n):
    d = {"v": "2", "ps": n["name"], "add": n["server"], "port": str(n["port"]), "id": n["uuid"],
         "aid": str(n.get("aid", "0")), "scy": n.get("security", "auto"), "net": n.get("net", "tcp"),
         "type": "none", "host": n.get("host", ""), "path": n.get("path", ""),
         "tls": n.get("tls", "") or "", "sni": n.get("sni", "")}
    return "vmess://" + base64.b64encode(json.dumps(d, ensure_ascii=False).encode()).decode()


def node_url(n):
    if n["type"] == "vmess":
        return to_vmess_url(n)
    return n.get("raw") or ""


def b64_sub(urls):
    return base64.b64encode("\n".join(urls).encode()).decode()


def build_clash(nodes):
    """Clash.Meta 风格 YAML 输出。"""
    proxies = []
    for n in nodes:
        base = {"name": n["name"][:60], "server": n["server"], "port": n["port"]}
        t = n["type"]
        if t == "vless":
            p = {**base, "type": "vless", "uuid": n["uuid"], "udp": True,
                 "network": n.get("net") or "tcp"}
            if n.get("tls"):
                p["tls"] = True
                p["servername"] = n.get("sni") or n["server"]
                p["client-fingerprint"] = "chrome"
            if p["network"] == "ws":
                p["ws-opts"] = {"path": n.get("path") or "/",
                                "headers": {"Host": n.get("host") or n["server"]}}
            proxies.append(p)
        elif t == "trojan":
            p = {**base, "type": "trojan", "password": n["uuid"], "udp": True}
            if n.get("tls"):
                p["tls"] = True
                p["servername"] = n.get("sni") or n["server"]
            if (n.get("net") or "") == "ws":
                p["network"] = "ws"
                p["ws-opts"] = {"path": n.get("path") or "/",
                                "headers": {"Host": n.get("host") or n["server"]}}
            proxies.append(p)
        elif t == "vmess":
            p = {**base, "type": "vmess", "uuid": n["uuid"], "cipher": n.get("security") or "auto",
                 "udp": True, "network": n.get("net") or "tcp"}
            if n.get("tls"):
                p["tls"] = True
                p["servername"] = n.get("sni") or n["server"]
            proxies.append(p)
        elif t == "ss":
            proxies.append({**base, "type": "ss", "cipher": n.get("method", "aes-256-gcm"),
                            "password": n.get("password", ""), "udp": True})
        elif t == "hy2":
            proxies.append({**base, "type": "hysteria2", "password": n["uuid"], "obfs": "salamander",
                            "obfs-password": "disabled", "sni": n.get("sni") or n["server"],
                            "skip-cert-verify": True})
    try:
        import yaml
        return "proxies:\n" + yaml.safe_dump(proxies, allow_unicode=True, sort_keys=False)
    except ImportError:
        # 无 yaml 库时手拼最小可用输出
        def dump(p):
            lines = [f"  - name: \"{p['name']}\"", f"    type: {p['type']}",
                     f"    server: {p['server']}", f"    port: {p['port']}"]
            for k, v in p.items():
                if k in ("name", "type", "server", "port"):
                    continue
                if isinstance(v, dict):
                    lines.append(f"    {k}:")
                    for kk, vv in v.items():
                        if isinstance(vv, dict):
                            lines.append(f"      {kk}:")
                            for k2, v2 in vv.items():
                                lines.append(f"        {k2}: {json.dumps(v2, ensure_ascii=False)}")
                        else:
                            lines.append(f"      {kk}: {json.dumps(vv, ensure_ascii=False)}")
                else:
                    lines.append(f"    {k}: {json.dumps(v, ensure_ascii=False)}")
            return "\n".join(lines)
        return "proxies:\n" + "\n".join(dump(p) for p in proxies) + "\n"


def cc_flag(cc):
    if not cc or len(cc) != 2:
        return "🏳️"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc.upper())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="subs", help="输出目录")
    ap.add_argument("--skip-test", action="store_true", help="跳过TCP测活")
    ap.add_argument("--limit", type=int, default=8000, help="最多测活节点数")
    ap.add_argument("--geo", action="store_true", default=True, help="对存活节点做IP归属查询")
    args = ap.parse_args()

    t0 = time.time()
    raw_lines = fetch_all()
    if not raw_lines:
        log("没有任何源可用，退出。")
        sys.exit(1)

    nodes, seen_key = [], set()
    for ln in raw_lines:
        n = parse_line(ln)
        if not n:
            continue
        n["raw"] = ln
        key = (n["type"], n["server"], n["port"], n.get("uuid", ""))
        if key in seen_key:
            continue
        seen_key.add(key)
        nodes.append(n)
    log(f"[解析] 共 {len(nodes)} 个去重节点")

    if args.skip_test:
        alive, pool = nodes, nodes
    else:
        alive, pool = test_nodes(nodes, limit=args.limit)

    geo = {}
    if args.geo:
        # 只查询存活节点，避免浪费限频额度
        n_uniq = len({n['server'] for n in alive})
        log(f"[归属] 查询存活节点 {n_uniq} 个服务端 IP ...")
        if n_uniq > 2000:
            log("[归属] IP 数量超过免费额度友好范围，仅查前 2000 个")
            alive.sort(key=lambda x: 0)  # 保持原序即可，此处仅截断查询
        geo = geo_ips([n["server"] for n in alive][:2000])

    # 分类
    for n in alive:
        info = geo.get(n["server"])
        n["cc"] = (info or {}).get("countryCode", "")
        n["country"] = (info or {}).get("country", "Unknown")
        n["residential"] = is_residential(info)

    by_cc = Counter(n["cc"] or "??" for n in alive)
    res_nodes = [n for n in alive if n["residential"]]
    log(f"[分类] 存活按国家 Top10: {by_cc.most_common(10)}")
    log(f"[分类] 住宅粗筛通过: {len(res_nodes)}")

    import os
    os.makedirs(args.out, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def write(name, text):
        with open(os.path.join(args.out, name), "w", encoding="utf-8") as f:
            f.write(text)
        log(f"[写出] {name}  ({len(text)} bytes)")

    all_urls = [node_url(n) for n in alive]
    write("all.txt", "\n".join(raw_lines_of_alive(alive)))
    write("sub-all.txt", b64_sub(all_urls))
    write("sub-residential.txt", b64_sub([node_url(n) for n in res_nodes]))
    write("clash-all.yaml", build_clash(alive))
    write("clash-residential.yaml", build_clash(res_nodes))

    # 国家专区（>=3 个存活节点的国家）
    for cc, cnt in by_cc.items():
        if cc == "??" or cnt < 3:
            continue
        sub = [n for n in alive if n["cc"] == cc]
        write(f"sub-{cc.lower()}.txt", b64_sub([node_url(n) for n in sub]))

    # 统计报告
    stat = {
        "generated": stamp,
        "sources": SOURCES,
        "fetched": len(raw_lines), "parsed": len(nodes),
        "tested": len(pool), "alive": len(alive),
        "alive_rate": f"{len(alive)/max(len(pool),1)*100:.1f}%",
        "residential": len(res_nodes),
        "top_countries": by_cc.most_common(15),
        "elapsed_sec": round(time.time() - t0, 1),
    }
    write("stats.json", json.dumps(stat, ensure_ascii=False, indent=2))
    readme = [f"# 免费节点订阅（自动生成 {stamp}）", "",
              "| 文件 | 内容 | 节点数 |", "|---|---|---|",
              f"| sub-all.txt | 全部存活节点(base64订阅) | {len(alive)} |",
              f"| sub-residential.txt | 住宅粗筛(base64订阅) | {len(res_nodes)} |",
              f"| clash-all.yaml | Clash.Meta 全量 | {len(alive)} |",
              f"| clash-residential.yaml | Clash.Meta 住宅 | {len(res_nodes)} |", ""]
    for cc, cnt in by_cc.most_common(20):
        if cc != "??" and cnt >= 3:
            name = next((n["country"] for n in alive if n["cc"] == cc), cc)
            readme.append(f"| sub-{cc.lower()}.txt | {cc_flag(cc)} {name} | {cnt} |")
    readme += ["", "> 免费节点稳定性无保证，请仅用于测试；登录敏感账号前请勿使用。"]
    write("README.md", "\n".join(readme))

    log(f"[完成] 用时 {time.time()-t0:.0f}s，产物在 {os.path.abspath(args.out)}")


def raw_lines_of_alive(nodes):
    return [n["raw"] for n in nodes]


if __name__ == "__main__":
    main()
