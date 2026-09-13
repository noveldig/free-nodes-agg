# -*- coding: utf-8 -*-
"""聚合免费节点：拉取多个订阅源 -> 解析为分享链接 -> 去重 -> 生成 v2ray 订阅。

输出：
  output/sub.txt        v2ray 订阅（base64 编码，导入客户端用）
  output/sub_plain.txt  明文链接版（调试用）
  output/stats.json     各源统计

用法：
  python merge.py                 # 直连源（GitHub Actions 内用）
  MIRROR=https://ghfast.top/ python merge.py   # 本地被墙时走镜像前缀
"""
import base64
import json
import os
import re
import ssl
import sys
import urllib.request
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

try:
    import yaml
except ImportError:
    yaml = None

ROOT = os.path.dirname(os.path.abspath(__file__))
SOURCES = os.path.join(ROOT, "sources.json")
OUT_DIR = os.path.join(ROOT, "output")
MIRROR = os.environ.get("MIRROR", "")          # 本地调试：URL 前缀镜像
TIMEOUT = int(os.environ.get("TIMEOUT", "20"))
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

LINK_RE = re.compile(
    r"^(?:vmess|vless|trojan|ss|ssr|hysteria2?|hy2|tuic)://", re.I)


def log(msg):
    print(msg, flush=True)


def fetch(url):
    if MIRROR and url.startswith("https://raw.githubusercontent.com/"):
        url = MIRROR + url
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
        return r.read()


# ---------------- v2ray 文本源 ----------------

def parse_v2ray(data, src_name, stats):
    """从文本/base64 中提取分享链接"""
    if isinstance(data, bytes):
        data = _decode_text(data)
    found = []
    # 整体或分块 base64：解码后逐行找链接
    for blob in _b64_candidates(data):
        try:
            text = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode(
                "utf-8", "ignore")
        except Exception:
            continue
        found += _extract_links(text)
    found += _extract_links(data)
    links = list(dict.fromkeys(found))  # 源内去重
    stats["sources"][src_name] = len(links)
    stats["ok"] += 1
    return links


def _decode_text(data):
    for enc in ("utf-8", "gbk"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "ignore")


def _b64_candidates(text):
    """疑似 base64 大块文本（订阅常见整页编码）"""
    cands = []
    for m in re.finditer(r"[A-Za-z0-9+/=\s]{200,}", text):
        blob = re.sub(r"\s+", "", m.group(0))
        if len(blob) % 4 == 0 or "=" in blob[-4:]:
            cands.append(blob)
    return cands


def _extract_links(text):
    out = []
    for line in text.splitlines():
        line = line.strip().strip('"')
        if LINK_RE.match(line):
            out.append(line)
    return out


# ---------------- clash 源 -> 分享链接 ----------------

def parse_clash(data, src_name, stats):
    if yaml is None:
        log("  [WARN] 未安装 pyyaml，跳过 clash 源 %s" % src_name)
        return []
    text = data.decode("utf-8", "ignore") if isinstance(data, bytes) else data
    try:
        doc = yaml.safe_load(text)
    except Exception as e:
        log("  [WARN] %s 解析失败: %s" % (src_name, e))
        return []
    proxies = (doc or {}).get("proxies") or []
    links = []
    for p in proxies:
        link = _clash_to_link(p)
        if link:
            links.append(link)
    # clash 也可能内嵌 provider 引用的分享链接文本，顺带提取
    links += _extract_links(text)
    links = list(dict.fromkeys(links))
    stats["sources"][src_name] = len(links)
    stats["ok"] += 1
    return links


def _b64s(s):
    return base64.b64encode(str(s).encode("utf-8")).decode("ascii")


def _clash_to_link(p):
    t = (p.get("type") or "").lower()
    server, port = p.get("server"), p.get("port")
    if not server or not port:
        return None
    name = quote(str(p.get("name") or server), safe="")
    tls = str(p.get("tls") or "").lower() in ("true", "tls", "reality")
    net = p.get("network") or "tcp"
    sni = p.get("servername") or p.get("sni") or p.get("peer") or ""
    ws = p.get("ws-opts") or {}
    grpc = p.get("grpc-opts") or {}
    q = {}
    if net and net != "tcp":
        q["type"] = net
    if tls:
        q["security"] = "tls"
    if sni:
        q["sni"] = sni
    if net == "ws":
        q["path"] = (ws.get("path") or "/")
        host = (ws.get("headers") or {}).get("Host")
        if host:
            q["host"] = host
    elif net == "grpc":
        sn = (grpc.get("grpc-service-name") or "")
        if sn:
            q["serviceName"] = sn
    if p.get("client-fingerprint"):
        q["fp"] = p["client-fingerprint"]
    if p.get("skip-cert-verify"):
        q["allowInsecure"] = "1"
    qs = ("?" + urlencode(q)) if q else ""

    if t == "ss":
        cipher, pwd = p.get("cipher") or "aes-256-gcm", p.get("password") or ""
        userinfo = _b64s("%s:%s" % (cipher, pwd))
        plugin = p.get("plugin")
        extra = ""
        if plugin:
            opts = ",".join("%s=%s" % (k, v) for k, v in
                            (p.get("plugin-opts") or {}).items())
            extra = "?plugin=%s" % quote("%s;%s" % (plugin, opts), safe="")
        return "ss://%s@%s:%s%s%s#%s" % (userinfo, server, port, extra,
                                         _keep_fragment_qs(qs) if not extra else "",
                                         name)
    if t == "vmess":
        j = {"v": "2", "ps": p.get("name") or server, "add": server,
             "port": str(port), "id": p.get("uuid") or "",
             "aid": str(p.get("alterId") or 0),
             "scy": p.get("cipher") or "auto", "net": net,
             "type": "none", "host": (ws.get("headers") or {}).get("Host", ""),
             "path": (ws.get("path") or "") if net == "ws" else
                     (grpc.get("grpc-service-name") or ""),
             "tls": "tls" if tls else "", "sni": sni,
             "alpn": ",".join(p.get("alpn") or [])}
        return "vmess://" + _b64s(json.dumps(j, ensure_ascii=False,
                                             separators=(",", ":")))
    if t == "vless":
        if p.get("reality-opts"):
            q["security"] = "reality"
            q["pbk"] = p["reality-opts"].get("public-key", "")
            if p["reality-opts"].get("short-id"):
                q["sid"] = p["reality-opts"]["short-id"]
        if p.get("flow"):
            q["flow"] = p["flow"]
        qs = ("?" + urlencode(q)) if q else ""
        return "vless://%s@%s:%s%s#%s" % (p.get("uuid"), server, port, qs, name)
    if t == "trojan":
        return "trojan://%s@%s:%s%s#%s" % (
            quote(str(p.get("password") or ""), safe=""), server, port, qs, name)
    if t in ("hysteria2", "hy2"):
        q2 = {}
        if sni:
            q2["sni"] = sni
        if p.get("skip-cert-verify"):
            q2["insecure"] = "1"
        if p.get("obfs"):
            q2["obfs"] = p["obfs"]
            if p.get("obfs-password"):
                q2["obfs-password"] = p["obfs-password"]
        qs2 = ("?" + urlencode(q2)) if q2 else ""
        return "hysteria2://%s@%s:%s%s#%s" % (
            quote(str(p.get("password") or p.get("auth") or ""), safe=""),
            server, port, qs2, name)
    if t == "tuic":
        qq = {"sni": sni} if sni else {}
        if p.get("congestion-controller"):
            qq["congestion_control"] = p["congestion-controller"]
        qs3 = ("?" + urlencode(qq)) if qq else ""
        return "tuic://%s:%s@%s:%s%s#%s" % (
            p.get("uuid"), quote(str(p.get("password") or ""), safe=""),
            server, port, qs3, name)
    if t == "ssr":
        raw = "%s:%s:%s:%s:%s:%s" % (
            server, port, p.get("protocol") or "origin",
            p.get("cipher") or "aes-256-cfb", p.get("obfs") or "plain",
            _b64s(p.get("password") or ""))
        tail = ""
        if p.get("obfs-param"):
            tail += "/?obfsparam=" + _b64s(p["obfs-param"])
        if p.get("protocol-param"):
            tail += ("&" if "?" in tail else "/?") + \
                "protoparam=" + _b64s(p["protocol-param"])
        return "ssr://" + _b64s(raw + tail)
    return None  # 不支持的类型

def _keep_fragment_qs(qs):
    """URI 型 ss 不需要 clash 风格 query，保留会破坏格式；丢弃"""
    return ""


# ---------------- 去重 ----------------

def dedup_key(link):
    scheme, _, rest = link.partition("://")
    scheme = scheme.lower()
    if scheme == "vmess":
        try:
            j = json.loads(base64.b64decode(
                rest + "=" * (-len(rest) % 4)).decode("utf-8", "ignore"))
            return "vmess|%s|%s|%s|%s|%s|%s" % (
                j.get("add"), j.get("port"), j.get("id"),
                j.get("scy") or j.get("security"), j.get("net"),
                j.get("path") or j.get("host") or "")
        except Exception:
            return link
    if "#" in rest:
        rest = rest.split("#", 1)[0]
    if "?" in rest:
        path, _, q = rest.partition("?")
        q = "&".join(sorted(q.split("&")))
        rest = path + "?" + q
    return "%s|%s" % (scheme, rest.lower())


# ---------------- 主流程 ----------------

def main():
    with open(SOURCES, encoding="utf-8") as f:
        sources = json.load(f)
    stats = {"sources": {}, "ok": 0, "fail": 0, "total_links": 0,
             "unique_links": 0, "by_scheme": {}}
    all_links = []
    log("== 拉取 %d 个源 ==" % len(sources))
    for s in sources:
        name, url, typ = s["name"], s["url"], s["type"]
        try:
            data = fetch(url)
            if typ == "clash":
                links = parse_clash(data, name, stats)
            else:
                links = parse_v2ray(data, name, stats)
            log("  [OK] %-28s %5d 链接" % (name, len(links)))
            all_links += links
        except Exception as e:
            stats["fail"] += 1
            stats["sources"][name] = 0
            log("  [FAIL] %-26s %s" % (name, e))

    # 全局去重
    seen = {}
    for link in all_links:
        seen.setdefault(dedup_key(link), link)
    unique = sorted(seen.values(), key=lambda x: (x.split("://")[0], x))

    for link in unique:
        sch = link.split("://")[0].lower()
        stats["by_scheme"][sch] = stats["by_scheme"].get(sch, 0) + 1
    stats["total_links"] = len(all_links)
    stats["unique_links"] = len(unique)

    os.makedirs(OUT_DIR, exist_ok=True)
    body = "\n".join(unique)
    with open(os.path.join(OUT_DIR, "sub.txt"), "w", encoding="utf-8") as f:
        f.write(base64.b64encode(body.encode("utf-8")).decode("ascii"))
    with open(os.path.join(OUT_DIR, "sub_plain.txt"), "w", encoding="utf-8") as f:
        f.write(body + "\n")
    with open(os.path.join(OUT_DIR, "stats.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)

    log("== 完成：总 %d -> 去重 %d（失败源 %d）==" % (
        stats["total_links"], stats["unique_links"], stats["fail"]))
    log("   协议分布: %s" % json.dumps(stats["by_scheme"], ensure_ascii=False))
    return 0 if unique else 1


if __name__ == "__main__":
    sys.exit(main())
