#!/usr/bin/env python3
"""验证例外白名单: git@github.com / example.com 豁免, 其他邮箱照常脱敏, 其他规则不受影响。
用法: python3 /root/maskit-verify-allow.py <zen_api_key> [--expect-allow] [--expect-deny]
"""
import json, re, sqlite3, sys, time, urllib.request

key = sys.argv[1]
BASE = "http://127.0.0.1:18712/v1/chat/completions"
DB = "file:/root/maskit-data/shield-events.sqlite3?mode=ro"
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))

PROBE = ("只回复'收到'。测试用例:"
         " 应豁免 git@github.com 与 ops@example.com;"
         " 应照常脱敏 real.person@corp-internal.com, 13800138000, 192.168.1.50, 10.9.9.9,"
         " sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX, fd00::5")

body = json.dumps({"model": "mimo-v2.6-flash-free", "messages": [{"role": "user", "content": PROBE}],
                   "max_tokens": 16, "stream": False}).encode()
t0 = time.time()
rq = urllib.request.Request(BASE, data=body, method="POST",
                            headers={"Content-Type": "application/json", "Authorization": "Bearer " + key})
with op.open(rq, timeout=120) as r:
    print("HTTP", r.status)

c = sqlite3.connect(DB, uri=True)
c.row_factory = sqlite3.Row
for r in c.execute("select id, payload from events where ts>=? and type='MASK' order by id", (t0 - 1,)):
    p = json.loads(r["payload"] or "{}")
    if "应豁免" not in (p.get("dialog") or ""):
        continue
    hits = {i.get("original"): i.get("label") for i in (p.get("items") or [])}
    print("事件 ev%s 命中 %d 项" % (r["id"], len(hits)))
    for k, v in hits.items():
        print("   打码:", v, "<-", k)
    allowed = ["git@github.com", "ops@example.com"]
    denied = ["real.person@corp-internal.com", "13800138000", "192.168.1.50", "10.9.9.9",
              "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX", "fd00::5"]
    print("豁免生效(应全部未命中):", [(a, a not in hits) for a in allowed])
    print("正常脱敏(应全部命中):", [(d, d in hits) for d in denied])
    break
else:
    print("没找到本次探测的 MASK 事件")
