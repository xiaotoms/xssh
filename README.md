# 免费节点订阅生成器 proxy_hub

免费公开节点聚合 + TCP 测活 + IP 归属分类，自动生成 v2rayN / Clash.Meta 订阅。

## 用法

```bash
# 本地完整流程（拉取→解析→测活→归属→分类→生成订阅）
python proxy_hub.py --out subs --limit 8000

# 跳过测活，快速出全量订阅（节点会多但可能含失效）
python proxy_hub.py --out subs --skip-test

# 限制测活节点数
python proxy_hub.py --out subs --limit 3000
```

依赖：`requests`、`pyyaml`（可选，无 pyyaml 时 Clash 输出降级为手拼 YAML）。

## 产出文件

| 文件 | 内容 |
|---|---|
| `sub-all.txt` | 全部存活节点（base64 订阅，v2rayN 可直接导入） |
| `sub-residential.txt` | 住宅 IP 粗筛（base64 订阅） |
| `clash-all.yaml` | Clash.Meta 全量配置 |
| `clash-residential.yaml` | Clash.Meta 住宅配置 |
| `sub-<cc>.txt` | 按国家分区的 base64 订阅（存活≥3 的自动生成） |
| `stats.json` | 本次运行的统计数据 |
| `README.md` | 自动生成的订阅说明 |

## GitHub Actions 自动刷新

仓库已含 `.github/workflows/update-subs.yml`：每天 UTC 02:00（北京时间 10:00）自动拉取、
测活、生成并把 `subs/` 提交回仓库。手机/电脑订阅固定 URL 即可：
`https://raw.githubusercontent.com/<你的用户名>/<仓库名>/main/subs/sub-all.txt`

## 安全提醒

- 免费节点来路不明，**只可用于测试**；登录任何账号前请勿使用。
- 住宅 IP 免费且存活的数量极少（本仓库实测千余存活节点中仅十几个命中粗筛），属正常现象。
- 源地址会定期失效，失效时到 `proxy_hub.py` 顶部 `SOURCES` 列表更新即可。