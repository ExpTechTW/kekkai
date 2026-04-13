# kekkai · 結界

高效能 L3/L4 邊緣防火牆（XDP/eBPF data plane + Go control plane）。
目標是用最小控制面、最早封包切入點，提供可熱重載、可觀測、可維運的 edge 防護。

`kekkai` 有兩個 binary：

- `kekkai-agent`：daemon（systemd 管理）
- `kekkai`：operator CLI + TUI

完整操作手冊（指令、systemd、排錯）請看：[`COMMAND_ZH.md`](COMMAND_ZH.md)

## 目前狀態

- 已完成：M1-M3、strict policy、CLI/TUI、doctor、installer
- 進行中路線：M4 NATS、M5 黑名單同步、M6 rate-limit/自動封鎖、M7 運維強化

## 快速開始

```bash
git clone git@github.com:ExpTechTW/kekkai.git
cd kekkai
bash ./kekkai.sh
```

安裝後建議流程：

```bash
sudo nano /etc/kekkai/kekkai.yaml
kekkai check
sudo kekkai reload
sudo kekkai status
```

> 所有指令細節（`status/check/ports/show/backup/reload/reset/doctor`）已移到 [`COMMAND_ZH.md`](COMMAND_ZH.md)。

## 過濾模型（Ingress）

目前預設是 strict model，封包判斷順序：

1. ARP（可配置）放行；其他非 IPv4 丟棄
2. IPv4 後續分片放行（無 L4 header 可檢查）
3. 回程流量放行（TCP ACK/RST/FIN、UDP ephemeral、ICMP 可配置）
4. static blocklist 命中丟棄
5. dynamic blocklist 命中丟棄
6. `filter.public.*` 放行
7. `filter.private.*` 只有 `ingress_allowlist` 可放行
8. 其餘 default deny

## 設定檔隔離（雙檔案）

- User config：`/etc/kekkai/kekkai.yaml`
- Agent managed（last-known-good）：`/etc/kekkai/kekkai.agent.yaml`

啟動時優先讀 managed 檔，managed 失效才回退 user config。
reload 成功後，agent 會更新 managed 檔，避免 user config 損毀導致重開機直接起不來。

## 核心特性

- XDP 在 ingress 熱路徑做 L3/L4 決策（低延遲、低 CPU）
- LPM blocklist/allowlist + port policy（public/private）
- 熱重載（SIGHUP）、emergency bypass
- 觀測：全域/協定/drop-pass reason/per-IP topN
- TUI：Overview / Detail / Top-N / Charts
- 配置：嚴格 schema 驗證、SSH lockout 防護、自動備份

## 專案結構（精簡）

```text
cmd/
  kekkai-agent/      daemon entry
  kekkai/            CLI + TUI entry
bpf/
  xdp_filter.c       XDP data plane
internal/
  config/            schema/defaults/validation/migration/backup
  loader/            eBPF 載入與 attach
  maps/              map wrappers
  stats/             stats reader
  tui/               Bubble Tea 視圖
  doctor/            健康檢查
deploy/systemd/
  kekkai-agent.service
```

## 建置需求

- Linux kernel 5.15+
- clang/llvm 14+
- Go 1.22+
- `libbpf-dev`

> BTF 非必要（目前不依賴 CO-RE）。

## 不在此 repo 的範圍

- Stateful conntrack / NAT
- L7 WAF 規則
- TLS 指紋
- ML 異常偵測

## 授權

待定。
