# kekkai · 結界

高效能 L3/L4 邊緣防火牆（XDP/eBPF data plane + Go control plane）。
目標是用最小控制面、最早封包切入點，提供可熱重載、可觀測、可維運的 edge 防護。

`kekkai` 有兩個 binary：

- `kekkai-agent`：daemon（systemd 管理）
- `kekkai`：operator CLI + TUI

完整操作手冊（指令、systemd、排錯）請看：[`COMMAND_ZH.md`](COMMAND_ZH.md)

## 目前狀態

- 已完成：strict policy、CLI/TUI、doctor、installer/update、雙檔 config 隔離
- 已完成：hybrid stateful conntrack（ingress flowtrack + egress state seed）
- 進行中路線：NATS/黑名單同步、進階限速與運維指令補齊

## 快速開始

一鍵安裝（直接執行 GitHub raw 腳本）：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ExpTechTW/kekkai/main/kekkai.sh)
```

若要固定更新通道（例如 pre-release）：

```bash
KEKKAI_UPDATE_CHANNEL=pre-release bash <(curl -fsSL https://raw.githubusercontent.com/ExpTechTW/kekkai/main/kekkai.sh)
```

或用 repo 模式（開發者）：

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

> 注意：預設 `filter.ingress_allowlist` 會先放 `192.168.0.0/16` 避免初次啟動被 SSH 防呆擋住；請務必改成你的實際管理網段。

> 所有指令細節（`status/check/ports/show/backup/reload/bypass/update/reset/doctor`）已移到 [`COMMAND_ZH.md`](COMMAND_ZH.md)。  
> `kekkai update` 來源可由 `update.channel` 設為 `git:main` / `release` / `pre-release`。

GitHub Releases 會提供各平台檔案（`kekkai-*` 與 `kekkai-agent-*`）：
- `linux-amd64`
- `linux-arm64`
- `darwin-amd64`
- `darwin-arm64`

## 過濾模型（Ingress）

目前預設是 strict model，封包判斷順序：

1. ARP（可配置）放行；其他非 IPv4 丟棄
2. IPv4 後續分片放行（無 L4 header 可檢查）
3. conntrack hit 直接放行（stateful fast path）
4. 回程 fallback 放行（TCP ACK/RST/FIN、UDP ephemeral、ICMP 可配置）
5. static blocklist 命中丟棄
6. dynamic blocklist 命中丟棄
7. `filter.public.*` 放行
8. `filter.private.*` 只有 `ingress_allowlist` 可放行
9. 其餘 default deny

## 設定檔隔離（雙檔案）

- User config：`/etc/kekkai/kekkai.yaml`
- Agent managed（last-known-good）：`/etc/kekkai/kekkai.agent.yaml`

啟動時優先讀 managed 檔，managed 失效才回退 user config。
reload 成功後，agent 會更新 managed 檔，避免 user config 損毀導致重開機直接起不來。

## 核心特性

- XDP 在 ingress 熱路徑做 L3/L4 決策（低延遲、低 CPU）
- Hybrid stateful：flowtrack fast path + egress state seed
- LPM blocklist/allowlist + port policy（public/private）
- 熱重載（SIGHUP）、emergency bypass（`kekkai bypass on|off [--save]`）
- 觀測：全域/協定/drop-pass reason/per-IP topN
- TUI：Overview / Detail / Top-N / Charts
- 配置：嚴格 schema 驗證、SSH lockout 防護、自動備份、update channel

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

- NAT
- L7 WAF 規則
- TLS 指紋
- ML 異常偵測

## 授權

待定。
