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
curl -fsSL https://raw.githubusercontent.com/ExpTechTW/kekkai/main/kekkai.sh \
  | bash -s -- install
```

若要固定更新通道（例如 pre-release）：

```bash
curl -fsSL https://raw.githubusercontent.com/ExpTechTW/kekkai/main/kekkai.sh \
  | KEKKAI_UPDATE_CHANNEL=pre-release bash -s -- install
```

完整刪除：

```bash
curl -fsSL https://raw.githubusercontent.com/ExpTechTW/kekkai/main/scripts/delete.sh \
  | sudo bash -s -- --yes --purge-home
```

kekkai 已改成純 release 分發：沒有原始碼建置模式，目標機不需要 Go / clang / git。所有安裝／升級都走 GitHub Releases 的預編 binary，由 `kekkai.sh` 一鍵腳本處理。

安裝後建議流程：

```bash
sudo nano /etc/kekkai/kekkai.yaml
sudo kekkai check
sudo kekkai reload
sudo kekkai status
```

權限速記：

- **所有 `kekkai` 指令一律用 `sudo kekkai <command>`**
- Debian / Ubuntu / Pi OS 預設 `kernel.unprivileged_bpf_disabled=2`，非 root 打 `bpf()` 會被 kernel 直接擋掉，無法用 `setcap` 繞過
- 安裝器會寫一份 `/etc/sudoers.d/kekkai-cli-<user>` NOPASSWD drop-in，所以 `sudo kekkai ...` **不會要密碼**
- 不再加 shell alias — 請直接敲 `sudo kekkai`，跨主機 muscle memory 才一致
- 若不小心打成 `kekkai`（非 root），CLI 會提示改用 `sudo kekkai`

> 注意：預設 `filter.ingress_allowlist` 會先放 `192.168.0.0/16` 避免初次啟動被 SSH 防呆擋住；請務必改成你的實際管理網段。

> 所有指令細節（`status/check/ports/show/backup/reload/bypass/update/reset/doctor`）已移到 [`COMMAND_ZH.md`](COMMAND_ZH.md)。  
> `kekkai update` 來源可由 `update.channel` 設為 `release`（預設）或 `pre-release`。

GitHub Releases 會提供各平台檔案（`kekkai-*` 與 `kekkai-agent-*`）：

- `linux-amd64`
- `linux-arm64`
- `darwin-amd64`
- `darwin-arm64`

版本字串規則：

- release / pre-release CI build：`YYYY.MM.DD+build.<N>`
- 本地開發 build（`make build`）：預設為 `dev-<shortSHA>`，僅供 repo 開發者本機驗證使用

## 過濾模型（Ingress）

目前預設是 strict model，封包判斷順序：

1. ARP（可配置）放行；其他非 IPv4 丟棄
2. IPv4 後續分片放行（無 L4 header 可檢查）
3. conntrack hit 直接放行（stateful fast path — TCP/UDP 都靠 egress seed 建立的 flow entry）
4. 回程 fallback 放行：
   - ICMP（可配置）
   - TCP：ACK / RST / FIN（classic "tcp-established" 判斷，SYN-only 新連線會掉到 port 規則）
   - UDP：只放行 dst port 68（DHCP client reply，避免 lease 續約 flap 介面 IP）
5. static blocklist 命中丟棄
6. dynamic blocklist 命中丟棄
7. `filter.public.*` 放行
8. `filter.private.*` 只有 `ingress_allowlist` 可放行
9. 其餘 default deny

> UDP 沒有 ephemeral port fallback — 本機主動發出去的 UDP session（DNS / NTP 等）回包完全依賴 egress seed 寫入 flowtrack，由 stateful fast path 接手。這個設計避免「dport >= 32768 就放行」的語義被 attacker 當成 UDP amplification 的入口。

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

## 執行需求（目標機）

- Linux kernel 5.15+
- `cap_bpf` + `cap_net_admin` + `cap_perfmon`（systemd unit 會設好）
- 網卡支援 generic/driver/offload XDP 其中之一

> BTF 非必要（目前不依賴 CO-RE）。目標機**不需要** Go / clang / libbpf-dev — 所有 binary 走 GitHub Releases 預編，安裝器會處理。

## 開發需求（repo 開發者）

僅在需要本機建置 / 測試時才需要：

- Linux kernel 5.15+（for `make bpf`）
- clang/llvm 14+
- Go 1.22+
- `libbpf-dev`

## 不在此 repo 的範圍

- NAT
- L7 WAF 規則
- TLS 指紋
- ML 異常偵測

## 授權

待定。
