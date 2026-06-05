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
> `kekkai update` 只在 config schema `version` 變更時才會回寫 `/etc/kekkai/kekkai.yaml`（先自動備份），平常同版本更新不會覆蓋你的檔案排版。

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
2. IPv4 後續分片（offset>0）**丟棄**：無 L4 header 可檢查，放行會繞過所有 port/blocklist/conntrack policy,也避免分片洪水塞爆 kernel 重組佇列。第一個分片（offset 0）仍帶 L4 header,照常走下面的 policy。（代價:合法的入站分片無法重組——對前置 TCP 服務的 L4 防火牆而言通常無感。）
3. **static + dynamic blocklist 命中丟棄**——在任何放行之前先查。blocklist 是「絕對 deny」,所以即使是 conntrack 回程、ICMP、DHCP 也擋得住;dynamic blocklist 推送也因此**即時生效**。
4. conntrack hit 直接放行（stateful fast path）。**flowtrack 只由 TC egress hook 種子**:本機主動發出去的連線,其回包落在 ephemeral port、沒有 port rule 涵蓋,才需要 flow entry。入站打到 public/private 服務 port 的封包每一個都直接命中 port rule,**不**建立 flow entry——所以 SYN flood 無法撐爆 flowtrack。
5. 只有兩種「無法用 flow 4-tuple 表示」的協定在此放行：
   - ICMP（可配置 `filter.allow_icmp`；ping 回包 / PMTU）
   - DHCP client 續租：UDP **src 67 → dst 68**（限定 src 67,避免任意來源從任意 port 觸達本機 DHCP client 控制面）
6. `filter.public.*` 放行
7. `filter.private.*` 只有 `ingress_allowlist` 可放行
8. 其餘 default deny

> **沒有無狀態回程 fallback。** 早期版本對「TCP 帶 ACK/RST/FIN」一律放行（classic tcp-established），但那讓偽造 ACK 能無中生有建立 flow entry，已移除。所有 TCP/UDP 回程都必須是真正的 conntrack 命中（步驟 3），由 TC egress seed 餵養。
>
> **kekkai 強制要求 kernel >= 6.6（TCX）。** egress seed 靠 TCX，是回程流量唯一的來源；< 6.6 會在**安裝時直接失敗**、agent 也會拒絕 attach。沒有它,DNS / NTP / 連線回包全部會被丟棄。

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
