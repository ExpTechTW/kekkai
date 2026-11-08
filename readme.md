# kekkai · 結界

高效能 L3/L4 邊緣防火牆（XDP/eBPF data plane + Go control plane）。
目標是用最小控制面、最早封包切入點，提供可熱重載、可觀測、可維運的 edge 防護。

`kekkai` 有兩個 binary：

- `kekkai-agent`：daemon（systemd 管理）
- `kekkai`：operator CLI + TUI

完整操作手冊（指令、systemd、排錯）請看：[`COMMAND_ZH.md`](COMMAND_ZH.md)

## 目前狀態

- 已完成：strict policy、CLI/TUI、doctor、installer/update、雙檔 config 隔離
- 已完成：IPv4 / IPv6 雙協定過濾；UDP stateful 回程（egress state seed + ingress flowtrack）
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

每個 release 都附 `SHA256SUMS`。安裝、`kekkai update` 與 agent 自動更新都會先比對 checksum（binary、`kekkai.sh`、systemd unit、motd、completions），缺檔或不符就中止，不會執行或安裝未驗證的檔案。安裝到 `/usr/local/bin/kekkai.sh` 的是該 release 附帶的版本，不是 `main` 分支上的。

安裝後建議流程：

```bash
sudoedit /etc/kekkai/kekkai.yaml
sudo kekkai check
sudo kekkai reload
sudo kekkai status
```

權限速記：

- **所有 `kekkai` 指令一律用 `sudo kekkai <command>`**
- Debian / Ubuntu / Pi OS 預設 `kernel.unprivileged_bpf_disabled=2`，非 root 打 `bpf()` 會被 kernel 直接擋掉，無法用 `setcap` 繞過
- 安裝器會寫 `/etc/sudoers.d/kekkai-cli-<user>`。NOPASSWD 只給安全子指令 `status`、`doctor`、`ports`、`version`、`check`、`show`、`reload`、`bypass`、`config`，以及 `sudoedit /etc/kekkai/kekkai.yaml`。`update`、`reset`、`backup` **會問密碼**
- 改設定用 `sudoedit`（編輯器以你的身分跑，不是 root），存檔後 `sudo kekkai reload`。`kekkai config` 只印出這段做法並檢查檔案，不會自己開編輯器
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

XDP 在 ingress 熱路徑同時處理 IPv4 與 IPv6：同一套規則、同一組 map（IPv4 位址以 `::ffff:a.b.c.d` 存放），`ingress_allowlist` / `static_blocklist` 可以混寫 v4 / v6 CIDR。TC egress hook 只記錄本機發出的 UDP flow 與 DHCP 請求，不擋任何東西。

封包判斷順序（先命中先決定）：

1. ARP：`filter.allow_arp` 開啟時放行；其他非 IPv4/IPv6（含帶 VLAN tag 的 frame）丟棄
2. L3 格式錯誤（版本 / IHL 不對、IP 長度超出 frame、IPv6 擴充標頭超過 6 層或 512 bytes、IPv6 來源是 `::ffff:` IPv4-mapped 位址）丟棄
3. 來源在 `static_blocklist` → 丟棄。最先檢查：黑名單來源的既有連線、分片、ICMP 都進不來
4. IP 分片第 2 片以後 → 放行（沒有 L4 header；第一片已經過完整檢查，kernel 重組時會丟掉缺第一片或互相重疊的分片）
5. TCP
   - 不合法 flag 組合（NULL、只有 FIN、Xmas、SYN+FIN、SYN+RST）→ 丟棄
   - 帶 ACK 或 RST → 放行（classic「tcp-established」，stateless，**不建立任何狀態**）。例外：送往非 public port、而且 kernel 裡只有 listener 會收的封包（SYN cookie 完成交握的情境），比照 SYN 走 port 規則，避免用猜 cookie 的方式繞過白名單
   - 只有 SYN（新連線）→ 走 port 規則
6. UDP
   - 本機先送出去的 flow 的回包 → 放行（egress seed 寫入 flowtrack，閒置 120 秒過期）
   - DHCP / DHCPv6 回覆（src 67→dst 68、547→546；DHCPv6 來源須為 fe80::/10），且本機 DHCP client 60 秒內送過請求 → 放行
   - 其餘 → 走 port 規則
7. ICMP / ICMPv6
   - echo request / reply → `filter.allow_icmp` 開啟時放行
   - frag-needed / packet-too-big → 放行（PMTU discovery；NAT / 容器流量沒有本機 socket，kernel 會自己比對 socket 並限制最小 MTU）
   - 其他錯誤訊息（unreachable、time exceeded、parameter problem）→ 引用的原始封包對應到本機現存的 TCP/UDP 連線才放行；`allow_icmp` 開啟時，引用本機 echo request 的也放行（traceroute -I、mtr）
   - IPv6 NDP（RS / RA / NS / NA，hop limit 必須是 255）與 MLD（hop limit 必須是 1）→ 放行，IPv6 運作必需
   - 其他類型（redirect、timestamp、address mask …）→ 丟棄
8. 其他 L4 協定（GRE、ESP、SCTP …）→ 丟棄
9. `filter.public.*` 放行任何來源；`filter.private.*` 只放行 `ingress_allowlist`；其餘 default deny

> UDP 沒有 ephemeral port fallback，本機 DNS / NTP 等回包完全依賴 egress seed。`filter.udp_ephemeral_min` 已停用，只為相容舊設定保留。公開 UDP 服務的回覆不寫入 flowtrack：那個 port 本來就開著，寫進去只會讓偽造來源的 flood 洗掉表。

## 安全邊界

- **來源位址無法驗證。** kekkai 依封包宣稱的來源 IP 比對 `ingress_allowlist` / `static_blocklist`，本身不做 anti-spoofing。白名單的可信度建立在上游網路已經擋掉偽造來源（ISP / 雲端供應商的 BCP 38、uRPF，或你自己的邊界路由器）。
  - TCP private 服務：偽造來源收不到 SYN-ACK，盲目偽造無法完成三向交握（Linux ISN 隨機）。
  - UDP private 服務：一個偽造封包就能觸發服務邏輯。請讓服務自帶驗證（例如 WireGuard 的金鑰），不要只靠白名單。
  - 同一個 L2 網段的主機可以任意偽造來源位址。白名單放整段區網（例如預設的 `192.168.0.0/16`）等於信任網段內每一台機器；公有雲 VPS 若上游不過濾私有位址來源，外部也可能偽造。請改成實際的管理 IP。
- **TCP established 是 stateless 判斷。** 帶 ACK / RST 的封包會交給 kernel，由 kernel 依現存 socket 決定，不存在就回 RST。外部因此能用 ACK 探測主機是否在線（看不出哪些 port 開著），但無法藉此建立連線，也不會在 kekkai 留下任何狀態。只會落到 listener 的 ACK（SYN cookie 情境）在非 public port 上比照 SYN 檢查白名單。沒有 socket 的封包照樣放行，因為 NAT / 容器的回程流量本來就沒有本機 socket。
- **只保護一張網卡、只看 ingress。** XDP 只掛在 `interface.name`；第二張 NIC、docker bridge、VPN tun 不受保護；本機送出的流量不過濾。
- **分片。** 第 2 片以後直接交給 kernel 重組。分片 flood 仍會消耗 kernel 重組記憶體（上限見 `net.ipv4.ipfrag_high_thresh` / `net.ipv6.ip6frag_high_thresh`）。
- **DHCP。** 只接受本機 DHCP client 剛送出請求後 60 秒內、來源 port 67 / 547 的回覆，DHCPv6 另外要求來源是 link-local（fe80::/10）。kernel 沒有 TCX（< 6.6）時沒有 egress hook 可以對照，退回只檢查 port。
- **XDP 不在時不過濾（fail-open）。** agent 停止、crash 或 emergency bypass 期間沒有任何過濾，用 `kekkai doctor` / `kekkai status` 確認。

## 設定檔隔離（雙檔案）

- User config：`/etc/kekkai/kekkai.yaml`
- Agent managed（last-known-good）：`/etc/kekkai/kekkai.agent.yaml`

啟動時優先讀 managed 檔，managed 失效才回退 user config。
reload 成功後，agent 會更新 managed 檔，避免 user config 損毀導致重開機直接起不來。

## 核心特性

- XDP 在 ingress 熱路徑做 L3/L4 決策（低延遲、低 CPU）
- UDP 回程 stateful（egress seed → flowtrack），TCP established stateless、不留狀態
- IPv4 / IPv6 雙協定：LPM blocklist/allowlist + port policy（public/private）
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

- Linux kernel 6.6+（TCX egress hook）。5.15–6.5 可以載入，但沒有 egress seed：本機 UDP 回包（DNS / NTP）會被擋，`kekkai doctor` 會報錯
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
