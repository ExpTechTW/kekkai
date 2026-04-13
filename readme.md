# kekkai · 結界

高效能 L3/L4 邊緣防火牆 agent — XDP/eBPF 做 data plane、Go 做 control plane。「結界」取自日本動漫「看不見的屏障，擋邪入善出」，正好對應 XDP 在封包進 kernel 網路堆疊前就決定去留的設計。本 repo 只包含 **edge 端**；未來與 core server 透過 NATS 交換黑名單與遙測，core server 另立 repo。

兩個 binary：
- `kekkai-agent` — long-running daemon，systemd 管
- `kekkai` — operator CLI + 互動式 TUI（`kekkai status`）

## 目前狀態

已完成 M1–M3 + strict policy + CLI/TUI。NATS 整合與 core 協同尚未動工。edge 目前能獨立運作，是一個會用的本地 L3/L4 防火牆。

| 里程碑 | 狀態 | 交付內容 |
|---|---|---|
| **M1** skeleton & loader | ✅ | XDP attach/detach、config、cilium/ebpf 載入器、跨平台建置 |
| **M2** blocklist | ✅ | LPM_TRIE map、靜態黑名單、`XDP_DROP` 生效 |
| **M3** stats | ✅ | 全域 + 協定 + drop/pass reason 計數、per-IP LRU top-N、tx 讀 sysfs |
| **strict policy** | ✅ | public/private port、ingress allowlist、回程放行、IP fragment、TCP ACK / UDP ephemeral、dynamic blocklist map、hot reload、emergency bypass |
| **schema + lifecycle** | ✅ | `version: 2`、v1→v2 自動遷移、三種備份 + GC、`security.*` SSH 防護 |
| **CLI + TUI** | ✅ | `kekkai status` 互動式 TUI（結界主題配色 + threat meter）、`check`/`show`/`backup`/`reset` 子命令 |
| **doctor + installer** | ✅ | 單腳本 `kekkai.sh`（auto install/update/repair/uninstall/doctor）、`kekkai doctor` 彩色健康檢查報告 |
| **M4** NATS 整合 | ⏳ | stats/events publish、心跳 |
| **M5** 黑名單 KV 同步 | ⏳ | JetStream KV watcher、本地 snapshot、開機回放 |
| **M6** rate limit & 自動封鎖 | ⏳ | 超閾值 TTL 封鎖、event ringbuf produce |
| **M7** 運維補強 | ⏳ | 壓測、native XDP fallback 驗證 |

## 過濾模型

進站封包依序走完下列判斷，第一個匹配的規則就決定命運。本機主動出去的連線不受這裡約束（XDP 只 hook ingress），回程由規則 3 自動放行。

```
1. 非 IPv4                         → DROP (drop_non_ipv4)
2. IP fragment 2+                  → PASS (pass_fragment)
                                     (後續片段沒有 L4 header 可檢查)
3. 回程封包                         → PASS
   · TCP ACK 設了                    (pass_return_tcp)
   · UDP dst port ≥ 32768 (ephemeral)(pass_return_udp)
   · ICMP (ping reply / PMTU 一律過) (pass_return_icmp)
4. src in static_blocklist (LPM)   → DROP (drop_blocklist)
5. src in dyn_blocklist (LRU+TTL)  → DROP (drop_dyn_blocklist)
                                     (map 已建立，M6 / NATS 寫入)
6. dst port in filter.public.{tcp,udp}
                                    → PASS (pass_public_{tcp,udp})
7. dst port in filter.private.{tcp,udp}:
   · src in ingress_allowlist (LPM) → PASS (pass_private_{tcp,udp})
   · 否則                           → DROP (drop_not_allowed)
8. 沒有任何規則命中                 → DROP (drop_no_policy)
```

**Lockout 防護**：config 載入時檢查 `private.tcp` 含 22 但 `ingress_allowlist` 空 → 拒絕啟動，錯誤訊息直接指出會鎖掉 SSH。用 `kekkai-agent -check <path>` 可以離線驗證。

**IP 分片**：第一片段 (`frag_off == 0`) 帶 L4 header，照常處理；後續片段無 L4 header 一律 PASS，交給 kernel defrag。攻擊者若只送後續片段，kernel 重組失敗會自然 drop。

## 架構

```
┌─ Edge Node (本 repo) ─────────────────────────┐
│                                               │
│  ┌─ Data Plane (eBPF/C, kernel) ─────────┐    │
│  │  XDP @ NIC (generic or driver)        │    │
│  │    ├ LPM_TRIE  blocklist_v4  (1 M)    │    │
│  │    ├ LPM_TRIE  allowlist_v4  (64 K)   │    │
│  │    ├ LRU_HASH  dyn_blocklist (256 K)  │    │
│  │    ├ HASH      public_tcp_ports       │    │
│  │    ├ HASH      public_udp_ports       │    │
│  │    ├ HASH      private_tcp_ports      │    │
│  │    ├ HASH      private_udp_ports      │    │
│  │    ├ PERCPU_ARRAY stats (48 slots)    │    │
│  │    ├ LRU_HASH  perip_v4   (65 K+)     │    │
│  │    └ RINGBUF   events       (reserved)│    │
│  └───────────────────────────────────────┘    │
│                    ↑ map read / write         │
│  ┌─ Control Plane (Go, userspace) ───────┐    │
│  │  loader    : cilium/ebpf, spec rewrite│    │
│  │              xdp_mode fallback        │    │
│  │              emergency_bypass toggle  │    │
│  │  maps      : PrefixSet / PortSet /    │    │
│  │              DynBlocklist wrappers    │    │
│  │              Sync() reload diff       │    │
│  │  stats     : dual-goroutine reader    │    │
│  │              preallocated buffers     │    │
│  │              BatchLookup fallback     │    │
│  │  config    : nested YAML + validate   │    │
│  │              SIGHUP hot reload        │    │
│  └───────────────────────────────────────┘    │
│                                               │
│  planned: NATS client, event ringbuf consumer │
└───────────────────────────────────────────────┘
```

## 專案結構

```
kekkai/
├── cmd/kekkai-agent/main.go              # agent 入口 + reload/check/bypass 編排
├── bpf/
│   ├── xdp_filter.c              # strict policy XDP 程式
│   └── headers.h                 # 自帶 eth/ip/tcp/udp struct (免 BTF)
├── internal/
│   ├── config/                   # nested YAML + validation
│   ├── loader/                   # cilium/ebpf attach + map handles
│   │   ├── loader.go             # 跨平台 API + Options
│   │   ├── loader_linux.go       # 真實 XDP attach + xdp_mode fallback
│   │   ├── loader_stub.go        # non-linux dev stub
│   │   └── bpf/xdp_filter.o      # go:embed 目標 (make bpf 產出)
│   ├── maps/                     # eBPF map 的型別安全 wrapper
│   │   ├── blocklist.go          # PrefixSet (LPM trie, 共用)
│   │   ├── portset.go            # PortSet (HASH, big-endian u16)
│   │   └── dynblocklist.go       # DynBlocklist (LRU + TTL)
│   └── stats/                    # 統計 reader + 檔案輸出
├── deploy/
│   └── edge.example.yaml
├── scripts/
│   ├── bootstrap.sh
│   └── build-bpf.sh
├── Makefile
└── readme.md
```

## 技術選型

| 層 | 選擇 | 理由 |
|---|---|---|
| Data plane | XDP + eBPF (C) | 在 NIC driver 層處理，比 netfilter/nftables 更前面 |
| eBPF loader | [cilium/ebpf](https://github.com/cilium/ebpf) | 純 Go、無 libbpf CGO、map 操作成熟、spec rewrite 支援 |
| Packet headers | 自帶 struct | 避開 BTF / `vmlinux.h`，支援沒開 `CONFIG_DEBUG_INFO_BTF` 的 kernel |
| 設定 | YAML (`gopkg.in/yaml.v3`) + `KnownFields(true)` | 拼錯欄位直接報錯，比 viper 的 magic 安全 |
| 統計輸出 | 純文字檔 + `watch` | 不引入 Prometheus 直到真的需要 |

未來會加：`nats.go` (M4)、protobuf (M4)。刻意不加：viper、BoltDB、Prometheus — 現在沒需求。

## 建置需求

- Linux kernel 5.15+（XDP + ringbuf + BPF LRU hash）
- clang 14+ / llvm
- Go 1.22+
- `libbpf-dev`（提供 `bpf/bpf_helpers.h`）
- 執行時：root 或 `CAP_BPF + CAP_NET_ADMIN + CAP_PERFMON`

**BTF 不必要** — data plane 不使用 CO-RE。

## 快速開始

在 Linux 目標機器上**一條指令安裝**：

```bash
git clone git@github.com:ExpTechTW/kekkai.git && cd kekkai
bash ./kekkai.sh                 # 自動偵測狀態 → install / update / repair / doctor
```

`kekkai.sh` 是單一入口腳本，會：
1. 偵測 OS + 架構（linux/amd64、linux/arm64 等）
2. 若沒裝 → 裝依賴、編譯、安裝 `kekkai-agent` + `kekkai` binary、寫預設 config、裝 systemd unit、啟動 service
3. 若已裝 → 檢查 git 有沒有新 commit，有就走 update 流程（含 config 驗證 + 自動 rollback）
4. 若安裝不完整 → 走 repair 補齊
5. 全好了 → 跑 `kekkai doctor` 印健康報告

完成後：

```bash
sudo nano /etc/kekkai/kekkai.yaml      # 填 ingress_allowlist (至少加你的管理網段)
kekkai check                           # 驗證 (read-only，非 root 可跑)
sudo systemctl restart kekkai-agent
kekkai doctor                          # 確認全綠
```

其他 subcommand：
```bash
bash ./kekkai.sh install         # 強制重裝
bash ./kekkai.sh update          # 強制更新（git pull + rebuild + restart）
bash ./kekkai.sh repair          # 補裝缺失的 binary / systemd unit
bash ./kekkai.sh doctor          # = kekkai doctor
bash ./kekkai.sh uninstall       # 移除一切但保留 config
```

Makefile alias：`make install` / `make update` / `make repair` / `make doctor` / `make uninstall`

即時監控（TUI，取代 `watch -n 1 cat`）：
```bash
sudo kekkai status                     # 彩色 TUI，1/2/3 切頁，q 退出
```

重載規則（不中斷過濾）：
```bash
sudo nano /etc/kekkai/kekkai.yaml
kekkai check                           # 建議先驗證
sudo systemctl reload kekkai-agent     # SIGHUP，hot reload
```

## 指令列

Kekkai 分成兩個 binary：`kekkai-agent` 是 daemon（systemd 管），`kekkai` 是你平常用的 CLI 前端。

| 指令 | 用途 |
|---|---|
| `kekkai status`   | 啟動互動式 TUI（3 頁：Overview / Detail / Top-N） |
| `kekkai doctor`   | 跑全套健康檢查並印彩色報告（read-only） |
| `kekkai check`    | 驗證 config，**read-only** 非 root 也能跑 |
| `kekkai show`     | 印出完整正規化後的 config |
| `kekkai backup`   | 寫一份時戳 manual backup |
| `kekkai reset`    | 用預設 template 覆蓋 config（原檔自動備份，iface 自動偵測） |
| `kekkai version`  | 版本資訊 |
| `kekkai help`     | 指令總表 |

`check` / `show` 從 `-read-only` 改寫後完全不動磁碟，遇到 v1 會印「would migrate v1 → v2 on daemon start」但不實際寫回。只有 daemon 正式啟動（`systemctl start`）才會做真正的遷移寫回與備份。

`reset` 範例：
```bash
sudo kekkai reset                         # 自動用 default route 偵測 iface
sudo kekkai reset --iface eth1            # 明確指定
sudo kekkai reset /tmp/test.yaml          # 任意路徑（測試）
```
重置前會把原檔複製成 `kekkai.yaml.backup.<時戳>`，之後寫出一份乾淨的 v2 template。

## 更新 / 修復 / 診斷

全部透過 `./kekkai.sh` 或 Makefile：

```bash
make update                             # 拉新 commit、編譯、驗證、重啟（含自動 rollback）
make repair                             # 補裝缺失的 binary / systemd unit
make doctor                             # 跑健康檢查
make uninstall                          # 移除 binary + systemd，config 保留
```

**更新流程的防護**（和先前版本相同，只是整進 `kekkai.sh`）
1. 還原 `internal/loader/bpf/xdp_filter.o` 避免上次 build 殘留的 dirty 狀態
2. 檢查 working tree 乾淨；不乾淨就列 `git status --short` 後終止（`--force` 跳過）
3. `git fetch origin` 比對 commit；沒有新 commit 就直接退出
4. 遠端 commit 時間比本地舊 → 拒絕降級（`--force` 跳過）
5. `git merge --ff-only` + `make bpf && make build`
6. 用新 binary 跑 `kekkai-agent -check` 驗證現有 config；失敗就中止
7. 舊 binary 備份到 `/usr/local/bin/kekkai-agent.prev`
8. 安裝新 `kekkai-agent` + `kekkai`，`systemctl restart kekkai-agent`
9. 1 秒後檢查 service；沒起來就自動 rollback

**`kekkai.sh` 旗標**
- `--force`：略過 dirty tree / branch mismatch / 降級保護
- `--no-install`：跳過 apt 依賴安裝
- `--iface <name>`：指定 reset 時的預設網卡
- `--run`：install 完成後前景啟動 agent（debug 用）

## 設定

完整範例見 [deploy/kekkai.example.yaml](deploy/kekkai.example.yaml)（含中英雙語註解）。核心結構：

```yaml
version: 2

node:          { id: edge-01, region: default }
interface:     { name: eth0, xdp_mode: generic }
runtime:       { emergency_bypass: false, perip_table_size: 65536 }
observability: { stats_file: /var/run/kekkai/stats.txt }

security:
  enforce_ssh_private: true    # 強制 port 22 進 private.tcp
  allow_ssh_public: false      # 允許 port 22 放 public.tcp (預設不允許)

filter:
  public:
    tcp: [80, 443]             # 任何來源都可連
    udp: [53]
  private:
    tcp: []                    # 22 會因 enforce_ssh_private 自動加入
    udp: []
  ingress_allowlist:
    - 10.0.0.0/8
    - 192.168.0.0/16
    - 100.64.0.0/10
  static_blocklist: []
```

**版本化與自動遷移**

Config 頂層 `version: 2` 標註 schema 版本。Agent 啟動或 reload 時偵測版本號，比當前版本舊的會**自動升級並寫回磁碟**，原始檔備份到 `kekkai.yaml.update_backup.<時戳>`。最多保留 10 份，舊的自動刪除。

- **v1 → v2 遷移**：平坦的 M3 schema (`node_id` / `iface` / `static_blocklist` 等) 自動轉成巢狀結構
- v1 沒有的欄位（`filter.public` / `filter.private` / `ingress_allowlist`）用**保守預設**：`public.tcp: [80, 443]`、其他空。結果是 SSH 會被預設拒絕擋掉 → agent 拒絕啟動 → 強迫 user 檢視遷移後 config
- 不支援降級遷移。rollback 請手動從備份檔還原

**備份種類與命名**

| 觸發 | 檔名格式 | 時機 |
|---|---|---|
| 自動遷移 (migration) | `kekkai.yaml.update_backup.<ts>` | 載入時發現版本落後 |
| Reload 有變化 | `kekkai.yaml.auto_backup.<ts>` | SIGHUP 且新 config struct 和舊的不同 (DeepEqual 判定) |
| 手動備份 | `kekkai.yaml.backup.<ts>` | `kekkai-agent -backup` 或 `make config-backup` |

時戳格式 `20060102T150405`（UTC，ISO8601 basic format，檔名安全）。每種 kind 各自保留最新 10 份。

**CLI 旗標（`kekkai-agent` 原生，`kekkai` 是 wrapper）**

| CLI | 原始 flag | 行為 |
|---|---|---|
| `kekkai check [path]`  | `kekkai-agent -check`  | **read-only** 驗證，非 root 可跑，遇 v1 印「would migrate」不寫回 |
| `kekkai show [path]`   | `kekkai-agent -show`   | read-only 印出完整正規化 config |
| `kekkai backup [path]` | `kekkai-agent -backup` | 寫 `backup.<ts>`，需要 `sudo` 才能寫 `/etc/kekkai` |
| `kekkai reset [path]`  | `kekkai-agent -reset`  | 寫預設 template，原檔自動備份；`--iface` 覆蓋自動偵測 |

Makefile alias：`make config-check` / `make config-show` / `make config-backup`

**只有 daemon 正式啟動（systemctl start / bootstrap --run）才會真正執行 v1→v2 遷移的寫回。** `check` / `show` 永遠不動磁碟，所以你遠端 SSH 用非 root 帳號 debug 時也能安全呼叫。

**驗證規則**（啟動和 reload 都跑）
- `interface.name` 必填且存在
- 所有 port 在 1..65535
- 同一 proto 的 port 不可重複出現在 public 和 private
- 所有 CIDR 必須解析成功
- SSH 安全：
  - 22 在 `public.tcp` + `allow_ssh_public=false` → 拒絕啟動
  - 22 同時在 public 和 private → 拒絕啟動
  - 22 在 `private.tcp` 但 `ingress_allowlist` 空 → 拒絕啟動（鎖 SSH 防護）
- `enforce_ssh_private=true`（預設）時 22 自動加進 `private.tcp`（log 印 `normalize: auto-added ...`）
- `allow_ssh_public=true` + 22 在 public → 啟動，但印三行 `SECURITY WARNING` log

**Hot reload 範圍**（SIGHUP / `systemctl reload kekkai-agent`）
- ✅ `filter.*` 所有子欄位
- ✅ `security.*`（會重新跑 normalize，22 可能被加進/移出 private）
- ✅ `runtime.emergency_bypass`（即時 detach/re-attach）
- ❌ `interface.*`（需重啟）
- ❌ `runtime.perip_table_size`（需重啟，動到 eBPF map 大小）

Reload 成功且新舊 struct 不同 → 自動寫 `auto_backup.<ts>`，log 印 backup 路徑。

## 統計輸出範例

```
kekkai edge stats            updated: 2026-04-13T06:00:00+08:00
node=exptech  iface=eth0  uptime=1h12m34s

traffic (rx via XDP)
  pps total       :        1,245.00
  pps passed      :        1,240.00
  pps dropped     :            5.00
  rx total        :       8.21 Mbps
  rx dropped      :      12.80 Kbps

traffic (tx via kernel, not filtered by XDP)
  tx              :       2.45 Mbps
  tx pps          :          420.00

protocols (since start)
  tcp             :  pkts=3,241,221     bytes=  2.81 GiB
  udp             :  pkts=182,033       bytes= 22.50 MiB
  icmp            :  pkts=1,200         bytes=102.00 KiB
  other l4        :  pkts=5             bytes=     300 B

protocols (rate, last 1s)
  pps tcp         :        1,220.00
  pps udp         :           22.00
  pps icmp        :            3.00

counters (since start)
  packets total   :       3,424,459
  packets passed  :       3,420,000
  packets dropped :           4,459
  bytes total     :        2.84 GiB
  bytes dropped   :        1.24 MiB

drops by reason (since start)
  non-ipv4        :             124
  malformed       :               2
  blocklist       :             840
  dyn blocklist   :               0
  not allowed     :           3,440
  no policy       :              53

passes by reason (since start)
  return tcp (ACK):       2,800,000
  return udp (eph):          85,000
  return icmp     :             600
  ip fragment     :               4
  public tcp      :         530,000
  public udp      :               0
  private tcp     :           4,396
  private udp     :               0

top 10 source IPs (scan: 432 entries / cap 65536, 3ms, at 120ms ago)
  #    SRC_IP           PKTS         BYTES        DROPPED    PROTO  STATUS
  1    10.0.0.5         1,250,000    1.20 GiB     0          tcp    pass
  2    203.0.113.77     840          68.00 KiB    840        tcp    BLOCK
  ...
```

## 擴展與效能

**Data plane（kernel）**
- 封包熱路徑全在 eBPF，每封包 ≤ 2 次 map lookup (blocklist + 白名單)、幾個 per-CPU counter add
- `stats` 是 `PERCPU_ARRAY`，每個 CPU 獨立 slot，無 cache line contention
- `perip_v4` 是 `LRU_HASH`，滿了 kernel 自動淘汰最舊
- `dyn_blocklist_v4` 使用 TTL 欄位，過期的 entry 不必清理，LRU 自然淘汰

**Control plane（Go userspace）**
- Stats reader 雙 goroutine 解耦 + 預先配置記憶體：
  - fast tick：全域計數 + sysfs tx + 寫檔
  - slow tick：掃 perip 寫 double buffer + `atomic.Pointer` swap
  - 穩定狀態**零 heap 分配**
- BatchLookup (Linux 5.6+) 掃描 perip，kernel 不支援時自動 fallback 到 Iterate
- Reload 使用 Sync() 做差異套用，不重建 map

**大量 IP 的應對**

| 場景 | 做法 |
|---|---|
| `perip_table_size` 不夠 | 調高到 256K / 1M，重啟 agent |
| 黑名單百萬條 CIDR | LPM_TRIE O(prefix_length) 查詢，只吃 kernel 記憶體 (~100 B/條) |
| 千萬級 src IP (DDoS) | 子網粒度 key (`/24`) 或 Count-Min Sketch；eBPF 粗篩 + userspace 精算 |
| 本地自動封鎖 (M6) | 寫入 `dyn_blocklist_v4`，TTL 由 userspace 決定 |

## 開發工作流

eBPF 只能在 Linux 跑。推薦流程：

- **macOS**：寫 Go code、跑 `go build`、`go vet`、單元測試 — `loader_stub.go` 讓 non-linux 可編譯
- **Linux 測試機**：`bash scripts/bootstrap.sh`，驗證 XDP 真實行為
- 本機 Linux VM 用 [Lima](https://lima-vm.io) 或 [OrbStack](https://orbstack.dev)

eBPF `.o` 用 `go:embed` 打包進 binary，部署時單一檔案。

## NATS 整合（規劃，M4+）

| Subject | 方向 | 傳輸 | 用途 |
|---|---|---|---|
| `stats.<region>.<node_id>` | edge → core | Core NATS | 聚合後統計 |
| `events.anomaly.<severity>` | edge → core | JetStream | 異常事件 |
| `heartbeat.<node_id>` | edge → core | Core NATS | 心跳 |
| `blocklist` (KV bucket) | core → edge | JetStream KV | Watch 收變更與初始快照 |
| `control.<node_id>` | core → edge | Core NATS | reload / flush / bypass 指令 |

## 部署

裸機 + systemd 是唯一支援方式。XDP 在容器裡會被 netns / veth / 權限 / driver 纏住，不值得。

- Binary: `/usr/local/bin/kekkai-agent`
- Config: `/etc/kekkai/kekkai.yaml`
- Stats: `/var/run/kekkai/stats.txt`
- Map pin: `/sys/fs/bpf/kekkai/`

## 不做的事

- Stateful conntrack（複雜度高，先做 stateless L3/L4）
- NAT
- L7 規則 / HTTP WAF（另外包 Coraza，不在本 repo）
- TLS 指紋 / JA3
- ML 異常偵測（core 端職責）
- IPv6（之後再加 `blocklist_v6` / `allowlist_v6`）

## 授權

待定。
