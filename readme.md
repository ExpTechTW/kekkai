# waf-go (edge)

高效能 L3/L4 邊緣防火牆 agent — XDP/eBPF 做 data plane、Go 做 control plane。本 repo 只包含 **edge 端**；未來與 core server 透過 NATS 交換黑名單與遙測（尚未實作），core server 另立 repo。

## 目前狀態

已完成 M1–M3 + strict policy：XDP 載入、完整過濾模型、熱重載、詳盡統計。NATS 整合與 core 協同在路線圖上但尚未動工。edge 目前能獨立運作，是一個會用的本地 L3/L4 防火牆。

| 里程碑 | 狀態 | 交付內容 |
|---|---|---|
| **M1** skeleton & loader | ✅ | XDP attach/detach、config、cilium/ebpf 載入器、跨平台建置 |
| **M2** blocklist | ✅ | LPM_TRIE map、靜態黑名單、`XDP_DROP` 生效 |
| **M3** stats | ✅ | 全域 + 協定 + 8 種 drop/pass reason 計數、per-IP LRU top-N、tx 讀 sysfs |
| **strict policy** | ✅ | public/private port、ingress allowlist、回程放行、IP fragment、TCP ACK/UDP ephemeral、dynamic blocklist map、hot reload、`-check` 模式、emergency bypass |
| **M4** NATS 整合 | ⏳ | stats/events publish、心跳 |
| **M5** 黑名單 KV 同步 | ⏳ | JetStream KV watcher、本地 snapshot、開機回放 |
| **M6** rate limit & 自動封鎖 | ⏳ | 超閾值 TTL 封鎖、event ringbuf produce |
| **M7** 運維補強 | ⏳ | systemd unit、graceful reload、壓測 |

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

**Lockout 防護**：config 載入時檢查 `private.tcp` 含 22 但 `ingress_allowlist` 空 → 拒絕啟動，錯誤訊息直接指出會鎖掉 SSH。用 `waf-edge -check <path>` 可以離線驗證。

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
waf-go/
├── cmd/edge/main.go              # agent 入口 + reload/check/bypass 編排
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

在 Linux 目標機器上：

```bash
git clone <repo> waf-go && cd waf-go
bash scripts/bootstrap.sh          # 裝依賴、build、install binary、寫預設 config
sudo nano /etc/waf-go/edge.yaml    # 填 interface.name 和 filter 規則
waf-edge -check /etc/waf-go/edge.yaml   # 先驗證
sudo /usr/local/bin/waf-edge -config /etc/waf-go/edge.yaml
```

另一個 terminal 監控統計：
```bash
watch -n 1 cat /var/run/waf-go/stats.txt
```

重載規則（不中斷過濾）：
```bash
sudo nano /etc/waf-go/edge.yaml
waf-edge -check /etc/waf-go/edge.yaml   # 建議先驗
sudo kill -HUP $(pgrep waf-edge)
```

**bootstrap.sh 旗標**
- `--no-install`：跳過 apt
- `--iface <name>`：指定網卡
- `--run`：build 完直接啟動

## 設定

完整範例見 [deploy/edge.example.yaml](deploy/edge.example.yaml)。核心結構：

```yaml
node:          { id: edge-01, region: default }
interface:     { name: eth0, xdp_mode: generic }
runtime:       { emergency_bypass: false, perip_table_size: 65536 }
observability: { stats_file: /var/run/waf-go/stats.txt }

filter:
  public:
    tcp: [80, 443]         # 任何來源都可連
    udp: [53]
  private:
    tcp: [22]              # 只有 ingress_allowlist 可連
    udp: []
  ingress_allowlist:
    - 10.0.0.0/8
    - 192.168.0.0/16
    - 100.64.0.0/10
  static_blocklist: []
```

**驗證規則**（啟動與 reload 都跑）：
- `interface.name` 必填且存在
- 所有 port 在 1..65535
- 同一 proto 的 port 不可重複出現在 public 和 private
- 所有 CIDR 必須解析成功
- `private.tcp` 含 22 但 `ingress_allowlist` 空 → 拒絕啟動（避免鎖 SSH）

**Hot reload 範圍**（SIGHUP）：
- ✅ filter 所有子欄位（public / private / allowlist / blocklist）
- ✅ `runtime.emergency_bypass`（即時 detach/re-attach）
- ❌ `interface.*`（需重啟）
- ❌ `runtime.perip_table_size`（需重啟，動到 map 大小）

## 統計輸出範例

```
waf-go edge stats            updated: 2026-04-13T06:00:00+08:00
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

- Binary: `/usr/local/bin/waf-edge`
- Config: `/etc/waf-go/edge.yaml`
- Stats: `/var/run/waf-go/stats.txt`
- Map pin: `/sys/fs/bpf/waf-go/`

## 不做的事

- Stateful conntrack（複雜度高，先做 stateless L3/L4）
- NAT
- L7 規則 / HTTP WAF（另外包 Coraza，不在本 repo）
- TLS 指紋 / JA3
- ML 異常偵測（core 端職責）
- IPv6（之後再加 `blocklist_v6` / `allowlist_v6`）

## 授權

待定。
