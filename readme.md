# waf-go (edge)

高效能 L3/L4 邊緣防火牆 agent — XDP/eBPF 做 data plane、Go 做 control plane。本 repo 只包含 **edge 端**；未來與 core server 透過 NATS 交換黑名單與遙測（尚未實作），core server 另立 repo。

## 目前狀態

已完成 M1–M3：XDP 載入、CIDR 黑名單、完整統計。NATS 整合與 core 協同在路線圖上但尚未動工。edge 目前能獨立運作，是一個會用的本地 L3/L4 防火牆。

| 里程碑 | 狀態 | 交付內容 |
|---|---|---|
| **M1** skeleton & loader | ✅ | XDP attach/detach、config、cilium/ebpf 載入器、跨平台建置（macOS 開發 stub） |
| **M2** blocklist | ✅ | LPM_TRIE map、靜態黑名單、`XDP_DROP` 生效 |
| **M3** stats | ✅ | 全域 + 協定 + drop 原因計數、per-IP LRU top-N、tx 讀 sysfs、watch 友善輸出 |
| **M4** NATS 整合 | ⏳ | stats/events publish、心跳 |
| **M5** 黑名單 KV 同步 | ⏳ | JetStream KV watcher、本地 snapshot、開機回放 |
| **M6** rate limit & 自動封鎖 | ⏳ | 超閾值 TTL 封鎖、event ringbuf produce |
| **M7** 運維補強 | ⏳ | systemd unit、graceful reload、壓測 |

## 架構

```
┌─ Edge Node (本 repo) ─────────────────────────┐
│                                               │
│  ┌─ Data Plane (eBPF/C, kernel) ─────────┐    │
│  │  XDP @ NIC (generic mode on RPi)      │    │
│  │    ├ LPM_TRIE  blocklist_v4           │    │
│  │    ├ PERCPU_ARRAY stats (32 slots)    │    │
│  │    ├ LRU_HASH perip_v4  (65 536)      │    │
│  │    └ RINGBUF events      (reserved)   │    │
│  └───────────────────────────────────────┘    │
│                    ↑ map read / write         │
│  ┌─ Control Plane (Go, userspace) ───────┐    │
│  │  loader    : cilium/ebpf attach       │    │
│  │  maps      : blocklist Add/Del        │    │
│  │  stats     : dual-goroutine reader    │    │
│  │              ├ fast 1s  → stats.txt   │    │
│  │              └ slow 1s  → top-N scan  │    │
│  │  config    : YAML                     │    │
│  └───────────────────────────────────────┘    │
│                                               │
│  planned: NATS client, event ringbuf consumer │
└───────────────────────────────────────────────┘
```

## 功能

**XDP 過濾**
- IPv4 src address 查 LPM trie，命中 `XDP_DROP`，否則 `XDP_PASS`
- IPv6、非 IP 協定一律 pass（M2+ 擴充）
- 封包 header 解析用 repo 內自帶的 `struct ethhdr` / `struct iphdr`，不依賴 BTF / `vmlinux.h`（RPi kernel 常沒開 `CONFIG_DEBUG_INFO_BTF`）

**統計**
- 全域計數：total / passed / dropped 封包與 bytes
- 協定分類：tcp / udp / icmp / other
- Drop 原因：blocklist / malformed（未來加 rate-limit / synflood）
- Per-source-IP LRU hash：pkts / bytes / dropped / last proto / blocked flag
- Top-N src IP 排序在 userspace 獨立 goroutine 做，**不阻塞 fast tick 寫檔**
- rx 從 XDP map 聚合，tx 從 `/sys/class/net/<iface>/statistics/` 讀（XDP 只 hook ingress）
- 人類可讀 snapshot 寫到 `/var/run/waf-go/stats.txt`，`watch -n 1 cat` 即時監控

**Event ringbuf layout 已定義**，payload 產出留給 M4+（異常封包樣本 → core）

## 專案結構

```
waf-go/
├── cmd/edge/main.go              # agent 入口與子系統編排
├── bpf/
│   ├── xdp_filter.c              # XDP 程式
│   └── headers.h                 # 自定義 packet header
├── internal/
│   ├── config/                   # YAML 載入
│   ├── loader/                   # cilium/ebpf attach + map handles
│   │   ├── loader.go             # 跨平台 API
│   │   ├── loader_linux.go       # 真實 XDP attach
│   │   ├── loader_stub.go        # non-linux dev stub
│   │   └── bpf/xdp_filter.o      # go:embed 目標 (make bpf 產出)
│   ├── maps/                     # eBPF map 的 Go wrapper
│   │   └── blocklist.go          # LPM trie Add/Delete/Len
│   └── stats/                    # 統計 reader + 檔案輸出
├── deploy/
│   └── edge.example.yaml         # 範例 config
├── scripts/
│   ├── bootstrap.sh              # 一鍵安裝依賴 + build + install
│   └── build-bpf.sh              # clang 編譯 eBPF
├── Makefile
└── readme.md
```

## 技術選型

| 層 | 選擇 | 理由 |
|---|---|---|
| Data plane | XDP + eBPF (C) | 在 NIC driver 層處理，比 netfilter/nftables 更前面 |
| eBPF loader | [cilium/ebpf](https://github.com/cilium/ebpf) | 純 Go、無 libbpf CGO、map 操作成熟 |
| Packet headers | 自帶結構 | 避開 BTF / `vmlinux.h`，支援沒開 `CONFIG_DEBUG_INFO_BTF` 的 kernel |
| 設定 | YAML (`gopkg.in/yaml.v3`) | 夠用、無 viper 的 magic |
| 統計輸出 | 純文字檔 + `watch` | 不引入 Prometheus 直到真的需要 |

未來會加的：`nats.go`（M4）、protobuf（M4，跨 edge/core 協議）。刻意不加的：viper、BoltDB、Prometheus — 都是現在沒需求的抽象。

## 建置需求

- Linux kernel 5.15+（XDP + ringbuf）
- clang 14+ / llvm
- Go 1.22+
- `libbpf-dev`（提供 `bpf/bpf_helpers.h`）
- 執行時：root 或 `CAP_BPF + CAP_NET_ADMIN + CAP_PERFMON`

**BTF 不必要** — data plane 程式不使用 CO-RE。

## 快速開始

在 Linux 目標機器上：

```bash
git clone <repo> waf-go && cd waf-go
bash scripts/bootstrap.sh          # 裝依賴、build、install binary、寫預設 config
sudo nano /etc/waf-go/edge.yaml    # 填 iface / static_blocklist
sudo /usr/local/bin/waf-edge -config /etc/waf-go/edge.yaml
```

另一個 terminal 監控統計：
```bash
watch -n 1 cat /var/run/waf-go/stats.txt
```

**bootstrap.sh 旗標**
- `--no-install`：跳過 apt（依賴已裝好）
- `--iface <name>`：指定網卡（預設抓 default route）
- `--run`：build 完直接啟動

## 設定

[deploy/edge.example.yaml](deploy/edge.example.yaml)

```yaml
node_id: edge-01           # 預設用 hostname
region: default
iface: eth0                # 必填
stats_path: /var/run/waf-go/stats.txt

static_blocklist:          # IPv4 only；裸 IP 視為 /32
  - 192.0.2.0/24
  - 198.51.100.7
```

## 統計輸出範例

```
waf-go edge stats            updated: 2026-04-13T05:21:10+08:00
node=exptech  iface=eth0  uptime=54s

traffic (rx via XDP)
  pps total       :           41.99
  pps passed      :           40.99
  pps dropped     :            1.00
  rx total        :     315.51 Kbps
  rx dropped      :     783.80 bps

traffic (tx via kernel, not filtered by XDP)
  tx              :      26.59 Kbps
  tx pps          :           31.99

protocols (since start)
  tcp             :  pkts=2,455          bytes=    2.08 MiB
  udp             :  pkts=97             bytes=   21.89 KiB
  icmp            :  pkts=27             bytes=    2.58 KiB
  other l4        :  pkts=3              bytes=     180 B

drops by reason (since start)
  blocklist       :              27
  malformed       :               0

top 10 source IPs (scan: 42 entries, 2ms, at 120ms ago)
  #    SRC_IP           PKTS         BYTES        DROPPED    PROTO  STATUS
  1    1.2.3.4          12,543       10.21 MiB    0          tcp    pass
  2    192.0.2.7        27           1.82 KiB     27         icmp   BLOCK
```

## 開發工作流

eBPF 只能在 Linux 跑。推薦流程：

- **macOS**：寫 Go code、跑 `go build`、`go vet` — `loader_stub.go` 讓 non-linux 可編譯，attach 呼叫會明確回錯
- **Linux 測試機**：執行 `bash scripts/bootstrap.sh`，驗證 XDP 真實行為
- 想在本機跑 Linux 測試：用 [Lima](https://lima-vm.io) 或 [OrbStack](https://orbstack.dev)，比 Docker Desktop 的 LinuxKit 更貼近真實 kernel

eBPF `.o` 用 `go:embed` 打包進 binary，部署時單一檔案。

## NATS 整合（規劃，M4+）

Edge 上線後會與 core 透過以下 subject 溝通：

| Subject | 方向 | 傳輸 | 用途 |
|---|---|---|---|
| `stats.<region>.<node_id>` | edge → core | Core NATS | 聚合後統計 |
| `events.anomaly.<severity>` | edge → core | JetStream | 異常事件（持久化） |
| `heartbeat.<node_id>` | edge → core | Core NATS | 心跳 |
| `blocklist` (KV bucket) | core → edge | JetStream KV | Watch 收變更與初始快照 |
| `control.<node_id>` | core → edge | Core NATS | 指令（reload、flush、bypass） |

黑名單同步用 NATS JetStream KV Watch — 內建版本號、history、斷線重連補送，不自己寫同步邏輯。

## 部署

裸機 + systemd 是唯一支援方式。XDP 在容器裡會被 netns / veth / 權限 / driver 纏住，不值得。

- Binary: `/usr/local/bin/waf-edge`（由 bootstrap.sh 安裝）
- Config: `/etc/waf-go/edge.yaml`
- Stats: `/var/run/waf-go/stats.txt`
- Map pin: `/sys/fs/bpf/waf-go/`（預留 agent 重啟不中斷過濾；systemd unit 尚未寫）

## 效能目標（M7 驗收標準，尚未壓測）

| 指標 | 目標 |
|---|---|
| 過濾吞吐 | 單機 10 Gbps / 10 Mpps（64B 封包，native XDP） |
| 黑名單生效延遲 | core publish → edge drop < 1s |
| 黑名單容量 | 100 萬條 CIDR |
| Agent CPU (idle) | 單核 < 5% |
| Agent 記憶體 | < 200 MB |

**Raspberry Pi 實測注意**：RPi 4/5 的內建網卡 driver（`macb`、`bcmgenet`）沒有 native XDP 支援，只能 generic/SKB 模式，效能是 native 的 1/5–1/10。功能驗證沒問題，但線速目標要靠支援 native XDP 的硬體（`ixgbe`、`i40e`、`mlx5`、`ena`、`bnxt_en` 等）。

## 不做的事

- Stateful conntrack（複雜度高，先做 stateless L3/L4）
- NAT
- L7 規則 / HTTP WAF（之後另外包 Coraza，不在本 repo）
- TLS 指紋 / JA3
- ML 異常偵測（core 端職責）

## 授權

待定。
