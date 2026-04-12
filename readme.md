# waf-go (edge)

高效能 L3/L4 邊緣防火牆 agent，用 XDP/eBPF 做 data plane，Go 做 control plane，透過 NATS 與中央 core 交換黑名單與遙測。本 repo 只包含 **edge 端**；core 伺服器另立 repo。

## 目標

- 單機 10 萬+ HTTP RPS / 百萬級 PPS 等級的封包過濾
- 取代 nftables 的 L3/L4 防火牆功能（ACL、rate limit、基本 DDoS 緩解）
- 本地統計聚合，異常流量取樣上報
- 從 core 即時同步雲端黑名單（秒級生效）
- Edge 與 core 解耦：core 掛掉，edge 仍可獨立運作

## 架構

```
┌─ Edge Node ─────────────────────────────────┐
│                                             │
│  ┌─ Data Plane (eBPF/C, kernel) ─────────┐  │
│  │  XDP program @ NIC driver             │  │
│  │    ├ LPM_TRIE  : blocklist (CIDR)     │  │
│  │    ├ PERCPU_HASH: per-IP counters     │  │
│  │    ├ PERCPU_ARRAY: global stats       │  │
│  │    └ RINGBUF   : anomaly samples → US │  │
│  └───────────────────────────────────────┘  │
│                    ↑ map       ↓ ringbuf    │
│  ┌─ Control Plane (Go, userspace) ───────┐  │
│  │  loader       : cilium/ebpf           │  │
│  │  collector    : ringbuf reader        │  │
│  │  aggregator   : 本地統計聚合 (1s flush)│  │
│  │  nats client  : pub stats / events    │  │
│  │                 KV watch blocklist    │  │
│  │  map writer   : blocklist → LPM_TRIE  │  │
│  │  local cache  : BoltDB snapshot       │  │
│  │  metrics      : Prometheus /metrics   │  │
│  └───────────────────────────────────────┘  │
│                    ↕ NATS                   │
└─────────────────────────────────────────────┘
                     ↕
              NATS Cluster (JetStream + KV)
                     ↕
                  Core Server
```

## 技術選型

| 層 | 選擇 | 理由 |
|---|---|---|
| Data plane | XDP + eBPF (C) | 在 NIC driver 層處理，比 netfilter/nftables 更前面，可達線速 |
| eBPF loader | [cilium/ebpf](https://github.com/cilium/ebpf) | 純 Go、無 libbpf CGO 依賴、map 操作成熟 |
| 訊息匯流排 | [NATS](https://nats.io) + JetStream + KV | Pub/sub 原生、KV Watch 直接解黑名單同步、斷線自動補送 |
| 序列化 | Protobuf | 10 萬 RPS 下 JSON 的 CPU 開銷過高 |
| 本地快取 | BoltDB | 單檔、零依賴，重啟時先載入黑名單避免空窗 |
| 指標 | Prometheus client_golang | 業界標準，與 Grafana 對接簡單 |
| 設定 | YAML (viper) + 環境變數覆寫 | 容器部署友善 |

不使用 fasthttp/net/http — 本 agent 不處理 L7 HTTP，只做 L3/L4。若之後要做 L7 WAF，另開子模組整合 Coraza。

## 功能範圍（edge MVP）

**包含**
- XDP ingress 過濾（IPv4 優先，IPv6 第二階段）
- CIDR 黑名單（LPM_TRIE），從 NATS KV 即時同步
- Per-src-IP PPS / bps 計數
- 超閾值自動本地封鎖（TTL，短期懲罰）
- 異常事件取樣上報（packet header + 少量 payload）
- 統計聚合後週期上報（1s）
- Prometheus metrics endpoint
- Graceful reload（SIGHUP 重載設定，不中斷封包處理）

**不包含（留給後續）**
- Stateful conntrack（複雜度高，MVP 先做 stateless）
- NAT
- L7 規則
- TLS 指紋 / JA3
- ML 異常偵測（core 端職責）

## NATS Subject 與訊息流

Edge 端只碰這些 subject：

| Subject | 方向 | 傳輸 | 用途 |
|---|---|---|---|
| `stats.<region>.<node_id>` | edge → core | Core NATS | 聚合後統計，丟失可接受 |
| `events.anomaly.<severity>` | edge → core | JetStream | 異常事件，需持久化 |
| `events.sample.<node_id>` | edge → core | JetStream | 封包樣本，低頻觸發 |
| `heartbeat.<node_id>` | edge → core | Core NATS | 週期心跳 |
| `blocklist` (KV bucket) | core → edge | JetStream KV | Watch 模式即時收變更與初始快照 |
| `control.<node_id>` | core → edge | Core NATS | 下指令（reload、flush、debug） |

黑名單同步完全透過 NATS KV Watch 實作，不自己寫版本協商 — KV 內建版本號、history、斷線重連自動補。

## 專案結構（計畫）

```
waf-go/
├── cmd/
│   └── edge/              # edge agent 進入點
│       └── main.go
├── bpf/
│   ├── xdp_filter.c       # eBPF data plane 原始碼
│   ├── xdp_filter.h       # map 定義、共用結構
│   └── headers/           # vmlinux.h 等
├── internal/
│   ├── loader/            # eBPF 程式載入、attach、map 句柄
│   ├── maps/              # LPM_TRIE / per-CPU map 的 Go wrapper
│   ├── collector/         # ringbuf reader、事件 decode
│   ├── aggregator/        # 本地統計聚合
│   ├── blocklist/         # NATS KV watcher → map writer
│   ├── publisher/         # stats / events 上報（批次 + 背壓）
│   ├── cache/             # BoltDB 本地快照（開機回放）
│   ├── config/            # YAML + env 載入
│   └── metrics/           # Prometheus 指標
├── pkg/
│   └── proto/             # Protobuf 定義（與 core 共用）
├── deploy/
│   └── systemd/
├── scripts/
│   ├── build-bpf.sh       # clang 編譯 eBPF
│   └── gen-proto.sh
├── Makefile
├── go.mod
└── readme.md
```

## 建置需求

- Go 1.22+
- clang 14+ / llvm（編譯 eBPF）
- Linux kernel 5.15+（XDP + BTF + ringbuf）
- `libbpf` headers（產 vmlinux.h）
- `root` 或 `CAP_BPF` + `CAP_NET_ADMIN` 執行權限

## 實作里程碑

1. **M1 — Skeleton & eBPF loader**
   入口 + 設定 + 載入一個最小 XDP 程式（pass all），確認 attach/detach 正常。

2. **M2 — Blocklist map & 靜態黑名單**
   LPM_TRIE map + 從設定檔載入 CIDR 清單 + drop 測試。驗證過濾正確性與效能基準。

3. **M3 — 統計與 ringbuf**
   Per-CPU counter map + ringbuf 事件上報 + Go 端聚合 + Prometheus 輸出。

4. **M4 — NATS 整合**
   連線、重連、stats publish（Core NATS）、events publish（JetStream）。

5. **M5 — 黑名單 KV 同步**
   JetStream KV watcher → LPM_TRIE 寫入 + BoltDB 本地快照 + 開機回放。

6. **M6 — Rate limit & 自動封鎖**
   超閾值時 edge 本地寫入短期 TTL 封鎖（不等 core），同時上報 core 決策是否永久化。

7. **M7 — 運維補強**
   Graceful reload、control subject 處理、壓測與 pprof 剖析、部署腳本。

## 效能目標（驗收標準）

| 指標 | 目標 |
|---|---|
| 封包過濾吞吐 | 單機 10 Gbps / 10 Mpps（64B 封包） |
| 黑名單生效延遲 | core publish → edge drop < 1s |
| 黑名單容量 | 100 萬條 CIDR |
| 統計上報延遲 | 本地聚合 1s + NATS 傳輸 < 100ms |
| Agent CPU（idle） | 單核 < 5% |
| Agent 記憶體 | < 200 MB |

## 部署

**裸機 + systemd**（唯一支援方式）

理由：XDP 在容器內會被 netns / veth / 權限 / driver 支援等多重限制纏住，即便 `--privileged --network host` 跑起來，也多一層排查負擔。edge agent 定位就是 host 層基礎設施，直接用 systemd 管理最乾淨。

- Binary 安裝到 `/usr/local/bin/waf-edge`
- eBPF `.o` 放 `/usr/local/lib/waf-go/`
- 設定檔 `/etc/waf-go/edge.yaml`
- Map pin 到 `/sys/fs/bpf/waf-go/`（agent 重啟不中斷過濾）
- systemd unit 設 `CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_PERFMON`，不用 root

## 開發環境

本 repo 在 macOS 上開發，但 XDP 只能在 Linux 跑。工作流：

- **Mac**：寫 Go code、跑 `go build`、`go vet`、單元測試（non-eBPF 部分）
- **Linux 測試機**（VM / 遠端）：跑 `make bpf` 編譯 eBPF、`make run` 實際 attach
- **CI**：GitHub Actions `ubuntu-latest` 跑 eBPF 編譯與 loader smoke test
- 建議本機裝 [Lima](https://lima-vm.io) 或 [OrbStack](https://orbstack.dev) 開 Linux VM，比 Docker Desktop 更貼近真實 kernel

eBPF 原始碼用 clang 編成 `.o`，Go 端用 `go:embed` 打包進 binary，部署時單一檔案即可。

## 安全與運維注意

- eBPF 程式改動需過 verifier，CI 要跑 `bpftool prog load` 驗證
- NATS 連線強制 TLS + nkey/JWT 認證，edge 權限限定自己的 subject
- 黑名單有 TTL，避免永久誤封
- 保留 `control.<node_id>` 的緊急 bypass 指令，支援快速全放行
- 部署時 pin eBPF map 到 bpffs，支援 agent 重啟不中斷過濾

## 授權

待定。
