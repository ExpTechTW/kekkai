# kekkai 指令手冊

完整的操作指令、設定語法、疑難排解速查。涵蓋 `kekkai` CLI、`kekkai-agent` daemon、systemd、scripts/bootstrap、scripts/update、config 檔、備份機制。

---

## 一、兩個 binary 的分工

| Binary | 用途 | 誰執行 |
|---|---|---|
| `kekkai-agent` | Long-running daemon，載入 XDP、管 map、跑 stats reader | systemd |
| `kekkai` | Operator CLI + TUI 前端 | 你手動跑 |

裝好之後都在 `/usr/local/bin/`。

---

## 二、`kekkai` 指令

通用 CLI，Docker Compose 風格 subcommand。執行 `kekkai help` 看最新列表。

### 2.1 kekkai status

啟動互動式 TUI，取代 `watch -n 1 cat /var/run/kekkai/stats.txt`。

```bash
kekkai status                              # 預設讀 /etc/kekkai/kekkai.yaml
kekkai status /path/to/kekkai.yaml           # 指定 config 路徑
```

需要 root 才能讀 pinned eBPF maps：

```bash
sudo kekkai status
```

**畫面分三頁**

| 頁 | 內容 |
|---|---|
| 1. Overview | RX / TX、協定速率、drop 原因摘要、top 5 IP |
| 2. Detail | 完整計數、每個 drop/pass reason 的 slot 值 |
| 3. Top-N | 整張 perip_v4 map 的 src IP 排行，支援上下捲動 |

**鍵盤**

| 鍵 | 動作 |
|---|---|
| `1` / `2` / `3` | 切到對應頁 |
| `Tab` / `Shift+Tab` | 前/後循環切頁 |
| `p` | 暫停刷新（再按一次恢復） |
| `↑` / `↓` / `j` / `k` | Top-N 頁上下選列 |
| `Home` / `g` | Top-N 頁跳到第一列 |
| `End` / `G` | Top-N 頁跳到最後一列 |
| `q` / `Ctrl+C` | 退出 |

刷新頻率 1 秒。畫面上方顯示 node id / iface / xdp mode / uptime，暫停時會亮 `[PAUSED]`。

### 2.2 kekkai check

驗證 config 檔後退出，走完整 migration + validate + normalize 流程（但不寫回磁碟，除非有版本遷移）。

```bash
kekkai check                               # 驗 /etc/kekkai/kekkai.yaml
kekkai check /tmp/new-kekkai.yaml            # 指定檔案
```

Exit code：`0` 通過、`1` 驗證失敗（錯誤訊息到 stderr）。推薦每次 reload 前先跑。

### 2.3 kekkai show

印出正規化後的 config。輸入是舊版 v1 時會顯示遷移後的 v2。

```bash
kekkai show > /tmp/current.yaml            # 看 agent 實際在用什麼
```

用途：
- 檢查 `security.enforce_ssh_private` 是否有自動加入 22 到 `private.tcp`
- v1 遷移時預覽新版長怎樣
- Diff 兩個 config 找差異

### 2.4 kekkai backup

手動寫一份備份。檔名 `kekkai.yaml.backup.<時戳>`。

```bash
sudo kekkai backup                         # 預設路徑
sudo kekkai backup /etc/kekkai/kekkai.yaml   # 指定路徑
```

需要 `sudo` 因為備份寫到 `/etc/kekkai/`。每個 kind (update/auto/backup) 各保留最新 10 份，舊的自動刪。

### 2.5 kekkai version / kekkai help

```bash
kekkai version        # 印 kekkai 版本 + 偵測 kekkai-agent 是否存在
kekkai help           # 指令總表
```

---

## 三、`kekkai-agent` 直接使用的 flag

多數情況不用直接跑 `kekkai-agent`，systemd 會管。以下幾個 flag 在 debug 時很有用。

### 3.1 啟動

```bash
sudo /usr/local/bin/kekkai-agent -config /etc/kekkai/kekkai.yaml
```

前景執行，`Ctrl+C` 結束時會 detach XDP。systemd 就是用這條指令跑的。

### 3.2 Offline 模式（不啟動 daemon）

這些模式 `kekkai` CLI 都有 wrapper，底下只是說明它們在 `kekkai-agent` 層做了什麼。

```bash
kekkai-agent -check  -config <path>    # 驗證
kekkai-agent -show   -config <path>    # 印出正規化後 YAML
kekkai-agent -backup -config <path>    # 寫一份 backup.<ts>
```

三個 flag 互斥。

---

## 四、systemd 操作

安裝後 systemd unit 在 `/etc/systemd/system/kekkai-agent.service`。

### 4.1 生命週期

```bash
sudo systemctl enable --now kekkai-agent     # 開機啟動 + 立即啟動
sudo systemctl start kekkai-agent            # 啟動
sudo systemctl stop kekkai-agent             # 停止（自動 detach XDP）
sudo systemctl restart kekkai-agent          # 重啟
sudo systemctl reload kekkai-agent           # SIGHUP → 熱重載 config
sudo systemctl disable kekkai-agent          # 取消開機啟動
systemctl status kekkai-agent                # 看狀態
systemctl is-active kekkai-agent             # 只回 active/inactive
```

### 4.2 Log

```bash
journalctl -u kekkai-agent                   # 全部 log
journalctl -u kekkai-agent -f                # 跟著看新 log（tail -f）
journalctl -u kekkai-agent -n 50             # 最後 50 行
journalctl -u kekkai-agent --since "1h ago"  # 最近 1 小時
journalctl -u kekkai-agent -p err            # 只看 error 級別
```

Reload 成功時 journal 會記：
- `filter applied: public tcp=[...] udp=[...] ...`
- `auto-backup written: /etc/kekkai/kekkai.yaml.auto_backup.20260414T...`（如果 struct 有變化）
- `normalize: auto-added port 22 to filter.private.tcp (security.enforce_ssh_private=true)`（如果 Normalize 動到 config）

### 4.3 熱重載 vs 重啟

| 改動類型 | 做法 |
|---|---|
| `filter.*`（ports / allowlist / blocklist） | `systemctl reload` |
| `security.*` | `systemctl reload` |
| `runtime.emergency_bypass` | `systemctl reload` |
| `interface.name` / `xdp_mode` | `systemctl restart`（會短暫放行封包） |
| `runtime.perip_table_size` | `systemctl restart`（動到 map 大小） |

Reload 失敗時會在 log 印 `reload failed (keeping previous config): ...`，既有規則維持不變。

### 4.4 緊急旁路

XDP 規則懷疑有問題時，立即放行所有流量：

```bash
sudo sed -i 's/emergency_bypass: false/emergency_bypass: true/' /etc/kekkai/kekkai.yaml
sudo systemctl reload kekkai-agent
```

這會觸發 `reload: emergency bypass ENABLED (XDP detached)`，eBPF program 還在 memory，但已經 detach 離網卡。修好 config 後改回 `false` + reload，XDP 會重新 attach。

---

## 五、Config 檔

### 5.1 位置

- 正式：`/etc/kekkai/kekkai.yaml`
- 範例：`deploy/kekkai.example.yaml`（repo 內，中英註解完整）

### 5.2 Schema 版本

頂層必有 `version: 2`。載入舊版（`version: 1` 或沒寫 version）會自動遷移並寫回，原檔備份成 `kekkai.yaml.update_backup.<時戳>`。

v1 (M3 平坦) → v2 (巢狀) 對照：

```
v1                          →  v2
node_id                        node.id
region                         node.region
iface                          interface.name
stats_path                     observability.stats_file
perip_max_entries              runtime.perip_table_size
static_blocklist               filter.static_blocklist
(無)                           filter.public / private / ingress_allowlist / security.*
```

v1 沒有 `filter.public/private/ingress_allowlist`，遷移用保守預設：`public.tcp: [80,443]`、其他空。結果 SSH 會被擋，agent 拒絕啟動，強迫你看 migration log。

### 5.3 完整結構

```yaml
version: 2

node:
  id: edge-01                # 預設 hostname
  region: default

interface:
  name: eth0                 # 必填
  xdp_mode: generic          # generic | driver | offload

runtime:
  emergency_bypass: false    # true = 載入 eBPF 但不 attach
  perip_table_size: 65536    # LRU hash 容量，需重啟才能改

observability:
  stats_file: /var/run/kekkai/stats.txt

security:
  enforce_ssh_private: true  # 自動把 22 放進 private.tcp
  allow_ssh_public: false    # 允許 22 放 public.tcp（危險）

filter:
  public:
    tcp: [80, 443]           # 任何來源可連
    udp: [53]
  private:
    tcp: []                  # 22 會被 normalize 自動加
    udp: []
  ingress_allowlist:         # private 服務的來源白名單
    - 10.0.0.0/8
    - 192.168.0.0/16
    - 100.64.0.0/10
  static_blocklist: []       # 靜態黑名單，不管 port
```

### 5.4 過濾流程

每個進站封包依序走：

```
1. 非 IPv4                  → DROP  (drop_non_ipv4)
2. IP fragment 2+           → PASS  (pass_fragment)
3. 回程封包                  → PASS
   · TCP ACK 有設              (pass_return_tcp)
   · UDP dst port >= 32768    (pass_return_udp)
   · ICMP                      (pass_return_icmp)
4. src 在 static_blocklist  → DROP  (drop_blocklist)
5. src 在 dyn_blocklist     → DROP  (drop_dyn_blocklist，M6 之後才寫入)
6. dst port 在 public.*     → PASS  (pass_public_*)
7. dst port 在 private.*:
     src 在 ingress_allowlist → PASS (pass_private_*)
     否則                      → DROP (drop_not_allowed)
8. 都沒命中                  → DROP  (drop_no_policy)
```

本機主動出去的連線回程靠規則 3 放行，不用特別設定。

### 5.5 驗證規則

Load / reload 都會跑：

- `interface.name` 必填且存在
- 所有 port 在 1..65535
- 同一 proto 的 port 不能在 public 和 private 同時出現
- 所有 CIDR 必須解析成功
- SSH 安全檢查：
  - `allow_ssh_public=false` 時 22 在 `public.tcp` → **拒絕啟動**
  - 22 同時在 public 和 private → **拒絕啟動**
  - 22 在 `private.tcp` 且 `ingress_allowlist` 空 → **拒絕啟動**（SSH lockout 防護）

### 5.6 Normalize 行為

`security.enforce_ssh_private: true`（預設）時，若 22 既不在 `public.tcp` 也不在 `private.tcp`，會自動加進 `private.tcp`。log 會記 `normalize: auto-added port 22 to filter.private.tcp`。

---

## 六、備份機制

三種 backup，檔名開頭都是 `kekkai.yaml.`，後面接 kind + ISO8601 basic format 時戳。

| Kind | 觸發 | 檔名範例 |
|---|---|---|
| `update_backup` | 自動遷移（版本升級） | `kekkai.yaml.update_backup.20260414T052301` |
| `auto_backup` | Reload 且 config struct 有變（DeepEqual 比對） | `kekkai.yaml.auto_backup.20260414T052450` |
| `backup` | 手動 `kekkai backup` | `kekkai.yaml.backup.20260414T052733` |

### 6.1 查看備份

```bash
ls -la /etc/kekkai/kekkai.yaml.*
```

### 6.2 還原備份

沒有自動 rollback，手動 cp 回去：

```bash
sudo cp /etc/kekkai/kekkai.yaml.update_backup.20260414T052301 /etc/kekkai/kekkai.yaml
sudo systemctl reload kekkai-agent
```

### 6.3 GC

每個 kind 各自保留最新 10 份，舊的自動刪。無法關閉（簡化設計）。

---

## 七、安裝 / 更新 / 建置

### 7.1 初次安裝

```bash
cd /path/to/kekkai
bash scripts/bootstrap.sh                    # 裝依賴 + 編譯 + 安裝 binary + 寫預設 config + 裝 systemd unit
sudo nano /etc/kekkai/kekkai.yaml              # 改 iface 和 allowlist
kekkai check                                    # 驗證
sudo systemctl enable --now kekkai-agent         # 啟動 + 開機啟動
```

bootstrap.sh 的旗標：

```bash
bash scripts/bootstrap.sh --no-install       # 跳過 apt
bash scripts/bootstrap.sh --iface eth1       # 指定網卡
bash scripts/bootstrap.sh --run              # 編譯完前景執行（測試用）
```

### 7.2 更新

```bash
cd /path/to/kekkai
make update                                  # = bash scripts/update.sh
```

流程：
1. 檢查 working tree 乾淨（`--force` 跳過）
2. `git fetch` + 顯示即將套用的 commit
3. 拒絕降級（遠端 commit 時間比本地舊）
4. `git merge --ff-only`
5. `make bpf && make build`
6. 用新 binary 跑 `kekkai-agent -check` 驗當前 config（失敗就中止，不動安裝）
7. 舊 binary 備份到 `/usr/local/bin/kekkai-agent.prev`
8. 安裝新 binary（`kekkai-agent` 和 `kekkai` 都裝）
9. `systemctl restart kekkai-agent`
10. 1 秒後檢查 service 狀態，沒起來自動 rollback

其他旗標：

```bash
make update-check                            # 只看有沒有新 commit
bash scripts/update.sh --branch dev          # 從別的 branch
bash scripts/update.sh --no-restart          # 安裝但不重啟 service
bash scripts/update.sh --force               # 忽略 dirty tree / allow 降級
```

### 7.3 手動建置

```bash
make bpf              # 只編 eBPF .o
make build            # build kekkai-agent + kekkai（本機架構）
make build-linux      # 交叉編譯 linux/amd64
make vet              # go vet
make test             # go test（目前幾乎沒測試）
make clean            # 清 bin/ 和 .o

make status           # 本地 build 後直接跑 kekkai status（開發用）
make run              # 本地 build 後以 sudo 前景跑 kekkai-agent
```

### 7.4 Makefile config 捷徑

```bash
make config-check     # = kekkai check
make config-backup    # = sudo kekkai backup
make config-show      # = kekkai show
```

---

## 八、統計檔案

`kekkai status` 之外，`/var/run/kekkai/stats.txt` 仍會每秒更新，適合給 script / Prometheus node_exporter textfile collector 讀。

```bash
cat /var/run/kekkai/stats.txt                # 一次性快照
watch -n 1 cat /var/run/kekkai/stats.txt     # 舊的 watch 方式（仍可用）
```

欄位：traffic rx/tx、protocols (since + rate)、counters、drops by reason、passes by reason、top 10 source IPs。

---

## 九、疑難排解

### 9.1 Agent 起不來

```bash
systemctl status kekkai-agent
journalctl -u kekkai-agent -n 50 --no-pager
```

常見原因：

| 症狀 | 對策 |
|---|---|
| `interface.name is required` | config 少 `interface.name` 欄位 |
| `lookup iface eth0: ...` | 網卡名錯誤，用 `ip -br link` 查 |
| `this would lock SSH out` | `private.tcp` 有 22 但 `ingress_allowlist` 空，補上你的管理網段 |
| `filter.public.tcp contains 22 but security.allow_ssh_public is false` | 把 22 搬到 `private.tcp`，或 `security.allow_ssh_public: true` |
| `unknown field` | config 有拼錯的欄位（`KnownFields(true)` 嚴格檢查） |
| `attach xdp: ...` | kernel 不支援 XDP、網卡 driver 不合、或 `CAP_BPF` 不夠 |

### 9.2 SSH 連不上

先確認你的來源 IP 在 `ingress_allowlist` 範圍內：

```bash
who                                # 目前 SSH session 來源
ip route get 8.8.8.8                # 本機對外 IP 所在網段
```

如果已經把自己鎖外面且有另一個 SSH session 還活著：立刻改 config 加你的網段、reload。

如果完全鎖死，需要實體存取或 out-of-band 管理：

```bash
# 在 Pi 本機（鍵盤螢幕）
sudo sed -i 's/emergency_bypass: false/emergency_bypass: true/' /etc/kekkai/kekkai.yaml
sudo systemctl reload kekkai-agent
```

### 9.3 XDP 只能跑 generic mode

RPi 的 `macb` / `bcmgenet` driver 沒有 native XDP 支援。這是驅動層限制，不是 agent 問題。Generic mode 功能正常但效能打折。想要 native XDP 就得換支援的網卡（`ixgbe` / `i40e` / `mlx5` / `ena` / `bnxt_en`）。

### 9.4 `kekkai status` 回報 `open pinned stats map`

代表 agent 沒在跑，或 bpffs 沒掛。

```bash
systemctl is-active kekkai-agent              # 確認 agent 跑著
mount | grep bpf                          # 確認 bpffs 掛載
ls /sys/fs/bpf/kekkai/                    # 確認 pin 路徑有檔案
```

bpffs 沒掛：`sudo mount -t bpf bpf /sys/fs/bpf`。

### 9.5 update.sh 中止且 rollback

```bash
journalctl -u kekkai-agent -n 30 --no-pager
```

新 binary 通常因 kernel verifier 拒絕新的 eBPF `.o` 而起不來。舊 binary 已經自動還原，agent 應該還在跑舊版。

### 9.6 Config 遷移後拒絕啟動

v1 → v2 遷移完 agent 故意拒絕啟動（保守預設 + SSH 防護），強迫你確認新 config。照 log 訊息改 `filter.*` 和 `ingress_allowlist`，`kekkai check` 驗證後 `systemctl start kekkai-agent`。

---

## 十、目錄速查

| 路徑 | 內容 |
|---|---|
| `/usr/local/bin/kekkai` | CLI + TUI |
| `/usr/local/bin/kekkai-agent` | Daemon |
| `/usr/local/bin/kekkai-agent.prev` | update.sh 留的 rollback 快照 |
| `/etc/kekkai/kekkai.yaml` | 主 config |
| `/etc/kekkai/kekkai.yaml.*_backup.*` | 備份檔 |
| `/etc/systemd/system/kekkai-agent.service` | systemd unit |
| `/sys/fs/bpf/kekkai/` | eBPF map pin 目錄 |
| `/var/run/kekkai/stats.txt` | 人類可讀統計快照 |
| `/sys/class/net/<iface>/statistics/tx_*` | sysfs tx 計數（kernel 來源） |

---

## 十一、環境變數

幾乎沒有。目前唯一會看環境變數的地方是 `NO_COLOR`（未來 TUI 支援）。其餘所有行為都由 `/etc/kekkai/kekkai.yaml` 和 CLI flag 決定。

---

## 十二、常用 one-liner

```bash
# 看當前過濾規則
kekkai show | grep -A20 filter

# 備份 + 編輯 + 驗證 + reload 的標準流程
sudo kekkai backup && sudo nano /etc/kekkai/kekkai.yaml && kekkai check && sudo systemctl reload kekkai-agent

# 看被擋最多的 src IP
sudo kekkai status      # 切到 Top-N 頁，排序已經是 by pkts

# 看 agent 吃多少 CPU / 記憶體
systemctl status kekkai-agent
ps -o pid,rss,pcpu,cmd -p $(pgrep kekkai-agent)

# 看 eBPF map 實際大小（需要裝 bpftool）
sudo bpftool map show name blocklist_v4
sudo bpftool map show name perip_v4

# 匯出目前 stats 到檔案（給 debug 用）
cat /var/run/kekkai/stats.txt > /tmp/stats-$(date +%s).txt
```

---

## 十三、哪些指令 **不要** 下

- `rm -rf /sys/fs/bpf/kekkai/` — 強拆 pin 會讓 agent 重啟時混亂
- `systemctl kill -s 9 kekkai-agent` — SIGKILL 不會 detach XDP，留下孤兒 program（要手動 `ip link set eth0 xdpgeneric off`）
- `git reset --hard` + `make update` — update.sh 會拒絕 dirty tree，但 hard reset 之後會變成 ff-only 失敗
- 同時跑兩個 `kekkai-agent` 進程 — 第二個會嘗試 attach 相同 iface 失敗，浪費時間

---

## 十四、未來會加的指令（路線圖）

這些目前**還沒**實作，規劃在後續 milestone：

```bash
kekkai block <ip>          # 寫入 dyn_blocklist_v4，TTL 指定
kekkai unblock <ip>        # 從 dyn_blocklist_v4 移除
kekkai logs [-f]           # journalctl -u kekkai-agent 包裝
kekkai update              # scripts/update.sh 包裝
kekkai bypass on|off       # 切換 emergency_bypass 並 reload
kekkai top                 # 純 text top-N（TUI 外的 script 友善版本）
kekkai stats               # 印 stats.txt 一次
```

M5 / M6 / M7 會陸續補齊。這次 (Phase 1) 先有 `status` / `check` / `show` / `backup` / `version` / `help`。
