# kekkai 指令手冊

完整的操作指令、設定語法、疑難排解速查。涵蓋 `kekkai` CLI、`kekkai-agent` daemon、systemd、`./kekkai.sh` 一鍵腳本、config 檔、備份機制、doctor 健康檢查。

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

### 2.0 sudo 權限政策（先看這個）

**所有 `kekkai` 指令一律用 `sudo kekkai <command>`。**

原因：Debian / Ubuntu / Pi OS 預設 `kernel.unprivileged_bpf_disabled=2`，非 root 呼叫 `bpf()` 會被 kernel 直接擋掉，`setcap` 無法繞過。為了跨主機一致、避免踩到平台差異，本專案乾脆把所有 CLI 使用統一到 sudo。

安裝器的行為：
- **會**寫 `/etc/sudoers.d/kekkai-cli-<user>` NOPASSWD drop-in → `sudo kekkai ...` 不會問密碼
- **不會**設 file capabilities (`setcap cap_bpf,...`) — 在這個 kernel sysctl 下沒用
- **不會**在 `.bashrc` / `.zshrc` 加 `alias kekkai='sudo kekkai'` — 避免跨主機 muscle memory 不一致

直接把 `sudo kekkai` 背起來就好，體感上跟無 sudo 差不多（沒密碼提示）。若不小心打成 `kekkai`，CLI 會提示改用 sudo。

若要關掉 NOPASSWD：`sudo rm /etc/sudoers.d/kekkai-cli-$USER`。

### 2.1 kekkai status

啟動互動式 TUI，取代 `watch -n 1 cat /var/run/kekkai/stats.txt`。
啟動後會背景檢查 `update.channel` 對應來源是否有新版（release / pre-release），並在 header 顯示 `up-to-date` / `available`。

```bash
sudo kekkai status                              # 預設讀 /etc/kekkai/kekkai.yaml
sudo kekkai status /path/to/kekkai.yaml           # 指定 config 路徑
```

**畫面分四頁**

| 頁 | 內容 |
|---|---|
| 1. Overview | RX / TX、協定速率、drop 原因摘要、top 5 IP |
| 2. Detail | 完整計數、每個 drop/pass reason 的 slot 值 |
| 3. Top-N | 整張 perip_v4 map 的 src IP 排行，支援上下捲動 |
| 4. Charts | 最近 120 秒 PPS/DPS/TCP/UDP/ICMP + stateful hit 走勢圖 |

**鍵盤**

| 鍵 | 動作 |
|---|---|
| `1` / `2` / `3` / `4` | 切到對應頁 |
| `Tab` / `Shift+Tab` | 前/後循環切頁 |
| `p` | 暫停刷新（再按一次恢復） |
| `↑` / `↓` / `j` / `k` | Top-N 頁上下選列 |
| `Home` / `g` | Top-N 頁跳到第一列 |
| `End` / `G` | Top-N 頁跳到最後一列 |
| `q` / `Ctrl+C` | 退出 |

刷新頻率 1 秒。畫面上方顯示 node id / iface / xdp mode / uptime，暫停時會亮 `[PAUSED]`。

### 2.2 kekkai check

驗證 config 檔後退出，**完全 read-only**，不動任何磁碟檔案。未來 schema 升版時這裡會印「would migrate on daemon start」但仍不寫回。

```bash
sudo kekkai check                               # 驗 /etc/kekkai/kekkai.yaml
sudo kekkai check /tmp/new-kekkai.yaml          # 指定檔案
```

實際的遷移寫回只會在 daemon 正式啟動（`systemctl start kekkai-agent` 或 `kekkai-agent -config ...`）時發生。

Exit code：`0` 通過、`1` 驗證失敗（錯誤訊息到 stderr）。推薦每次 reload 前先跑。

### 2.3 kekkai ports

快速列出 `public/private` port，含顏色與 SSH 暴露提示，方便在 reload 前做肉眼檢查。

```bash
sudo kekkai ports                               # 讀 /etc/kekkai/kekkai.yaml
sudo kekkai ports /tmp/new-kekkai.yaml          # 指定檔案
```

輸出重點：
- `PUBLIC`（綠色）與 `PRIVATE`（黃色）分開顯示 TCP/UDP
- `SSH exposure` 會標示 22 在 public/private/未配置
- 顯示 `ingress_allowlist` 條目數，快速判斷 private gate 是否有設

### 2.4 kekkai show

印出正規化後的 config（post-migrate, post-defaults, post-normalize），**read-only**。輸入是舊版 v1 時顯示遷移後的 v2，但不會寫回磁碟。

```bash
sudo kekkai show > /tmp/current.yaml       # 看 agent 實際在用什麼
sudo kekkai show /tmp/test.yaml            # 指定檔案
```

用途：
- 檢查 `security.enforce_ssh_private` 是否把 22 自動加進 `private.tcp`
- v1 遷移時預覽新版長怎樣（但要 daemon 正式啟動才會真的寫回）
- Diff 兩個 config 找差異

### 2.5 kekkai backup

手動寫一份備份。檔名 `kekkai.yaml.backup.<時戳>`。

```bash
sudo kekkai backup                            # 備份 /etc/kekkai/kekkai.yaml
sudo kekkai backup /etc/kekkai/kekkai.yaml    # 顯式指定
sudo kekkai backup /tmp/test.yaml             # 任意路徑
```

每個 kind (update/auto/backup) 各保留最新 10 份，舊的自動刪。

### 2.6 kekkai reset

用**預設 template** 覆蓋 config。原檔會先被複製成 `kekkai.yaml.backup.<時戳>` (manual backup kind) 所以永遠可以 rollback。

```bash
sudo kekkai reset                              # 用 default route 自動偵測 iface
sudo kekkai reset --iface eth1                 # 明確指定網卡
sudo kekkai reset /tmp/test.yaml               # 任意路徑
sudo kekkai reset /tmp/test.yaml --iface eth0
```

流程：
1. 偵測或接收 iface 名稱（`--iface` 沒給就讀 `/proc/net/route` 找 default route）
2. 如果目標檔案已存在 → 備份成 `*.backup.<時戳>`
3. 寫出乾淨的 v2 template（node / interface / runtime / observability / security / filter 全部預設值）
4. 印 `default config written: ...` + 提醒要補 `ingress_allowlist`

預設 template 會先放一條 `filter.ingress_allowlist: [192.168.0.0/16]`，避免初次安裝直接因 SSH 防呆拒啟。你仍然應該改成自己的管理網段：

```bash
sudo kekkai reset
sudo nano /etc/kekkai/kekkai.yaml
# 改成:
#   ingress_allowlist:
#     - 192.168.88.0/24     # 你的管理網段
sudo kekkai check
sudo systemctl restart kekkai-agent
```

**適用情境**
- config 被改壞了想從頭來
- 升級 schema 後發現遷移結果不理想，想用全新 template 重來
- 第一次安裝不想抄 internal/config/default.yaml

### 2.7 kekkai doctor

**完全 read-only 健康檢查**，不寫檔、不啟停 service、不 attach/detach XDP。印出彩色報告，分七大區塊，每項標 ✓ / ⚠ / ✗：

```
  ◈ KEKKAI doctor  結界 · diagnostic report
  ---------------------------------------------

  ○ BINARIES
    ✓  kekkai-agent (daemon)        6.3 MiB · 2026-04-14 05:20 · sha a1b2c3d4…
    ✓  kekkai (CLI)                 4.1 MiB · 2026-04-14 05:20 · sha 9f8e7d6c…

  ○ CONFIG
    ✓  config file                  /etc/kekkai/kekkai.yaml
    ✓  schema version               v2 (current)
    ✓  validation                   schema ok, ports unique, CIDRs parse
    ✓  SSH allowlist                2 allowlist entries gate port 22
    ✓  interface                    eth0 (xdp_mode=generic)

  ○ SYSTEMD
    ✓  unit file                    /etc/systemd/system/kekkai-agent.service
    ✓  enabled at boot              yes
    ✓  runtime                      running · since Mon 2026-04-14 04:50:23

  ○ KERNEL / EBPF
    ✓  kernel version               Linux version 6.12.47+rpt-rpi-2712 (…)
    ✓  BTF                          not available (OK — kekkai doesn't need CO-RE)
    ✓  bpffs                        mounted at /sys/fs/bpf
    ✓  pinned maps                  9 entries in /sys/fs/bpf/kekkai

  ○ NETWORK
    ⚠  NIC driver                   macb — native XDP not supported, using generic mode
    ✓  XDP attachment               program attached to eth0
    ✓  sysfs counters               tx_bytes readable

  ○ PERMISSIONS
    ⚠  effective uid                501 (non-root)
    ✓  /sys/fs/bpf                  accessible
    ✓  pin root readable            /sys/fs/bpf/kekkai

  ○ RUNTIME
    ✓  stats file                   /var/run/kekkai/stats.txt · updated 400ms ago
    ✓  packets dropped              1,234

  ---------------------------------------------
  healthy  18 checks · 16 ok · 2 warn · 0 error
```

Exit code：`0` 為 healthy 或只有 warning、`1` 為任何 error。設計上 warning 不算失敗（對應 `docker info` 慣例）。

**使用情境**
- 安裝後確認全部綠燈
- service 沒起來時快速指出問題與修法建議
- 升級前後 sanity check
- SSH 進機器後第一個要跑的指令

**和 `kekkai check` 的差別**
- `kekkai check` 只驗 config 語法
- `kekkai doctor` 驗**整個系統**：binary 在不在、systemd 啟沒啟、pinned map 存不存在、網卡 driver 支不支援、stats 檔有沒有在更新

### 2.8 kekkai version / kekkai help

```bash
sudo kekkai version        # 印 kekkai 版本 + 偵測 kekkai-agent 是否存在
sudo kekkai help           # 指令總表
```

### 2.9 kekkai bypass on|off [--save]

切換 `runtime.emergency_bypass`。

```bash
sudo kekkai bypass on                # 立即開啟 bypass（不寫 config）
sudo kekkai bypass off               # 立即關閉 bypass（不寫 config）
sudo kekkai bypass on --save         # 寫入 config 並 reload（重開機後仍生效）
sudo kekkai bypass off --save
```

行為：
- 預設（不帶 `--save`）是**臨時切換**，透過 signal 直接通知 running agent。
- CLI 會輸出警告：重開機/重啟 service 後會失效。
- 帶 `--save` 才會：
  1) 先做手動 backup  
  2) 改寫 `runtime.emergency_bypass` 到 config  
  3) 執行 reload 套用

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
kekkai-agent -check  -config <path>              # 驗證 (read-only)
kekkai-agent -show   -config <path>              # 印出正規化後 YAML (read-only)
kekkai-agent -backup -config <path>              # 寫一份 backup.<ts>
kekkai-agent -reset  -config <path> -iface eth0  # 覆蓋成預設 template (原檔自動備份)
```

四個 flag 互斥。`-check` / `-show` 完全不動磁碟（v2 之後的行為，之前的版本會寫回遷移）；`-backup` / `-reset` 會寫檔。直接跑 `kekkai-agent` 時請記得 sudo。

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
- agent 管理（last-known-good）：`/etc/kekkai/kekkai.agent.yaml`
- Canonical template：`internal/config/default.yaml`（repo 內，中英註解完整）
  - 編譯時用 `go:embed` 打包進 binary；部署到目標機器不需要 repo
  - `kekkai reset` 就是把這份 template 經過 `Render(values)` 字串替換產生

### 5.2 Schema 版本

頂層必有 `version: 1`。這是初版 schema，還沒有發生過 breaking change，所以**目前沒有實際的 migration 發生**。載入 `version: 2+` 的檔案會直接拒絕啟動。

未來第一次要改 schema 時，`internal/config/migrate.go` 會加一個新的 case：

```go
case 1:  // v1 → v2
    oldDoc := parseV1(data)
    values := translateValuesToV2(oldDoc)
    return parseCurrent([]byte(Render(values)))
```

因為 template 是共用的，migration 輸出**自動帶完整註解**。舊檔會備份成 `kekkai.yaml.update_backup.<時戳>` 再寫回。

### 5.3 完整結構

```yaml
version: 1

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
    tcp:
      - 80
      - 443
    udp:
  private:
    tcp:                     # 22 會被 normalize 自動加
    udp:
  ingress_allowlist:         # private 服務的來源白名單
    - 10.0.0.0/8
    - 192.168.0.0/16
  static_blocklist:          # 靜態黑名單，不管 port
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
| `update_backup` | 未來 schema migration 時自動寫 | `kekkai.yaml.update_backup.20260414T052301` |
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

## 七、安裝 / 更新

kekkai 是**純 release 分發**：目標機不需要 Go、git、clang，也不需要 clone repo。所有生命週期動作走 `/usr/local/bin/kekkai.sh`（由一鍵安裝腳本落地），內部只做「下載 GitHub release 資產 → 安裝 → 重啟 service」。

### 7.1 一鍵安裝（推薦）

```bash
curl -fsSL https://raw.githubusercontent.com/ExpTechTW/kekkai/main/kekkai.sh \
  | sudo bash -s -- install
```

若要固定更新通道為 pre-release：

```bash
curl -fsSL https://raw.githubusercontent.com/ExpTechTW/kekkai/main/kekkai.sh \
  | KEKKAI_UPDATE_CHANNEL=pre-release sudo bash -s -- install
```

安裝器會把 `kekkai.sh` 自己也落地到 `/usr/local/bin/kekkai.sh`，之後 `sudo kekkai update` 會找到它。

### 7.2 生命週期 subcommand

直接跑 `/usr/local/bin/kekkai.sh`（或用 `sudo kekkai update`）：

```bash
sudo bash /usr/local/bin/kekkai.sh install     # 強制重裝
sudo bash /usr/local/bin/kekkai.sh update      # 檢查 release 有無新版
sudo bash /usr/local/bin/kekkai.sh repair      # 補裝缺失的 binary / unit
sudo bash /usr/local/bin/kekkai.sh doctor      # read-only 健康檢查
sudo bash /usr/local/bin/kekkai.sh uninstall   # 移除 binary + unit，config 保留
```

`sudo kekkai update` 是 `sudo bash /usr/local/bin/kekkai.sh update` 的等價捷徑。

### 7.3 腳本旗標

```bash
bash kekkai.sh --no-install     # 跳過 apt 依賴安裝
bash kekkai.sh --iface eth1     # install 時指定網卡
bash kekkai.sh --run            # 裝完前景跑 agent（debug）
```

### 7.4 Update channel

設定在 `/etc/kekkai/kekkai.yaml`：

```yaml
update:
  channel: release     # release（預設）或 pre-release
```

或用 env 臨時覆蓋：`sudo KEKKAI_UPDATE_CHANNEL=pre-release kekkai update`

### 7.5 安裝完成後

```bash
sudo nano /etc/kekkai/kekkai.yaml             # 填 ingress_allowlist
sudo kekkai check                              # 驗證
sudo systemctl restart kekkai-agent             # 套用
sudo kekkai doctor                              # 確認全綠
sudo kekkai status                              # 看 TUI
```

補充：
- 預設 template 會先帶 `ingress_allowlist: 192.168.0.0/16` 作為「首次啟動保底」。
- `kekkai.sh` 安裝時若偵測到管理介面 IP 不在 `192.168.0.0/16`，會印警告。
- 實際上線前請務必改成你的管理網段（例如 `10.0.0.0/8`、`172.16.0.0/12`、Tailscale 網段）。

### 7.6 更新流程內部細節

`sudo kekkai update` 做的事：

1. 從 `https://github.com/ExpTechTW/kekkai/releases` 抓目標 channel（release / pre-release）的最新資產
2. 下載 `kekkai-agent-linux-<arch>` 和 `kekkai-linux-<arch>` 到 tmp 目錄
3. 用新 agent binary 跑 `-check` 驗 `/etc/kekkai/kekkai.yaml`（失敗中止，不動 service）
4. 三路 diff：agent / cli / kekkai.sh 個別比對 sha256，每個獨立決定要不要更新
5. agent 有變 → `systemctl restart kekkai-agent`（失敗自動 rollback 到 `kekkai-agent.prev`）
6. cli 或 kekkai.sh 有變 → 個別覆寫，不 restart service
7. 最後印藍色 `UPDATED`（有變）或綠色 `ALREADY UP-TO-DATE`（全部沒變）結果區塊

### 7.7 開發者本機建置（maintainer 用）

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

### 7.6 Makefile config 捷徑

```bash
make config-check     # = sudo kekkai check
make config-backup    # = sudo kekkai backup
make config-show      # = sudo kekkai show
```

---

## 八、統計檔案

`sudo kekkai status` 之外，`/var/run/kekkai/stats.txt` 仍會每秒更新，適合給 script / Prometheus node_exporter textfile collector 讀。

```bash
sudo cat /var/run/kekkai/stats.txt                # 一次性快照
sudo watch -n 1 cat /var/run/kekkai/stats.txt     # 舊的 watch 方式（仍可用）
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

**第一件事：確認你是用 `sudo kekkai status`**。非 root 幾乎必定會因 `kernel.unprivileged_bpf_disabled` 失敗。

```bash
sudo kekkai status
```

若 `sudo` 還是失敗，代表 agent 沒在跑或 bpffs 有問題：

```bash
sudo systemctl is-active kekkai-agent         # 確認 agent 跑著
sudo mount | grep bpf                         # 確認 bpffs 掛載
sudo ls /sys/fs/bpf/kekkai/                   # 確認 pin 路徑有檔案
```

bpffs 沒掛：`sudo mount -t bpf bpf /sys/fs/bpf`。

如果你真的要讓非 root 使用者直接跑 CLI（不建議，跨主機不穩）：

```bash
sudo sysctl kernel.unprivileged_bpf_disabled=0
```

這會放寬 kernel 的 Spectre 緩解，請自己評估風險。

### 9.5 `kekkai.sh update` 中止且 rollback

```bash
journalctl -u kekkai-agent -n 30 --no-pager
```

新 binary 通常因 kernel verifier 拒絕新的 eBPF `.o` 而起不來。舊 binary 已經自動還原，agent 應該還在跑舊版。

### 9.6 Config 遷移後拒絕啟動

目前 schema 是 v1，沒有實際的 migration 發生。如果看到 `unsupported config version: N` 代表手上這份 config 是用更新的 binary 寫出的 — 可能剛降級了 binary。修法是把 binary 升回去，或跑 `sudo kekkai reset` 重置成現行 schema。

---

## 十、目錄速查

| 路徑 | 內容 |
|---|---|
| `/usr/local/bin/kekkai` | CLI + TUI |
| `/usr/local/bin/kekkai-agent` | Daemon |
| `/usr/local/bin/kekkai-agent.prev` | `kekkai.sh update` 留的 rollback 快照 |
| `/etc/kekkai/kekkai.yaml` | user 主 config（可手動編輯） |
| `/etc/kekkai/kekkai.agent.yaml` | agent 管理的 last-known-good config（啟動優先使用） |
| `/etc/kekkai/kekkai.yaml.*_backup.*` | 備份檔 |
| `/etc/systemd/system/kekkai-agent.service` | systemd unit |
| `/sys/fs/bpf/kekkai/` | eBPF map pin 目錄 |
| `/var/run/kekkai/stats.txt` | 人類可讀統計快照 |
| `/sys/class/net/<iface>/statistics/tx_*` | sysfs tx 計數（kernel 來源） |

---

## 十一、環境變數

主要會看這些環境變數：

- `NO_COLOR`：關閉彩色輸出
- `KEKKAI_SCRIPT`：直接指定 `kekkai.sh` 路徑（預設 `/usr/local/bin/kekkai.sh`）
- `KEKKAI_REPO`：指定 `kekkai.sh` 所在目錄（罕用，大部分人用預設就好）
- `KEKKAI_UPDATE_CHANNEL`：臨時覆蓋 `update.channel`（`release` / `pre-release`）

---

## 十二、常用 one-liner

```bash
# 看當前過濾規則
sudo kekkai show | grep -A20 filter

# 備份 + 編輯 + 驗證 + reload 的標準流程
sudo kekkai backup && sudo nano /etc/kekkai/kekkai.yaml && sudo kekkai reload

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
- `git reset --hard` + `make update` — `kekkai.sh update` 會拒絕 dirty tree，且 hard reset 之後 ff-only merge 會失敗
- 同時跑兩個 `kekkai-agent` 進程 — 第二個會嘗試 attach 相同 iface 失敗，浪費時間

---

## 十四、目前可用的指令總表

### `kekkai` CLI

| 指令 | 實作 | 說明 |
|---|---|---|
| `kekkai status [path]`          | ✅ | 互動式 TUI |
| `kekkai config [path]`          | ✅ | 用 nano 編輯 config，退出後自動 reload |
| `kekkai doctor`                 | ✅ | 全系統健康檢查（read-only） |
| `kekkai check [path]`           | ✅ | 驗證 config (read-only) |
| `kekkai ports [path]`           | ✅ | 彩色列出 public/private port 與 SSH 暴露狀態 |
| `kekkai show [path]`            | ✅ | 印出正規化 config (read-only) |
| `kekkai backup [path]`          | ✅ | 手動時戳備份 |
| `kekkai reload [path]`          | ✅ | 先做 config check，再送出 systemd reload |
| `kekkai bypass on\|off [--save]` | ✅ | 預設臨時切換 bypass；`--save` 才持久化到 config |
| `kekkai update [kekkai.sh flags]` | ✅ | delegate 到 `kekkai.sh update`（支援 `--force` 等旗標透傳） |
| `kekkai reset [path] [--iface]` | ✅ | 覆蓋成預設 template，原檔自動備份 |
| `kekkai version`                | ✅ | 版本資訊 |
| `kekkai help`                   | ✅ | 指令總表 |

### `./kekkai.sh` 一鍵腳本

| 指令 | 實作 | 說明 |
|---|---|---|
| `kekkai.sh` (無參數)      | ✅ | 自動偵測狀態並執行對應動作 |
| `kekkai.sh install`       | ✅ | 強制初次安裝 |
| `kekkai.sh update`        | ✅ | 強制更新（來源由 `update.channel` 決定） |
| `kekkai.sh repair`        | ✅ | 補齊缺失的 binary / systemd unit |
| `kekkai.sh doctor`        | ✅ | delegate 到 `kekkai doctor` |
| `kekkai.sh uninstall`     | ✅ | 移除 binary + systemd，config 保留 |

## 十五、未來會加的指令（路線圖）

這些目前**還沒**實作，規劃在後續 milestone：

| 指令 | 規劃 milestone | 說明 |
|---|---|---|
| `kekkai block <ip> [--ttl]`   | M6 | 寫入 `dyn_blocklist_v4` 即時封鎖 |
| `kekkai unblock <ip>`         | M6 | 從動態黑名單移除 |
| `kekkai logs [-f] [-n N]`     | M7 | `journalctl -u kekkai-agent` 包裝 |
| `kekkai start/stop/restart/enable/disable` | M7 | systemctl 包裝 |
| `kekkai stats`                | M7 | 印 `stats.txt` 一次（script 友善） |

`kekkai update` 已整進 CLI，內部委派給 `/usr/local/bin/kekkai.sh update`（安裝器會自動落地這份腳本）。更新 / rollback / 結果區塊等邏輯全部集中在 `kekkai.sh` 單一來源。
