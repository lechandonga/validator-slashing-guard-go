# 验证者签名客户端与防罚没保护 —— 设计说明

一套本地可运行的验证者签名客户端：用本地生成的链状态与职责事件模拟证明
（attestation）与区块提议（block proposal）签名，在**并发触发、进程崩溃重启、
链状态回退、记录互导**交织时，签署结论始终安全、确定、可解释。全程离线，
不访问真实链、外部服务或凭据。

## 1. 组件

- `internal/domain` —— 链状态（`ChainState`，可推进/回退）、职责请求、
  签名根、记录类型与可区分的拒绝原因码。
- `internal/store` —— 防罚没记录的崩溃安全持久化（单文件、原子替换 + fsync）。
- `internal/guard` —— 签名准入与防罚没判定，串行化“判定 + 固化”，
  并提供确定性签名与崩溃后重放。
- `internal/interchange` —— 标准 EIP-3076（`interchange_format_version: "5"`）
  线格式的记录导入/导出、身份映射与安全合并。
- `internal/simulator` —— 本地确定性链推进、回退与职责事件生成。
- `cmd/simdemo` —— 端到端演示程序。

## 2. 签名准入规则

每次签名前，请求必须与**当前本地链状态快照**一致，否则拒绝（只拒绝，不放行）：

| 原因码 | 触发条件 |
| --- | --- |
| `INVALID_REQUEST` | 区块根为空、`target_epoch != slot 所属 epoch`、`source > target` 等结构非法 |
| `DUTY_FUTURE` | 职责 slot 晚于链当前 slot，无法判定安全性 |
| `DUTY_EXPIRED` | 职责 slot 早于链当前 slot，职责已过期 |
| `STATE_MISMATCH` | 证明投票的区块根不等于本地头根，或 `source_epoch != 本地 justified epoch` |
| `DUPLICATE_DUTY` | 签名根完全一致的同一职责已经签署（重复触发/并发重放） |
| `DOUBLE_VOTE` | 同一验证者、同一 `target_epoch` 已签过内容（区块根）不同的证明 |
| `SURROUND_VOTE` | 新证明的 `(source,target)` 区间被既有记录的区间**严格包含** |
| `DUPLICATE_BLOCK_SLOT` | 同一验证者在同一 slot 已签过内容不同的区块 |
| `IDENTITY_MISMATCH` | 请求携带的验证者公钥与该索引在本地托管的身份不一致（或缺公钥） |
| `UNKNOWN_VALIDATOR` | 请求/互导文件引用了本地未托管的验证者索引或公钥 |
| `IMPORT_AMBIGUOUS` | 导入判定所需的 `signing_root` 等信息缺失，无法确定是否同一次签署 |

无法判定安全与否的情形（未来 slot、状态不一致等）一律拒绝，绝不猜测放行。
拒绝只返回错误，**不写入任何记录**，因此不会污染既有历史。

## 3. 防罚没规则

证明（同一验证者维度）：

1. 同一签名根只允许签署一次（重复职责）。
2. 同一 `target_epoch` 不允许两个区块根不同的证明（double vote）。
3. 不允许两个区间互相严格包含（surround vote，两个方向都罚）：
   拒绝 `s0 < s1 且 t1 < t0`（新区间被包含），也拒绝 `s1 < s0 且 t0 < t1`
   （新区间反包既有区间）。

区块提议：同一验证者、同一 slot 只允许一个已签区块。

判定按“完全重复 > double vote > surround”优先级给出单一、稳定、可解释的原因。

## 4. 记录先固化、确定性签名与崩溃恢复

提交协议在一个互斥临界区内串行完成：

1. 读取当前链头快照；
2. 做准入校验与防罚没判定；
3. **先把新记录集原子固化到磁盘**：写同目录临时文件 → `fsync` 文件 →
   原子 `rename` 覆盖正式文件 → `fsync` 目录；
4. 固化成功后才返回签名值。

签名采用 Ed25519（RFC 8032），它是对 `(私钥, 签名根)` 的**确定性**函数：
同一条已固化记录在任何时刻都能重新派生出**完全相同**的签名。因此：

- 在 rename 前崩溃：磁盘上没有记录，恢复后该职责可以正常签署一次，
  不存在“已签名却无记录”；
- 在 rename 后崩溃：记录已落盘，恢复后重放该职责得到 `DUPLICATE_DUTY`，
  不会把同一职责签第二次，也不会把没签过的职责当成已签；
- 记录只追加、原子替换，已生效记录不会被后续操作静默回退或覆盖。

崩溃点由 `store.SetCrashHook` 注入，`TestCrashRestartConsistency` 覆盖两个边界。

## 5. 链状态回退语义

`ChainState.Rollback` 只改变后续准入判定所基于的链头，**绝不修改或删除任何
已固化记录**。回退后：

- 历史签名记录仍然存在，仍用于防罚没判定；
- 新请求基于回退后的头根/justified epoch/slot 重新走完整准入；
- 回退前的旧职责通常变成 `DUTY_FUTURE`（或状态不一致），仍被拒绝而非放行。

## 6. 多验证者身份归属与记录隔离

一个 `guard.Client` 同时托管多个验证者身份，每个身份由
`(validator_index, BLS pubkey 48 字节, 本地签名私钥)` 唯一确定：

- **职责归属**：每个签署请求（证明/区块）都必须携带 `BeaconPublicKey`。
  进入存储临界区前先做身份核验：
  - 请求索引本地未托管 → `UNKNOWN_VALIDATOR`；
  - 请求公钥缺失，或与该索引的本地托管公钥不一致 → `IDENTITY_MISMATCH`。
  两种情况下都**不签名、不在任何身份下写入记录**（证明与区块两条路径一致）。
- **记录隔离**：所有防罚没判定都以 `ValidatorIndex` 为维度。不同身份即使在
  同一 slot 提议区块、或在同一 `target_epoch` 对不同区块投票，也互不影响；
  同一身份自己的第二份不同内容仍按 `DOUBLE_VOTE` / `DUPLICATE_BLOCK_SLOT` 拒绝。
- **互导身份映射**：互导文件用 BLS 公钥作身份键，由 `ValidatorDirectory`
  （`guard.Client` 已实现）解析为本地索引；导入的每条记录只落到对应身份下，
  导出按身份分组，绝不串用。
- 文件中的身份本地不存在时，语义明确且可由调用方选择：
  - **默认（推荐）**：整体拒绝 `UNKNOWN_VALIDATOR`，文件里其他已知身份的条目
    也不会部分写入；
  - `ImportOptions{SkipUnknownValidators: true}`：未知身份的条目**整条跳过**
    （不是只跳某几条记录），已知身份正常合并。

## 7. EIP-3076 标准互换格式与合并语义

线格式严格遵循 EIP-3076（Slashing Protection Interchange Format，版本 5，
"complete" database）：

| 项 | 规范编码 | 必填 |
| --- | --- | --- |
| `metadata.interchange_format_version` | JSON 字符串 `"5"`（不是数字） | 是 |
| `metadata.genesis_validators_root` | `0x` + 32 字节十六进制，必须与本地链一致 | 是 |
| `data[].pubkey` | `0x` + **48 字节** BLS 公钥十六进制 | 是 |
| `signed_blocks[].slot` | JSON **十进制字符串**（如 `"81952"`，不是数字） | 是 |
| `signed_blocks[].signing_root` | `0x` + 32 字节；导出必带，导入可选 | 否 |
| `signed_attestations[].source_epoch` / `target_epoch` | JSON **十进制字符串** | 是 |
| `signed_attestations[].signing_root` | `0x` + 32 字节 | 否 |
| `signed_attestations[].beacon_block_root` | `0x` + 32 字节 | 否 |
| `signed_blocks` / `signed_attestations` 键 | 可整体省略（视为空） | 否 |

规范要求 slot/epoch 用字符串是为了规避跨语言 JSON 数字精度问题；所有十六进制
必须带 `0x` 前缀。数字编码、缺前缀、根长度不为 32、公钥不为 48、版本不符、
genesis 根不符、截断 JSON、尾随数据、`source > target` 等一律
`IMPORT_INVALID` 整体拒绝。

冲突判定以**“是不是同一次签署内容”**为准，判定键是 `signing_root`：

- **区块**：同身份、同 slot：两侧根相等 → 同一次签署（幂等）；根不等 →
  `IMPORT_CONFLICT`（同 slot 两个不同区块）；任一侧缺根无法判定 →
  `IMPORT_AMBIGUOUS` 整体拒绝并说明原因，绝不猜测、绝不静默丢弃。
- **证明**：两侧根相等 → 幂等；同 `target_epoch` 根不等 → `IMPORT_CONFLICT`
  （double vote）；区间互相严格包含（任一方向）→ `IMPORT_CONFLICT`
  （surround vote）；两侧都缺 `signing_root` 时，仅当
  `source/target/beacon_block_root` 也完全一致才视为同一次签署，同 target
  但投票根不同判为冲突，其余无法判定的情形一律 `IMPORT_AMBIGUOUS`。
- 上述判定同时覆盖“导入条目 vs 库内记录”和“同一文件内条目互相矛盾”。

导入是**全有或全无**的事务：解析、身份映射、冲突/歧义检测全部先在工作集内
完成，任何错误都返回 `IMPORT_INVALID` / `IMPORT_CONFLICT` /
`IMPORT_AMBIGUOUS` / `UNKNOWN_VALIDATOR` 且零写入；只有全部通过才一次性
原子替换。**同一文件重复导入幂等**：完全相同的签署不重复计数（返回新增条数
为 0）。

导出在存储的**一致性快照**上完成：与并发签署交错时，导出结果要么包含某次
签署、要么不包含，不会出现半条记录或重复条目。区块条目携带 `signing_root`，
因此按规范实现的外部工具回读后能正确判断同一 slot 是否签过不同区块；
条目按身份（索引升序）、slot/target 排序，输出稳定可复现；没有任何记录的
托管身份不产生空条目。

## 8. 并发与迁移保证

迁移历史记录与正常职责可以同时进行，保证来自同一个存储级临界区：

- **导入 ∥ 签名**：二者在同一把存储锁内串行化“读取工作集 → 判定 → 原子提交”。
  无论调度如何交错，最终记录集合是确定的安全并集：签名要么恰好发生一次，
  要么被识别为重复/冲突；导入要么整体成功、要么整体拒绝，不丢签名、不写半截。
- **重复导入**：同一份文件被并发或串行重复导入时，新增计数恒定（只计第一次），
  结果可复现。
- **导出 ∥ 签名/导入**：`Snapshot` 在锁内取完整拷贝，导出是某一时刻的一致
  快照，绝不会把同一次签署拆成半个条目；不同快照之间只有“有无该次签署”的
  整体差异。
- 记录固化沿用临时文件 + fsync + 原子 rename + fsync 目录的提交协议，
  并发保证与崩溃安全（第 4 节）叠加成立。

## 9. 本地验证方法


```bash
make test        # 普通单测（带业务/用例日志）
make test-race   # 竞态检测（需要 CGO，本机已具备 gcc）
make demo        # 端到端演示：多身份归属、并发、回退、标准互导、崩溃恢复语义
make vet
```

测试日志中每个测试先打印“业务”，再打印该业务下各“用例”的输入与结论，
可直接看出覆盖范围：

- 证明准入的各可区分拒绝原因（含状态不匹配、过期、未来、非法）；
- 身份公钥错配/缺失 → `IDENTITY_MISMATCH`、未托管索引 → `UNKNOWN_VALIDATOR`，
  且任何身份下记录零污染；
- 多身份记录隔离：同 slot/同 target 跨身份允许、同身份冲突拒绝（证明与区块）；
- 同一职责 64 路并发仅 1 次成功、其余 `DUPLICATE_DUTY`；
- double vote 与 surround vote（含反向包含）拒绝且不污染记录；
- 区块同 slot 不重复签署；
- rename 前/后崩溃注入下的重启一致性；
- 链回退后记录保留、判定基于回退状态；
- EIP-3076 规范样例文件（字符串 slot/epoch、48 字节公钥、区块 signing_root）
  原样导入成功；
- 导出线格式被独立 JSON 解析核对（字符串 epoch/slot、0x 根、区块带根），
  空库回读内容逐项一致、重复导入幂等；
- 线格式非法（数字 epoch/slot、缺 0x、根/公钥长度错、版本/genesis 不符、
  截断、source>target）整体 `IMPORT_INVALID`；
- 区块/证明冲突与文件内自相矛盾整体 `IMPORT_CONFLICT`；判定信息缺失整体
  `IMPORT_AMBIGUOUS`，均不部分写入；
- 一个文件多验证者条目按身份合并、互不判冲突；未知身份默认整体拒绝、
  显式 skip 时整条跳过且语义稳定；
- 20 轮 导入×5 / 签署×5 / 导出×8 并发：导入总新增恒为 3、签署恰好 1 次、
  8 份导出均为可解析的一致快照（`make test-race` 下稳定通过）。

快速手工验证标准互导文件可参考 `TestEIP3076CanonicalSampleImport` 中的样例；
`make demo` 会在临时目录写出 `interchange.json`，可直接用任意 EIP-3076 v5
兼容工具回读核对。
