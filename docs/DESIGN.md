# 验证者签名客户端与防罚没保护 —— 设计说明

一套本地可运行的验证者签名客户端：用本地生成的链状态与职责事件模拟证明
（attestation）与区块提议（block proposal）签名，在**并发触发、进程崩溃重启、
链状态回退、记录互导、同机多验证者**交织时，签署结论始终安全、确定、可解释。
全程离线，不访问真实链、外部服务或凭据。

## 1. 组件

- `internal/domain` —— 链状态（`ChainState`，可推进/回退）、职责请求、
  签名根、记录类型、占位根（`DummySigningRoot`）与可区分的拒绝原因码。
- `internal/store` —— 防罚没记录的崩溃安全持久化（单文件、原子替换 + fsync），
  所有签署与导入共用同一把锁。
- `internal/guard` —— 多验证者托管、签名准入与防罚没判定（含 EIP-3076
  条件 2/4/5 的历史低水位），串行化“判定 + 固化”，并提供确定性签名与崩溃后重放。
- `internal/interchange` —— 严格 EIP-3076（`interchange_format_version: "5"`）
  的记录导入/导出与安全合并。
- `internal/simulator` —— 本地确定性链推进、回退与职责事件生成。
- `cmd/simdemo` —— 多验证者端到端演示程序。

## 2. 多验证者身份与职责归属

一个 `guard.Client` 同时托管多个验证者身份（索引与公钥均可不同）。

- 签署接口显式接收“本次签署使用的身份索引”（`SignAttestation(signerIndex, req)`、
  `SignBlock(signerIndex, req)`），并与请求体 `req.ValidatorIndex` 严格比对：
  - 二者不同：返回 `VALIDATOR_MISMATCH`，不调用密钥、不进入存储临界区、
    不在任何身份下留记录；
  - 二者相同但身份未托管：返回 `UNKNOWN_VALIDATOR`，同样不留痕；
  - 只有二者一致且身份已托管才执行准入与签署。
- 所有防罚没判定与互导合并都带 `ValidatorIndex` 维度：不同身份在相同 slot /
  target epoch 各自签署互不冲突；身份内部的双投、surround、同 slot 不同区块
  照常被识别。导出按公钥分组，导入按公钥落回对应身份，记录不会串。
- `Validator.PublicKey` 是 48 字节的对外 BLS 公钥（EIP-3076 线格式使用）。
  本地演示用 `DeriveExternalPubkey(index)` 确定性派生；真实部署由
  `NewValidatorWithPubkey` 提供存款凭据中的公钥。本地确定性签名仍用 Ed25519
  （仅模拟），与外部 BLS 公钥相互独立。

## 3. 签名准入规则

每次签名前，请求必须与**当前本地链状态快照**一致，否则拒绝（只拒绝，不放行）：

| 原因码 | 触发条件 |
| --- | --- |
| `INVALID_REQUEST` | 区块根为空、`target_epoch != slot 所属 epoch`、`source > target` 等结构非法 |
| `VALIDATOR_MISMATCH` | 签署身份与职责声明的身份索引不一致 |
| `UNKNOWN_VALIDATOR` | 身份未在本进程托管 |
| `DUTY_FUTURE` | 职责 slot 晚于链当前 slot，无法判定安全性 |
| `DUTY_EXPIRED` | 职责 slot 早于链当前 slot，职责已过期 |
| `STATE_MISMATCH` | 证明投票的区块根不等于本地头根，或 `source_epoch != 本地 justified epoch` |
| `DUPLICATE_DUTY` | 签名根完全一致的同一职责已经签署（重复触发/并发重放） |
| `DOUBLE_VOTE` | 同一验证者、同一 `target_epoch` 已签过内容不同的证明，或缺签名根无法证明相同 |
| `SURROUND_VOTE` | 新证明的 `(source,target)` 区间与既有记录区间互相严格包围 |
| `DUPLICATE_BLOCK_SLOT` | 同一验证者在同一 slot 已签过不同内容的区块，或缺签名根无法证明相同 |
| `HISTORY_WATERMARK` | slot/epoch 已进入导入历史的低水位区（EIP-3076 条件 2/4/5） |

无法判定安全与否的情形（未来 slot、状态不一致、签名根缺失无法证明“同一次
签署内容”等）一律拒绝，绝不猜测放行。拒绝只返回错误，**不写入任何记录**。

## 4. 防罚没规则与“同一次签署内容”判定

判定的核心问题是：新请求与某条历史是不是**同一次签署内容**。只有当双方都
携带真实 `signing_root` 且根相等时，才算同一次签署（幂等/重放）。任何一方
缺失签名根（内部记为 `DummySigningRoot`，即规范建议的 32 字节 0x0 占位）时，
都无法证明相同，必须保守拒绝：

证明（同一验证者维度）：

1. 签名根相同 => 同一职责，允许重放（`DUPLICATE_DUTY` 幂等返回）；
2. 同 `target_epoch` 内容不同，或任一侧缺根无法证明相同 => `DOUBLE_VOTE`；
3. `(s,t)` 区间互相严格包围 => `SURROUND_VOTE`；
4. 新证明的 `source < min(历史 source)` 或 `target <= min(历史 target)`
   （且不是可重放的同一次签署）=> `HISTORY_WATERMARK`。

区块提议（同一验证者维度）：

1. 签名根相同 => 同一次签署，幂等；
2. 同 slot 根不同，或任一侧缺根无法证明相同 => `DUPLICATE_BLOCK_SLOT`；
3. `slot <= min(历史 slot)` 且不是同一次签署 => `HISTORY_WATERMARK`。

低水位规则对实时签署与导入记录一视同仁，保证迁移历史后不会在历史 slot/epoch
或数据库“空档”里补签（EIP-3076 Conditions 2/4/5）。

## 5. 记录先固化、确定性签名与崩溃恢复

提交协议在一个互斥临界区内串行完成：

1. 读取当前链头快照；
2. 做身份校验、准入校验与防罚没判定；
3. **先把新记录集原子固化到磁盘**：写同目录临时文件 → `fsync` 文件 →
   原子 `rename` 覆盖正式文件 → `fsync` 目录；
4. 固化成功后才返回签名值。

签名采用 Ed25519（RFC 8032），它是对 `(私钥, 签名根)` 的**确定性**函数：
同一条已固化记录在任何时刻都能重新派生出**完全相同**的签名。因此：

- rename 前崩溃：磁盘上没有记录，恢复后该职责可以正常签署一次；
- rename 后崩溃：记录已落盘，恢复后重放该职责得到 `DUPLICATE_DUTY`；
- 记录只通过整集原子替换生效，已生效记录不会被静默回退或覆盖。

## 6. 链状态回退语义

`ChainState.Rollback` 只改变后续准入判定所基于的链头，**绝不修改或删除任何
已固化记录**。回退后历史记录仍参与判定，新请求基于回退后的状态重新走完整
准入；回退前的旧职责通常变成 `DUTY_FUTURE`（或状态不一致），仍被拒绝。

## 7. 记录互换格式（EIP-3076 v5）兼容范围

### 7.1 线格式（严格遵循规范，不接受自创写法）

```json
{
  "metadata": {
    "interchange_format_version": "5",
    "genesis_validators_root": "0x<32 字节，0x 前缀十六进制>"
  },
  "data": [
    {
      "pubkey": "0x<48 字节 BLS 公钥>",
      "signed_blocks": [
        {"slot": "81952", "signing_root": "0x<32 字节，可选>"}
      ],
      "signed_attestations": [
        {"source_epoch": "2290", "target_epoch": "3007", "signing_root": "0x<32 字节，可选>"}
      ]
    }
  ]
}
```

- **必填**：`metadata.interchange_format_version`（固定字符串 `"5"`）、
  `metadata.genesis_validators_root`（必须 32 字节且与本地链一致）、`data`、
  每个条目的 `pubkey`（48 字节）、`signed_blocks`、`signed_attestations`
  （两个键都必须出现，可为空数组）、区块的 `slot`、证明的 `source_epoch` 与
  `target_epoch`。
- **可选**：区块与证明条目的 `signing_root`（出现时必须是 32 字节）。
- **数据类型**：所有 slot / epoch 都是**引号包裹的十进制字符串**（规范
  Rationale: Integer Representation），JSON 数字（如 `81952`）一律拒绝；
  非规范写法（空串、前导零、负数、十六进制）一律拒绝。
- **不允许自创字段**：解析启用未知字段拒绝。上一版本本地自创的
  `beacon_block_root` 已移除——规范的证明条目只有 source/target/signing_root。
- 同一 `pubkey` 在 `data` 中出现两次、尾随 JSON 数据、截断 JSON、未知格式
  版本、根长度不符等，一律 `IMPORT_INVALID` 整体拒绝。

### 7.2 导入合并语义（全有或全无）

导入分两阶段，且全部在存储锁内完成：

1. **解析与身份解析、文件内自冲突检测**：身份默认必须全部能映射到本地验证者，
   否则以 `UNKNOWN_VALIDATOR` 整体拒绝；文件内不同条目之间的双投、surround、
   同 slot 不同区块也在此阶段整体拒绝。
2. **与既有记录合并**：按第 4 节规则判定。完全相同的同一次签署幂等跳过；
   构成冲突则 `IMPORT_CONFLICT` 整体拒绝。只有全部条目处理成功才做一次
   原子替换，**不存在部分写入**。

缺 `signing_root` 的条目：

- 内部统一记为 `DummySigningRoot`（规范 Security Considerations 建议的
  “null/0x0”占位），并按业务键（证明：身份+source+target；区块：身份+slot）
  识别同一条历史的重复导入，保证幂等；
- 与任何同 target 的不同区间证明、同 slot 的不同区块（或对方有真实根）
  无法证明为同一次签署时，**整体拒绝并在错误信息中说明缺失签名根**，
  不会提示成功却丢记录。

### 7.3 文件中身份本地不存在的处理

- 默认语义：**整体拒绝**（`UNKNOWN_VALIDATOR`），一个条目不写。这是最安全、
  最稳定的默认，避免迁移时静默丢失某个验证者的历史。
- 显式选择：`Options{SkipUnknownValidators: true}` 时，本地不存在的身份被
  稳定跳过，其条目数在 `Result.SkippedValidators / SkippedAttestations /
  SkippedBlocks` 中返回；其余身份正常事务合并。

### 7.4 导出

- 导出在一次存储快照上完成（持锁拷贝），内容要么包含某次签署、要么不包含，
  绝不会导出半条记录；与并发签署交叉时每份输出都是自洽快照。
- 本地真实签署的区块与证明都带完整 `signing_root` 并原样输出，对端可据此
  判断“同一 slot/target 是否签过不同内容”；迁移进来的缺根历史在再次导出时
  继续省略 `signing_root`，不伪造根。
- 条目按公钥、slot、target/source 排序，输出稳定、可比较。

## 8. 并发保证

- 导入、证明签署、区块签署、导出都串行化在 `store` 的同一把锁上：
  - 导入与签署并发：最终记录集合确定、可复现，恒为安全并集；冲突导入整体
    拒绝，签署记录不丢；
  - 同一文件重复导入（无论并发还是串行）：幂等，不重复计数；
  - 导出与签署并发：每份导出都是一致快照，可被严格解析器重新读回。

## 9. 本地验证方法

```bash
make test        # 普通单测（日志含“业务/用例/结论”）
make test-race   # 竞态检测（CGO，并发用例在 -race 下稳定通过）
make demo        # 多验证者端到端演示：身份归属、隔离、互导、重放
```

关键测试覆盖：

- `TestImportCanonicalSpecSample`：EIP-3076 官方样例文件原样导入；
- `TestWireFormatStrictness`：数字/自创字段、缺 slot、长度错误、尾随数据拒绝；
- `TestExportRoundTrip`：导出被严格解析器读回、空库导入集合一致、再导幂等；
- `TestMissingRootConflictRejectsWholeFile`：关键签名根缺失时整体拒绝、无污染；
- `TestMultiValidatorMergeAndUnknownIdentity` /
  `TestSameTargetAcrossIdentitiesNotConflict`：多身份合并、隔离、未知身份语义；
- `TestIdentityMismatchRejectedAndNoRecords` /
  `TestMultiValidatorRecordIsolation`：身份不匹配拒绝且不留痕、记录隔离；
- `TestConcurrentImportSignExport` / `TestConcurrentSignAndExportSnapshot`：
  导入/导出/签署并发、一致快照、无半条记录（`-race` 下稳定）。
