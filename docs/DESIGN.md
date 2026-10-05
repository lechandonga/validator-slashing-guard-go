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
- `internal/interchange` —— EIP-3076 风格（`interchange_format_version: "5"`）
  的记录导入/导出与安全合并。
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

无法判定安全与否的情形（未来 slot、状态不一致等）一律拒绝，绝不猜测放行。
拒绝只返回错误，**不写入任何记录**，因此不会污染既有历史。

## 3. 防罚没规则

证明（同一验证者维度）：

1. 同一签名根只允许签署一次（重复职责）。
2. 同一 `target_epoch` 不允许两个区块根不同的证明（double vote）。
3. 不允许新区间 `(s1,t1)` 被既有区间 `(s0,t0)` 严格包含，
   即拒绝 `s0 < s1 且 t1 < t0`（surrounded vote）。

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

## 6. 记录互换与合并语义（EIP-3076 风格）

文件形如：

```json
{
  "metadata": {
    "interchange_format_version": "5",
    "genesis_validators_root": "0x...."
  },
  "data": [
    {
      "pubkey": "0x....",
      "signed_attestations": [
        {"source_epoch": 0, "target_epoch": 1, "signing_root": "0x..", "beacon_block_root": "0x.."}
      ],
      "signed_blocks": [{"slot": 9}]
    }
  ]
}
```

导入是**全有或全无**的事务：

- JSON 必须完整可解析（截断、尾随数据直接拒绝）；
- 仅支持 `interchange_format_version = "5"`；
- `genesis_validators_root` 必须与本地链一致；公钥必须能映射到本地验证者；
- 先在内存中与现有记录合并并检测冲突（double vote / surround / 同 slot 区块），
  任何冲突或解析错误都以 `IMPORT_INVALID` / `IMPORT_CONFLICT` **整体拒绝**，
  不发生部分写入；
- 业务身份完全相同的条目幂等合并；
- 导入与签名共用同一把存储锁，并发执行结论确定、可复现
  （最终集合恒为安全并集）。

## 7. 本地验证方法

```bash
make test        # 普通单测（带业务/用例日志）
make test-race   # 竞态检测（需要 CGO，本机已具备 gcc）
make demo        # 端到端演示：并发、回退、互导、崩溃恢复语义
make vet
```

测试日志中每个测试先打印“业务”，再打印该业务下各“用例”的输入与结论，
可直接看出覆盖范围：

- 证明准入的各可区分拒绝原因（含状态不匹配、过期、未来、非法）；
- 同一职责 64 路并发仅 1 次成功、其余 `DUPLICATE_DUTY`；
- double vote 与 surround vote 拒绝且不污染记录；
- 区块同 slot 不重复签署；
- rename 前/后崩溃注入下的重启一致性；
- 链回退后记录保留、判定基于回退状态；
- 互导文件截断/版本不符/根不符/未知公钥整体拒绝；
- 导入冲突整体回滚、25 轮并发合并结果恒定、导出往返一致。
