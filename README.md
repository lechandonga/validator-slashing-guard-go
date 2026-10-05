# Validator Slashing Guard (Go, 本地模拟)

一套**完全本地运行**的验证者签名客户端与防罚没（slashing protection）流程：
用本地确定性生成的链状态与职责事件模拟验证者运行，使**并发触发、进程重启、
链状态回退（reorg）与记录互导**交织时，签署结论始终**安全、确定、可解释**。

不依赖真实链数据、信标节点、网络服务或任何凭据；签名是确定性模拟值
（非真实 BLS），仅用于表达“签 / 不签”的结论。

## 目录结构

| 路径 | 职责 |
| --- | --- |
| `internal/types` | 领域类型、职责结构、可区分的拒绝原因代码 |
| `internal/chain` | 本地链状态模拟：出块、推进、回退、finalized checkpoint |
| `internal/store` | 防罚没记录持久化：flock 跨进程锁 + fsync + 原子 rename |
| `internal/signer` | 签名准入与防罚没判定核心 |
| `internal/interchange` | EIP-3076 互换文件的严格解析、整体合并、导出 |
| `cmd/guard-demo` | 一键本地演示（正常/并发/不匹配/回退/互导冲突） |

## 运行

```bash
# 演示全部业务
go run ./cmd/guard-demo

# 单元测试（竞态检测）
CGO_ENABLED=1 go test ./... -race -v

# 压力重复并发交织（默认每个测试 50 次交织）
CGO_ENABLED=1 go test ./internal/interchange -race -count=5
```

所有产物都在当前目录的 `.demo-data*` 与 Go 的临时测试目录中，可随时删除。

## 签名准入规则（按顺序判定，首个失败即拒绝）

每条证明 / 提议职责在签署前依次通过以下闸门；失败返回**可区分的原因代码**
（见 `internal/types` 的 `Reason`），拒绝绝不写入任何记录：

1. `malformed_request` —— 字段缺失、target epoch 与 slot 不符、source > target。
2. `unknown_validator` —— 请求的验证者不是本地签名者。
3. `duplicate_duty` —— 同一 `signing_root` 已有固化记录（幂等重放）。
4. `state_mismatch` —— 请求与本地链状态不一致：
   - slot 在未来；
   - 证明的 `beacon_block_root` 与该 slot 本地规范块根不符（回退分叉）；
   - 证明的 source epoch 与本地 finalized epoch 不符；
   - 提议 slot 的块根与本地规范链不符。
5. `duty_expired` —— target epoch 已最终化、证明距 head 超过一个 epoch、
   提议 slot 已成为历史 slot。
6. 防罚没几何规则（下节）。

### 防罚没规则

- **证明（attestation）**
  - `double_attestation`：同一 target epoch 已存在内容不同（`signing_root` 不同）的记录。
  - `surrounded_attestation`：新证明区间 `[source,target]` 被既有记录
    `[s,t]` **严格包含**：`s < source` 且 `target < t`。
  - `surrounding_attestation`：新证明严格包含既有记录（等价罚没条件，安全侧一并拒绝）。
- **区块提议（proposal）**
  - `double_proposal`：同一 slot 已存在不同 `block_root` 的提议记录。
- 任何无法判定安全与否的情况一律拒绝，绝不猜测放行。

## 记录固化与崩溃恢复保证

- **记录先于签名固化**：实现先在内存计算出模拟签名并连同记录一起写入，
  数据库经过 `temp 文件 -> fsync -> 原子 rename -> 目录 fsync` 后，
  签名结果才返回给调用方。因此不存在“签名已发出却无记录”的窗口。
- 记录内嵌签名：若进程在 fsync 之后、返回之前被杀死，重启后该职责
  重放会得到 `duplicate_duty`，可取出同一份签名，不会被当成新职责再签一次；
  也不会把从未签署过的职责误认为已签（只有完整记录才算已签）。
- **只追加、不修改、不删除**：链回退不撤销任何记录；后续操作无法静默覆盖。
- **原子写**：崩溃只可能留下旧版本或新版本数据库，绝不会出现截断文件；
  一旦解析失败或身份/GVR 不匹配，数据库 **fail-closed** 拒绝启动。
- **跨进程锁**：`flock` 保证同一数据目录同时只有一个签名者实例，
  避免两个进程带着各自的缓存双签。

测试中的 `TestBusinessCrashRecovery` 会启动真实子进程，在“fsync 完成、
签名未返回”窗口以非零码退出，再重新打开数据库验证上述全部不变量。

## 链状态回退语义

- 本地链状态可回退到指定 head，并在目标 slot 产生与原规范链不同的竞争块根。
- finalized checkpoint 不可回退（尝试回退到最终化区间直接报错）。
- 回退后：历史签名记录原样保留；新的签署判定基于回退后的链状态。
  因此“同 epoch 不同根的证明”“同 slot 不同根的提议”都会被防罚没规则拦截。

## EIP-3076 互导与合并语义

- 仅接受 `interchange_format_version = "5"`（EIP-3076），JSON 解析
  **拒绝未知字段、尾随数据与截断内容**，错误码 `interchange_invalid`。
- 校验 `genesis_validators_root` 与本地链状态一致，且文件中恰好包含
  本地验证者公钥；多验证者 / 外部验证者文件整体拒绝。
- 合并在**内存中**对“现有记录 + 文件全部条目”逐条做几何检查：
  同 target 不同内容、区间包含 / 被包含、同 slot 不同块均判冲突；
  `source > target` 等畸形条目同样拒绝。
- 完全相同的条目（同 `signing_root` 且 epoch/slot 一致）视为幂等重导入，跳过。
- **任一冲突 => 整体拒绝，绝不部分写入**；只有全部通过才单次原子提交。
- 导出按 epoch/slot 规范化排序，输出可复现。

### 导入与签署并发

导入必须通过 `Signer.UnderLock(...)` 在与实时签署相同的互斥临界区内执行，
把“检查 + 合并 + 提交”线性化。`TestBusinessImportSignConcurrency`
以 50 轮随机交织验证：无论导入先于还是后于签署，同一 target epoch 始终
**恰好存在一条记录**，另一方得到明确的 `double_attestation`，结论可复现。

## 测试与业务覆盖

测试命名以 `TestBusiness*` 标注业务，`go test -v` 日志可直接看出覆盖范围：

| 业务 | 用例 |
| --- | --- |
| 正常签署 | 证明 / 提议与链状态一致时成功 |
| 并发与重复职责 | 同一职责 64 并发仅 1 次有效，其余 `duplicate_duty`；存储层 100 并发追加 |
| 状态不匹配 | 伪造块根、未来 slot、source 不符、外部验证者、畸形 epoch |
| 过期职责 | target 已最终化、超窗证明、历史 slot 提议 |
| 防罚没几何 | 同 target 双证明、区间被包含/包含、回退后双提议 |
| 链回退 | 记录不撤销；分叉证明 / 提议被拦截；finalized 不可回退 |
| 崩溃恢复 | 子进程 fsync 后被杀：库完整、记录内嵌签名、重放为重复、锁可重获 |
| fail-closed | 截断数据库拒绝启动；身份/GVR 不匹配拒绝打开 |
| EIP-3076 | 往返导出、幂等再导入、坏 GVR/外部验证者/未知字段/截断 JSON/畸形 epoch |
| 导入冲突 | 双证明、区间包含、双提议整体拒绝且零污染 |
| 导入并发签署 | 50 轮交织下单记录不变量恒成立（竞态检测） |

## 说明与边界

- 每个数据目录对应**单个验证者**；签名为确定性模拟值，不具备真实密码学效力。
- 并发确定性依赖“单进程互斥 + flock 跨进程锁 + 原子提交”三层保证。
