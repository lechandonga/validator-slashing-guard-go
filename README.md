# validator-slashing-guard-go

本地可运行的**多验证者签名客户端 + 防罚没保护**参考实现：一个进程同时托管
多个验证者身份，用本地生成的链状态与职责事件模拟运行，并按标准
[EIP-3076](https://eips.ethereum.org/EIPS/eip-3076) 互换格式迁移历史防罚没
记录。并发签署、并发导入/导出、进程重启与链状态回退交织时，签署结论始终
安全、确定且可解释。全程离线，无真实链数据、外部服务或凭据依赖。

## 快速开始

```bash
make test-race   # 竞态检测下的全部单测（需 CGO；输出含业务/用例覆盖日志）
make demo        # 端到端本地演示
```

## 能力一览

- 证明与区块提议签名；签名前校验请求与本地链状态一致。
- 同一进程托管多个验证者：请求身份（索引 + BLS 公钥）与本地身份不一致时
  `IDENTITY_MISMATCH` 明确拒绝、不留记录；未托管身份 `UNKNOWN_VALIDATOR`；
  不同身份的判定与导出按身份严格隔离。
- 可区分拒绝原因：`STATE_MISMATCH` / `DUTY_EXPIRED` / `DUTY_FUTURE` /
  `INVALID_REQUEST` / `DUPLICATE_DUTY` / `DOUBLE_VOTE` / `SURROUND_VOTE` /
  `DUPLICATE_BLOCK_SLOT` / `IDENTITY_MISMATCH` / `UNKNOWN_VALIDATOR` /
  `IMPORT_CONFLICT` / `IMPORT_INVALID` / `IMPORT_AMBIGUOUS`。
- 同一职责并发触发只产生一次有效签名（存储级临界区串行化）。
- 记录先于签名原子固化（临时文件 + fsync + rename + fsync 目录）；
  签名为记录的确定性派生，崩溃重启后无“已签无记录”、无误判已签。
- 链状态回退不撤销历史记录，新判定基于回退后状态。
- **标准 EIP-3076 v5 互导**：slot/epoch 为 JSON 字符串、十六进制带 `0x`、
  区块条目导出 `signing_root`；规范样例可原样导入，导出文件可被按规范实现的
  工具正确回读。冲突以“是否同一次签署（signing_root）”判定，信息不足时
  `IMPORT_AMBIGUOUS` 整体拒绝，不静默丢条目、不部分写入；重复导入幂等；
  多验证者文件按身份合并，未知身份默认整体拒绝（可显式整条跳过）；
  导入/签署/导出并发结论确定，导出始终是一致快照。

## 代码结构

- `internal/domain`：链状态、职责、签名根、记录与原因码。
- `internal/store`：崩溃安全的原子记录存储（含崩溃注入钩子）。
- `internal/guard`：准入规则、防罚没判定、确定性签名与重放。
- `internal/interchange`：EIP-3076 互导与安全合并。
- `internal/simulator`：本地链推进/回退与职责事件。
- `cmd/simdemo`：端到端演示。

详细规则、崩溃恢复论证与互导合并语义见 [`docs/DESIGN.md`](docs/DESIGN.md)。
