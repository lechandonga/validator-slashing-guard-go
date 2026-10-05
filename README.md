# validator-slashing-guard-go

本地可运行的**验证者签名客户端 + 防罚没保护**参考实现：用本地生成的链状态与
职责事件模拟验证者运行，使并发触发、进程重启与链状态回退交织时的签署结论
始终安全、确定且可解释。全程离线，无真实链数据、外部服务或凭据依赖。

## 快速开始

```bash
make test-race   # 竞态检测下的全部单测（需 CGO；输出含业务/用例覆盖日志）
make demo        # 端到端本地演示
```

## 能力一览

- 证明与区块提议签名；签名前校验请求与本地链状态一致。
- 可区分拒绝原因：`STATE_MISMATCH` / `DUTY_EXPIRED` / `DUTY_FUTURE` /
  `INVALID_REQUEST` / `DUPLICATE_DUTY` / `DOUBLE_VOTE` / `SURROUND_VOTE` /
  `DUPLICATE_BLOCK_SLOT` / `IMPORT_CONFLICT` / `IMPORT_INVALID`。
- 同一职责并发触发只产生一次有效签名（存储级临界区串行化）。
- 记录先于签名原子固化（临时文件 + fsync + rename + fsync 目录）；
  签名为记录的确定性派生，崩溃重启后无“已签无记录”、无误判已签。
- 链状态回退不撤销历史记录，新判定基于回退后状态。
- EIP-3076 风格（版本 5）互导：解析/冲突失败整体拒绝、不部分写入；
  重复条目幂等；导入与签名并发结论确定。

## 代码结构

- `internal/domain`：链状态、职责、签名根、记录与原因码。
- `internal/store`：崩溃安全的原子记录存储（含崩溃注入钩子）。
- `internal/guard`：准入规则、防罚没判定、确定性签名与重放。
- `internal/interchange`：EIP-3076 互导与安全合并。
- `internal/simulator`：本地链推进/回退与职责事件。
- `cmd/simdemo`：端到端演示。

详细规则、崩溃恢复论证与互导合并语义见 [`docs/DESIGN.md`](docs/DESIGN.md)。
