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
  `INVALID_REQUEST` / `VALIDATOR_MISMATCH` / `UNKNOWN_VALIDATOR` /
  `DUPLICATE_DUTY` / `DOUBLE_VOTE` / `SURROUND_VOTE` /
  `DUPLICATE_BLOCK_SLOT` / `HISTORY_WATERMARK` /
  `IMPORT_CONFLICT` / `IMPORT_INVALID`。
- 单进程同时托管多个验证者：职责按身份落密钥与记录分区；身份不匹配/不存在
  明确拒绝且不留痕；身份之间判定、导出、互导互不串。
- 同一职责并发触发只产生一次有效签名（存储级临界区串行化）。
- 记录先于签名原子固化（临时文件 + fsync + rename + fsync 目录）；
  签名为记录的确定性派生，崩溃重启后无“已签无记录”、无误判已签。
- 链状态回退不撤销历史记录，新判定基于回退后状态。
- 严格 EIP-3076（版本 5）互导：引号十进制整数、字段名/必填可选/长度全部
  按规范；官方样例可原样导入，导出含完整区块 `signing_root` 可被规范工具读回；
  缺签名根无法判定“同一次签署”时整体拒绝；重复文件幂等；导入/签署/导出
  并发结论确定，导出为一致快照；文件中未知身份默认整体拒绝（可显式跳过）。

## 代码结构

- `internal/domain`：链状态、职责、签名根、记录与原因码。
- `internal/store`：崩溃安全的原子记录存储（含崩溃注入钩子）。
- `internal/guard`：准入规则、防罚没判定、确定性签名与重放。
- `internal/interchange`：EIP-3076 互导与安全合并。
- `internal/simulator`：本地链推进/回退与职责事件。
- `cmd/simdemo`：端到端演示。

详细规则、崩溃恢复论证与互导合并语义见 [`docs/DESIGN.md`](docs/DESIGN.md)。
