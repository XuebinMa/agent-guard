# Broker-first 开发计划

**制定日期：2026-10-06。状态：方向已接受并进入实施；完成项以末节与
[实际进度](../broker-first-progress.md)为准，不将计划当作已发布能力。**

长期目标见[已接受的项目记忆](../decisions/2026-10-06-broker-first-scope.md)。
执行规则以 [CLAUDE.md](../../CLAUDE.md) 为准；版本、CI、公告和暂停状态以
[交付记录](../security-delivery-2026-10-04.md) 为准。本计划不覆盖已有发布暂缓决定。

## 1. 目标、范围和完成标准

目标不是识别所有危险 Shell，而是：**agent 无法绕开 broker 完成受保护的远端
Git 变更；broker 只执行人工批准的确切事务。**

首个部署闭环限定为：

- 一个 Linux 宿主；使用一个现有容器运行时，不开发新的沙箱后端。
- 一个普通仓库、一个受认证 HTTPS 目的地、一个分支、普通非强制推送。
- agent 在无远端写凭据的非特权容器中开发；人工从可信宿主终端运行现有 CLI。
- broker 二进制、配置、凭据、授权文件与持久记录不在 agent 的挂载/权限范围内。
- 不新增常驻服务、通用 RPC、自动审批、多租户或签名密钥管理。

这个配置是**新部署验收范围**，不是删除已有 API 或让其他受支持调用静默改变。
SSH/SCP、macOS/Windows 部署、force/delete/mirror/tag、多 refspec 等不纳入首次
硬边界声明。既有严格拒绝项保持拒绝；现有接口继续维护。

完成意味着支持范围、部署前提、负向测试和真实远端结果彼此一致；不意味着整个
项目没有漏洞，也不意味着所有工具路径、程序或平台都受到了同样隔离。

## 2. 已有进展：复用，不重做

以下来自本地 `e1a0a0a5fd956186e67e9c235451cbfa2fb4b260` 与已有验证记录。
它们是已核实基线，不是新补丁的验证结果：

| 能力 | 当前状态 | 后续处理 |
| --- | --- | --- |
| 精确 push URL、OID、远端 tip/lease 与执行前重校验 | 已实现并有测试 | 复用；只补实际缺口 |
| 临时裸仓库、hooks/config 隔离与严格布局/协议检查 | 已实现并有测试 | 保持，纳入部署组合验收 |
| R3：HTTPS helper/header 作用域、path context、redirect 拒绝 | 已修复 | 不重新开发；其他认证方式仍属部署前提 |
| R7：deny 修正不扩大 allow/escape 授权 | 已修复，sec63/sec64 | 保留兼容性锁和 parity 场景 |
| grant 单次消费、过期、策略变更与并发消费 | 已实现并有测试 | 检查实际入口与部署权限，不重造授权协议 |
| CLI 确认输入 | 当前读取 stdin，未强制可信 TTY | 严格部署的宿主启动层需新增 TTY 前置要求；不称现有 CLI 已拒绝管道确认 |
| F1–F44 修复与绑定/平台验证 | 已整合，具体覆盖见两轮报告 | 不按新计划重新修一遍；维护其回归 |
| broker receipt 可选签名 API | 已实现 | CLI 目前传入 `None`；先接受宿主保存的 unsigned attempt record |
| `guard-verify verify/verify-log` | 验证 SDK `ExecutionReceipt` | 不当作 `PushReceipt` 验证器 |
| `doctor` | 报告 sandbox capability | 不当作凭据隔离证明 |

参考：[首轮报告](../security-review-2026-10-04.md)、
[第二轮报告](../security-review-2026-10-05.md)、
[broker 执行路径](../../crates/agent-guard-broker/src/execute.rs)、
[CLI 收据路径](../../crates/agent-guard-cli/src/main.rs)、
[现有边界测试](../../crates/agent-guard-broker/tests/security_boundary.rs)。

新解析器报告尚未关闭：独立工作区四文件补丁的五项诊断为 **3 通过 / 2 失败**。
这些是 parser/validator 诊断，不等于完整 SDK 或 broker 利用链已被证明。
临时日志可能消失，因此下一步先保存证据，不把旧 CI 绿灯套到这个补丁上。

## 3. 顺序和工作量

工作量是个人开发者的规划估算，不是交付日期；CI、权限、版本选择的等待时间不计入。
每阶段先做缺口盘点，若现有实现已满足要求，就补证据而不新增代码。

| 阶段 | 依赖 | 产出 | 估计有效工作量 |
| --- | --- | --- | --- |
| P0 项目记忆与范围冻结 | 无 | 已接受决策、入口链接、本计划 | 本轮文档工作 |
| P1 有限安全维护收尾 | P0 | 当前已确认解析问题的永久回归与修复 | 1–3 天，失败时重新估算 |
| P2 支持契约与声明对齐 | P0；P1 后定稿 | Shell 支持范围、Git 部署契约、真实能力表 | 1–2 天 |
| P3 单一隔离部署参考 | P2 | 受控启动配置、宿主操作流程、前置检查 | 2–4 天 |
| P4 认证部署端到端验收 | P3 | 本地认证 fixture、不可旁路测试、CI 证据 | 2–4 天 |
| P5 用户流程与运维验收 | P4 | 操作指南、代表性基准、一次完整演练 | 1–2 天 |
| R 维护版本交付 | P1 + 所需声明修正 + 新版本决定 | 修复产物、安装验证、准确公告 | 单独排程 |

**维护版本不必等全部 P3–P5 完成。** 尚未完成部署闭环时继续明确“不提供该部署
硬边界证明”，不能为了产品化目标无限延迟已有安全修复。

## 4. P1：有限安全维护收尾

### S1 保存已有补丁与失败证据

- 只读确认另一会话工作区、补丁和诊断日志仍在；联系/确认所有权，不覆盖其变化。
- 把完整变更、基线 SHA、失败输入类别、预期决策和日志迁入可持续保存的工作记录。
- 后续在独立分支/工作区处理；按既有授权正常交付，不强推、不直接改 main。
- 若临时文件已失，依据记录重新建立安全、decision-only 失败测试，不执行负向命令。

验收：可以在指定基线上独立重现失败；补丁状态明确，不再依赖会话临时目录。

### S2 关闭已确认缺口，不扩展成通用解释器

永久测试覆盖四类：

1. 引号外控制字节造成的词法/注释分歧。
2. 计算型命令字；包括不支持的 zsh 命令字形式与非法空名赋值前缀。
3. 外层引用数据中嵌套的可执行文本，不能误用外层“数据”判断豁免内层检查。
4. assignment-looking 字面命令词与真正赋值节点的区分。

正向控制覆盖正常静态命令、合法赋值、引号内普通数据和已支持的包装形式。
优先使用 AST 节点身份与现有 `TooComplex`/opaque 路径；不增加新的 launcher 名单。
无法可靠解释的结构保守拒绝，不把原有 deny 降为 ask。

受影响位置：[AST](../../crates/agent-guard-validators/src/bash/ast.rs)、
[tokenize](../../crates/agent-guard-validators/src/bash/tokenize.rs)、
[wrappers](../../crates/agent-guard-validators/src/bash/wrappers.rs)。

验收：新单元测试先红后绿；修复没有误伤上述正向控制；嵌套可执行区域独立验证。
若选择不支持一种语法，文档和结果必须说明是“不支持/无法验证”，而不是“安全”。

### S3 锁住真正调用路径

- 在[SDK 安全回归](../../crates/agent-guard-sdk/tests/security_regression.rs)中，
  用真实 Guard 和实际 preset 断言预期决策；不只看 parser 返回值或 audit 文本。
- 为受影响的绑定加入[共享场景](../../tests/cross-language-parity/fixtures/scenarios.json)。
- 实际运行 Rust/Python/Node comparator；相等不等于正确，SDK 仍需期望断言。
- 用安全 JSON 输入验证 hook 决策与提示；不运行负向 Shell 字符串。
- 新测试编号在实施时检查冲突，不覆盖已有 secNN 或他人的测试。

若 SDK 已被其他层拒绝，记录为 parser/validator 的纵深缺陷，不能据此声称
完整执行链已被绕过；低层回归仍保留，覆盖和严重性按实际证据说明。

验收：修复在入口层有效、跨语言一致，所有既有拒绝与兼容回归保持。

### S4 新冻结树验证与有限结案

新树运行完整本地门禁、strict all-target lint、独立 parity 和精确 head CI。
查看每项实际 conclusion，不只看汇总状态。确认修复/声明范围后结案，不要求证明
“全世界所有 Shell 写法均安全”。新增报告另行按实际影响分级，不能忽略已证实回归。

## 5. P2：明确产品与执行契约

### C1 固定威胁模型

agent 可控制仓库内容、提交、工具输入和自己的容器进程；不信任其计划解释。
隔离范围包括 agent runtime 及其文件/MCP/hook 等工具路径，不只包括 Bash。
可信宿主、容器运行时/内核、Git 二进制、专用认证程序和审批者属于可信计算基。
宿主被攻陷、恶意人工批准、所有工具的通用数据外流不属于首次里程碑的保证。

列出每个资产及其权限：仓库、远端写凭据、认证 socket、broker config/policy、
grant store、二进制/PATH/HOME、receipt 目录、审批终端、容器管理 socket。
明确 agent 能否读、写、使用或调用；“读不到密钥”不等于“不能使用认证能力”。

### C2 Shell 支持与维护契约

- 声明实际解析方言和执行方言；Bash AST 不应代表所有宿主 Shell。
- 自动分析限于有明确语义与回归的范围；未知结构不获得新增执行权限。
- 普通开发执行留在无写凭据的隔离环境；hook 只是 advisory 提示与记录。
- 保留已发布能力和公告义务；如需改变兼容行为，列迁移办法并单独审核。
- 清理“覆盖整个任意执行类”等过度声明，不把声明修正计为漏洞修复。

产出：在现有概念/操作指南中增加支持范围和维护规则，不新增通用 Shell 产品。

### C3 校准现状文档

依据源码与 CI 校准文档，而不是复制旧结论：Linux 已有 opt-in native BPF，
`FullAccess` 会跳过过滤；默认构建仍是 noop。BPF 本身不证明路径或凭据隔离。
Python 已有真实 framework CI；测试指南的 gate 列表需要与实际源码对应。
`verify.sh full` 不运行独立 parity comparator，应修正相反的文档表述。

验收：README、ROADMAP、部署/测试指南与 CLI 的能力、默认值、限制一致；
没有把默认安装、`doctor` 或 unsigned receipt 写成隔离证明。

## 6. P3：一个受控隔离部署

### D1 选择一个运行方式

只提供一个受维护的 Linux 非特权容器参考配置；Docker/Podman 等候选在实施前
比较现有条件后选定其一，不同时维护多套后端。首次不新建 daemon/RPC。

agent 只获得专用开发仓库及必要的公开依赖。宿主人工通过现有 CLI 预览、批准和
执行。不得以 agent 传来的“已批准”字段、提交说明或 Shell 文本替代宿主批准。
整个 agent runtime 与其工具必须落在该权限范围内；只把 Shell 放进容器、却让
文件工具、MCP、hooks 或 host handler 使用宿主凭据，不满足本部署契约。

### D2 保护权限与配置

- 不挂载宿主 HOME、SSH/认证 socket、broker config/policy、grants、records，
  也不传入远端可接受的 token 或 broker 特权调用能力。
- 不挂载容器管理 socket，不启用特权模式或不必要的宿主 PID/网络命名空间。
- 不代理到具备宿主读写/认证能力的 MCP 或 host handler；可用工具路径逐项登记，
  新增路径必须重新验收，不能用容器内 Shell 的测试代替宿主工具验证。
- 选择明确的非特权身份和最小挂载；broker 资源不能因 UID 映射、共享 inode 或
  可写父目录而间接可达。新建专用开发卷，不接入有共享敏感 inode 的宿主目录。
- 固定宿主二进制来源、受控 PATH/HOME 和专用最小 HTTPS 配置；agent 不能改写。
- grants、policy 和 unsigned attempt records 保存在 agent 无法篡改的宿主目录。
- 宿主 `--yes` 不向 agent 暴露为有凭据执行路径；严格宿主启动层校验 stdin/stdout
  为 agent 无法控制的可信 TTY，缺失则拒绝该严格流程。当前 CLI 仅读取 stdin，
  管道确认仍可能通过；TTY 前置检查是待开发的部署要求，不是已有 CLI 保证。
- 需要的能力不可用、权限不满足或检查无法完成时，不启动“严格部署”；可明确
  提供 advisory 模式，但不得静默降级或给它同样的安全标签。

R1 Windows handles、R2 通用共享 inode 问题继续记为未关闭。上述部署限制只缩小
本配置的风险，不算修复那些 SDK/平台问题。

### D3 可审查的启动前检查

优先复用运行时配置检查，增加小型固定配置检查器/测试，不构建通用主机证明系统。
检查敏感挂载、环境键、权限、必要路径与受支持配置；未知可扩大权限的配置拒绝。
报告分别给出“配置检查通过”和“隔离验收通过”，不假称能够发现宿主所有旁路。

验收：坏配置会在 agent 启动前失败；正常配置能开发、提交和测试；不以禁止所有
网络或让两端都无法推送冒充隔离成功。

## 7. P4：真实能力的安全端到端测试

先实现临时本地认证 Git 服务及独立远端状态观察器：使用临时仓库、合成身份、
一次性测试凭据和受控 TLS；没有真实用户 token，不推第三方仓库。
公共 CA/地址可提供给 agent；认证凭据只交给可信宿主与本地服务。
agent 必须能连到测试服务，避免把断网失败当作认证隔离。

测试均有超时、明确资源所有权与限定临时目录；失败保留日志，不隐藏 skip。
若环境不具备容器能力，标为未运行；专用 Linux 验收 job 必须具备能力且不得跳过。

| 不变量 | 负向测试 | 正向/独立控制 |
| --- | --- | --- |
| I1 无执行授权不能变更 | missing/expired/tampered/replayed grant 的执行调用不推送；不触发该执行路径的网络/认证程序 | 有效 grant 只消费一次；独立远端 ref 核对 |
| I2 批准内容不可漂移 | 改 URL、OID、ref、policy/remote tip 后拒绝 | 未变化的事务正常完成；stale lease 失败无 hook 副作用 |
| I3 仓库不能取得 broker 权限 | 既有 hook/config/alternates/promisor/symlink fixtures，只拒绝或忽略受禁配置，无哨兵副作用 | 普通 refs/objects 仓库可用 |
| I4 认证只面向批准范围 | 越界初始 URL 在连接前拒绝；获批 URL 返回 redirect 后失败，且不连接 redirect target | 合法作用域能向本地认证服务推送；独立目标监听器证实未连接 |
| I5 agent 不能自行 mutation | 在 agent 容器中直接使用现有 Git 客户端，向本地测试远端做受限 fixture 变更，认证失败、ref 不变 | 同一服务从宿主 broker 批准后成功；agent 连通性正常 |
| I6 agent 不能篡改权威资源 | 对合成配置、grant/record、宿主路径/socket 的读写/访问检查被阻止 | 仓库内正常写入、构建、提交成功 |
| I7 收据与实际结果一致 | 拒绝/stale lease 含实际 transaction 与已消费 grant ID；伪造/失败不写成功结果 | 只有获批 ref 更新到精确 OID；独立远端状态符合记录 |
| I8 请求者不等于批准者 | agent 无法通过账本文件、host CLI 或 `--yes` 获得有效授权；严格启动层拒绝非可信 TTY 输入 | 可信宿主批准成功；取消、EOF 与严格启动层拒绝后无变更 |

I1 区分 preview 和 execution：可信宿主的 preview 可在通过目的地/配置检查后查询
远端；“无 grant 不联网”针对未授权 execution，不否定受控预览所需的读查询。

复用现有 `security_boundary.rs`、grant 和 CLI 测试，尤其：

- `approved_push_url_is_the_only_remote_updated_and_receipted`
- `preview_rejects_a_destination_outside_trusted_helper_scopes_before_connecting`
- `changed_push_url_is_rejected_before_network_and_burns_the_grant`
- `repository_hooks_and_execution_config_are_not_loaded`
- `a_git_refusal_keeps_the_spent_grant_without_running_the_source_hook`
- `concurrent_spenders_produce_exactly_one_winner`

新增重点是**跨进程/容器权限闭环**，不把重复的库测试当新增隔离证明。
源码位置：[broker tests](../../crates/agent-guard-broker/tests/transaction.rs)、
[grant tests](../../crates/agent-guard-broker/tests/grant.rs)、
[CLI tests](../../crates/agent-guard-cli/tests)。

若验证现有 OS 后端，直接测试真实后端，使用本来可写的临时 workspace/outside
文件作双向控制。SDK 提前拒绝、普通文件权限拒绝或 noop 分支 skip，都不能证明
OS 资源限制已经生效。现有 GATE 3 不是整个部署的隔离证明。

验收：I1–I8 在专用 job 全部实际执行；失败使 job 失败；版本与 SHA、配置、运行时、
执行/跳过情况与独立远端状态均可追溯。指标不是新增测试数量，而是不变量覆盖。

## 8. P5：用户流程与运维验收

- 写一条完整流程：启动隔离环境 → agent 开发 → 宿主预览 → 人工确认/取消 →
  broker 执行 → 查看宿主持久记录。默认安装与严格部署分别说明。
- 用一个真实用户任务验证这条流程是否值得用；先完成本地合成 fixture 演练。
  若需真实 GitHub 写操作，单独取得该仓库/分支的授权，不在本计划中自动执行。
- 记录代表性仓库对象大小、快照复制时间、峰值临时磁盘、冷/热条件、机器与方法。
  基准可复现，不把小仓库数值外推大仓库；配额/磁盘不足须安全拒绝。
- 故障手册覆盖取消、超时、stale lease、配置不匹配、网络失败、磁盘不足与升级。
- 当前 CLI 使用 unsigned record，指定 `--receipt` 才持久化；不声称第三方可验签
  或可从记录证明隔离。该限制不能被 UI 或发布文案省略。

验收：维护者可按照文档完成正/负演练并定位失败；没有依赖默认全部信任的捷径。
用户认为审批与部署成本可接受，才考虑扩大支持。

## 9. 验证与维护版本交付

### 按改变的风险选择验证

文档变化运行 `./scripts/verify.sh docs` 和 `git diff --check`。
实现阶段冻结新树后运行：

```bash
./scripts/verify.sh full
cargo clippy --workspace --exclude agent-guard-python --all-features --all-targets -- -D warnings
```

另外在已按 CI 安装 Python/Node 原生绑定的解释器中执行：

```bash
python3 tests/cross-language-parity/compare.py
```

`full` 当前不包含这个独立 comparator，不能省略。平台测试使用对应 OS/feature，
以当前 [CI workflow](../../.github/workflows/ci.yml) 和相关 crate 指令为准。
新部署验收另外提供专用 Linux job，不以其他平台的编译成功证明隔离。

同一未变树不重复已有成功门禁；每个新 head 必须得到其自身证据。必要失败测试
不能静默 skip，环境问题按正常权限流程处理，不能绕保护或削弱测试。

### 当前发布暂缓与版本待决

The historical hold below was resolved by the direct user instruction on
2026-10-06 (Pacific time): self-use first, stop the old run and publish a
successor. Run `37424509488` is now cancelled; `v0.2.7` is still immutable.
Use the [0.2.8 delivery checkpoint](../release-028-delivery.md) for current
authorization/gates, and the [self-pilot record](broker-first-self-pilot.md)
for P5. The old snapshot is retained below rather than treated as current.

- `v0.2.7` 已固定在 `e1a0a0a5fd956186e67e9c235451cbfa2fb4b260`，不得移动。
- 注册表无 0.2.7 是交付记录中 `2026-10-06T10:45:10Z` 的快照，不当作实时事实。
- 是否停止旧发布并使用后继版本，仍按已有待答问题处理；不预填 0.2.8，
  不重复询问、不审批环境、不写注册表或公开公告。
- 同意本计划不自动回答上述版本选择。恢复交付前重新核对当前远端与注册表。

获相应决定与授权后，交付顺序保持：新精确 PR head CI → 正常合并 → 最终 main
SHA 的 push CI → tag/preflight → 发布环境审核 → 八个 Rust crate、五个 wheels、
npm provenance 与精确版本隔离 `--locked` 安装 → 公告与 published markers。

原 GHSA 更正保留原三问题范围与受影响 PyPI 包；新问题的受影响版本和披露单独
核实。未发布前不标成可用补丁，不虚构 CVE。既有
[GHSA 草稿](../ghsa-j64p-f672-v3jq-correction-draft.md)中的 0.2.7 文字需按最终
决定调整并重新审阅，不能直接照发。

### 阻塞与非阻塞

阻塞：已确认本轮缺陷未关闭、既有 deny 被削弱、broker 不变量失败、公告涵盖的
修复仍不完整、新 head/最终 main 门禁未通过、版本/发布授权缺失、产物未包含修复。

不自动阻塞一个诚实限定的维护版本：未承诺的新 Shell/程序语义、新平台或认证
方式、非产品面的开发依赖告警、非关键性能优化。R1/R2 等仍列为未关闭；
一旦本次新增承诺依赖其安全性，它们就必须阻塞该承诺，不能用文档豁免。

## 10. 后续可选工作与停止扩张规则

首个部署闭环完成后，才评估以下小任务；都不是本轮默认需求：

- 将现有 broker 签名 API 接到 CLI，并提供明确区分 `PushReceipt`/`ExecutionReceipt`
  的离线验签入口；不开发新密钥管理平台。
- 对已声明静态 Shell 子集做有预算、无害且隔离的差分测试；保留失败最小样本。
  引入 parser/Unicode 属性库前先验证方言、版本、覆盖和依赖成本。
- 仅在实际用户需要且现有边界证据稳定时，评估第二平台/第二认证方式。

每个新需求先回答：是否修复已承诺行为或证实缺陷？是否直接加强确切 Git 事务
与部署权限？是否能复用成熟实现？谁需要它？四项不清楚时不自动纳入开发。
没有新证据的反复全量审核，不作为默认产品迭代方式。

## 11. 进度、恢复与完成定义

- [x] P0：用户决策写入仓库记忆，并从 CLAUDE/ROADMAP/文档入口链接。
- [x] P1：S1–S4；四类有限修复和红→绿证据、完整本地门禁、70项
  parity、strict lint，`c1f9ee1` 的20项CI均成功。
- [x] P2：C1–C3；契约与相关文案校准，版本与默认能力声明保持区分。
- [x] P3：D1–D3；固定 Linux Docker 参考与20项配置测试已实施；
  `5f8e714` 的必需 native CI 已实际完成启动/开发/审批闭环。
- [x] P4：I1–I8；host TLS 9项、实际执行入口5项、driver 10项测试
  已通过；新head21项CI成功，native job与同job69项broker/23项CLI
  测试共同覆盖不变量，零失败/忽略。只验收该固定合成Linux配置。
- [ ] P5：基准方法、10项测试和运维指南已实施；测试专用探针另已
  测得合成fixture复制阶段/完整快照耗时与保留逻辑字节量，不改生产API。
  真实用户任务、代表性仓库容量、冷/热条件与完整物理峰值仍待验收。
- [ ] R：有限安全收尾版本与公告交付，仍受版本待决节点约束。

最初制定计划的文档轮只完成项目记忆与入口链接；其22项脚本/208篇文档
结果是历史快照，不是现在的实现验证。后续用户明确授权按本计划实施，
独立工作区已有 `c1f9ee1` 与[草稿 PR #171](https://github.com/XuebinMa/agent-guard/pull/171)。
具体新树结果、日志、CI及剩余项见[进度记录](../broker-first-progress.md)。
原工作区的他人修改、发布hold和不可移动的 `v0.2.7` 保持原样。

每次推进只更新已实际完成的任务，记录 commit、命令退出码、日志/CI URL、覆盖
范围、未运行项与阻塞；计划、已实现、已验证、已发布分别记录。工作量偏离估计
时重新排序，不自动增加横向功能或用新功能掩盖未关闭缺陷。

既有恢复任务先读本计划与交付记录，再看 git status/远端状态，只推进未完成项；
额度恢复后按正常权限继续，不消费 reset、不购买额度，不覆盖他人的变化。
本计划本身不创建或扩大自动化权限；原发布 hold 优先，未答问题不能由心跳代答。

整体完成定义：有限安全收尾完成、首个部署所有验收实际通过、声明与产物相符、
用户流程可用且可追溯。在此之前不标“全面安全”或暂停未完成交付来制造完成状态。
