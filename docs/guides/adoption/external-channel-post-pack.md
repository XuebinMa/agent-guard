# External Channel Post Pack

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Ready To Publish |
| **Audience** | Maintainers, DevRel, Community Outreach |
| **Version** | 1.0 |
| **Last Reviewed** | 2026-04-14 |
| **Related Docs** | [Social Post Templates](social-posts.md), [GitHub Discussions Announcement](discussions-announcement.md), [Release Announcement Template](release-announcement.md), [Three-Minute Proof](../getting-started/three-minute-proof.md) |

---

This is a first-wave outreach pack for maintainers and DevRel. It is a publishing convenience document, not a core product or onboarding guide.

---

This pack is the first outbound wave for `agent-guard`.

It is designed to help you publish quickly across multiple channels without rewriting the same message each time.

Recommended publishing order:

1. GitHub Release
2. GitHub Discussions
3. X
4. Reddit
5. LinkedIn
6. Chinese builder communities

The goal is consistency:

- same problem statement
- same proof demo
- same 2-3 links

---

## Shared Link Set

Use these links across channels:

- Release: https://github.com/XuebinMa/agent-guard/releases/tag/v0.2.0-rc1
- Discussion: https://github.com/XuebinMa/agent-guard/discussions/1
- Three-Minute Proof: https://github.com/XuebinMa/agent-guard/blob/main/docs/guides/getting-started/three-minute-proof.md
- Node Quickstart: https://github.com/XuebinMa/agent-guard/blob/main/crates/agent-guard-node/examples/quickstart/README.md
- Framework Support Matrix: https://github.com/XuebinMa/agent-guard/blob/main/docs/framework-support-matrix.md

---

## 1. X Post

```text
AI agents with shell tools should not rely on “please be safe” prompts.

We built `agent-guard` to put a policy gate and OS sandbox in front of AI tool calls.

Fastest proof:
- safe command: allowed
- git push: blocked / approval-required
- destructive command: stopped before execution

Try it:
npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:proof --prefix crates/agent-guard-node

Release:
https://github.com/XuebinMa/agent-guard/releases/tag/v0.2.0-rc1
```

Optional reply thread follow-up:

```text
Best-fit users right now:
- code agents with bash or shell access
- tool-calling runtimes exposed to LLMs
- platform/security teams that want an auditable tool boundary

Quick links:
Three-Minute Proof:
https://github.com/XuebinMa/agent-guard/blob/main/docs/guides/getting-started/three-minute-proof.md

Discussion:
https://github.com/XuebinMa/agent-guard/discussions/1
```

---

## 2. Reddit Post

Suggested communities:

- `r/LocalLLaMA`
- `r/ArtificialInteligence`
- `r/MachineLearning` only if framed as tooling / security infra rather than product promotion
- agent or developer-tooling communities where self-promo is acceptable

Suggested title:

`We built agent-guard to put a policy and sandbox boundary in front of AI tool calls`

Body:

```text
Most AI agent stacks still rely too heavily on a fragile assumption: if the prompt says “be safe,” the tool call will probably be safe too.

That breaks down quickly when the runtime can call shell tools, file-capable tools, or other high-risk handlers.

We built `agent-guard` to put a real decision boundary in front of AI tool calls.

What it does:
- checks tool calls against policy before execution
- can route execution through an OS sandbox path
- supports auditable outcomes and deeper trust workflows

The easiest way to evaluate it is the proof demo:

npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:proof --prefix crates/agent-guard-node

That demo shows:
- a safe command still works
- a risky command no longer silently executes
- a destructive command is stopped before execution

Links:
- Release: https://github.com/XuebinMa/agent-guard/releases/tag/v0.2.0-rc1
- Three-Minute Proof: https://github.com/XuebinMa/agent-guard/blob/main/docs/guides/getting-started/three-minute-proof.md
- Discussion: https://github.com/XuebinMa/agent-guard/discussions/1

If you are building code agents or tool-calling runtimes, I would especially love feedback on where your current shell/tool boundary lives today.
```

---

## 3. LinkedIn Post

```text
AI agents are getting more useful as they gain access to tools, but that also means the execution boundary matters much more than it used to.

We have been building `agent-guard` around a simple idea:
put a policy gate and OS sandbox in front of AI tool calls so shell and other high-risk tools do not execute on prompt trust alone.

What makes the project easy to evaluate now:
- a 3-minute proof demo
- a Node quickstart
- framework support guidance
- release and discussion threads for feedback

If you want the shortest proof, run:

npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:proof --prefix crates/agent-guard-node

Release:
https://github.com/XuebinMa/agent-guard/releases/tag/v0.2.0-rc1

Discussion:
https://github.com/XuebinMa/agent-guard/discussions/1
```

---

## 4. Hacker News Style Post

Suggested title:

`Show HN: agent-guard, a policy and sandbox boundary for AI tool calls`

Body:

```text
We built agent-guard for a narrow but important problem: AI agents that can call tools, especially shell-like tools, should not rely on prompt trust alone.

The project puts a policy gate in front of tool calls and can route execution through an OS sandbox path.

What is available today:
- Node adapters for LangChain-style tools and OpenAI-style handlers
- Rust SDK path
- Python binding
- a short proof demo and quickstart

Fastest way to evaluate it:

npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:proof --prefix crates/agent-guard-node

Links:
- Release: https://github.com/XuebinMa/agent-guard/releases/tag/v0.2.0-rc1
- Three-Minute Proof: https://github.com/XuebinMa/agent-guard/blob/main/docs/guides/getting-started/three-minute-proof.md
```

---

## 5. V2EX / 中文技术社区

建议标题：

`agent-guard：给 AI Agent 的工具调用加上一层策略与沙箱边界`

正文：

```text
很多 AI Agent 一旦接上 bash、文件系统、外部工具，真正危险的地方就不再是 prompt 本身，而是“工具调用已经开始碰宿主机了”。

我们最近把 `agent-guard` 整理成了一个更容易试用的版本，核心思路很简单：

给 AI 工具调用前面加一层 policy gate，并在可用时把执行放进 OS sandbox 路径里，这样高风险命令就不会只靠 prompt 来约束。

现在最容易理解项目价值的方式是直接跑 proof demo：

npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:proof --prefix crates/agent-guard-node

你会看到三件事：
- 安全命令可以正常执行
- 像 git push 这种高风险命令不会静默执行
- 像 rm -rf / 这样的破坏性命令会在执行前被拦下

适合当前第一批用户的场景：
- 有 bash / shell 能力的 code agent
- 暴露工具调用给 LLM 的平台或应用
- 关心审计、收据、执行边界的安全 / 平台团队

链接：
- Release: https://github.com/XuebinMa/agent-guard/releases/tag/v0.2.0-rc1
- 3 分钟验证: https://github.com/XuebinMa/agent-guard/blob/main/docs/guides/getting-started/three-minute-proof.md
- 讨论区: https://github.com/XuebinMa/agent-guard/discussions/1
```

---

## 6. 掘金 / 知乎 / 公众号风格短文

建议标题：

`AI Agent 的工具调用，不能只靠 Prompt 保证安全`

正文：

```text
如果一个 AI Agent 已经能调用 bash、文件系统或者其他高风险工具，那么真正需要控制的地方，其实是工具执行边界。

我们做了一个项目叫 `agent-guard`，核心目标不是做新的 Agent 框架，而是在 AI 工具调用前加一层 policy gate，并在可用时走 OS sandbox 路径。

这样一来，风险命令不会直接从模型流进宿主机执行。

为了降低试用门槛，我们把第一条验证路径做成了一个 3 分钟 proof demo：

npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:proof --prefix crates/agent-guard-node

这个 demo 会清楚展示：
- 安全命令通过
- 风险命令被拦截或要求确认
- 破坏性命令在执行前被阻断

项目地址和说明：
- Release: https://github.com/XuebinMa/agent-guard/releases/tag/v0.2.0-rc1
- 三分钟验证: https://github.com/XuebinMa/agent-guard/blob/main/docs/guides/getting-started/three-minute-proof.md
- 讨论反馈: https://github.com/XuebinMa/agent-guard/discussions/1
```

---

## 7. Suggested Posting Sequence

If you are publishing manually, use this order:

1. X
2. Reddit or Hacker News
3. LinkedIn
4. V2EX / 掘金 / 知乎等中文社区

That sequence helps you:

- test the English positioning first
- get technical feedback next
- then adapt for professional and Chinese-language audiences

---

## 8. After Posting

Once the first wave is out, watch for:

- which link gets clicked most
- whether people understand the shell-tool wedge immediately
- whether people ask for framework support details
- whether people ask for real integration examples instead of architecture

Those replies should drive the next product and documentation step.
