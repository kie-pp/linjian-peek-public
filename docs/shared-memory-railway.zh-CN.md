# Railway 共享记忆部署说明

本补丁以 `0.3.7.9` 为基线。当前生产 `main` 开启自动部署，禁止直接把实验分支推送或合并到生产分支。先在独立 Railway 环境验证，再安排受控上线。

## 1. 新建 PostgreSQL

在 Railway 项目中新增 PostgreSQL 服务。不要把现有掌心窗 JSON、手机日记、状态或关怀记录迁入数据库；共享记忆使用独立表。

在 `zhangxinchuang-server` 的 Variables 页面，通过 Railway reference 将 PostgreSQL 提供的 `DATABASE_URL` 引入 server。不要复制数据库连接串到源码或公开文档。

## 2. 生成凭据

在本地安全终端分别生成三个互不相同的随机值：

- `MEMORY_CREDENTIAL_PEPPER`
- `MEMORY_BOOTSTRAP_READER_TOKEN`
- `MEMORY_BOOTSTRAP_WRITER_TOKEN`

可在安全的本地 PowerShell 中把下面命令分别执行三次，并立即把每次输出存入对应的 Railway secret variable；不要把输出写入仓库或聊天记录：`python -c "import secrets; print(secrets.token_urlsafe(32))"`。

reader 只拥有 `memory:read`；writer 拥有 `memory:read` 和 `memory:write`。真实值只保存到 Railway secret variables 和对应客户端的安全配置。

## 3. 首次 migration 与 bootstrap

在 server 设置 `MEMORY_ENABLED=true`、`DATABASE_URL`、pepper 及两个 bootstrap Token。server 启动时按文件名顺序、在事务中幂等执行 `server/migrations/*.sql`，并把成功版本记入 `schema_migrations`。空库只创建一个内部随机 namespace，并把 reader/writer 凭据摘要映射到同一 namespace。

只有同一个 namespace 下同时存在有效 reader 和 writer 凭据时，`memory_ready` 才为 true。健康接口只显示 `memory_enabled`、`memory_ready` 和脱敏状态，不得出现数据库地址、namespace、凭据或摘要。

确认初始化完成后，可以移除两个 `MEMORY_BOOTSTRAP_*` 变量；数据库中的凭据摘要仍然有效。保留 pepper，否则后续鉴权摘要无法匹配。

## 4. 客户端配置

Cyberboss 配置 server 的 `/api/memory/context` 地址，并只使用 reader Token。请求体只能包含 `query` 和 `history_limit`，不得包含 namespace 或 `device_id`。

`zhangxinchuang-mcp` 使用 writer Token，通过 `MEMORY_MCP_WRITER_TOKEN` 调用 server。`MEMORY_MCP_TOOLS_ENABLED` 与 `MEMORY_MCP_ENDPOINT_ENABLED` 默认必须保持 `false`。

## 5. 验证后启用 MCP 工具

公开 `/mcp` 始终不注册共享记忆工具，保持现有 ChatGPT 掌心窗连接兼容。共享记忆只通过独立的 `/mcp-memory` 暴露；该入口必须先完成 OAuth 2.1 Bearer Token 校验，缺少认证时返回 401，不会创建 MCP server 实例，也无法列出工具。

推荐直接使用成熟身份提供方，不在掌心窗内实现授权服务器：

- **WorkOS AuthKit（优先）**：提供 MCP/OAuth、动态客户端注册、托管登录与 JWKS；当前 AuthKit 前 100 万 MAU 免费，但生产环境需要添加账单信息。配置说明：<https://workos.com/docs/authkit/mcp>，价格：<https://workos.com/pricing>。
- **Auth0（备选）**：提供 MCP OAuth 指南、PKCE、资源参数和 JWKS；当前 Free 计划最高 25,000 MAU，无需信用卡即可注册。配置说明：<https://auth0.com/ai/docs/mcp/get-started/authorization-for-your-mcp-server>，价格：<https://auth0.com/pricing>。

两种方案都必须签发 audience 精确指向 `/mcp-memory` 的 JWT，并提供 `memory:read`、`memory:write` scope。MCP 服务只作为 OAuth resource server，使用 `jose` 从 `MEMORY_MCP_OAUTH_JWKS_URL` 校验签名，同时校验 issuer、audience、过期时间和 scope；不会签发 Token，也不会保存 ChatGPT 的 access token。

启用前配置：

- `MEMORY_MCP_ENDPOINT_ENABLED=true`
- `MEMORY_MCP_TOOLS_ENABLED=true`
- `MEMORY_MCP_OAUTH_ISSUER`
- `MEMORY_MCP_OAUTH_AUDIENCE`
- `MEMORY_MCP_OAUTH_JWKS_URL`
- `MEMORY_MCP_OAUTH_RESOURCE`（完整的 `https://.../mcp-memory`）
- `MEMORY_MCP_OAUTH_ALLOWED_SUBJECTS`（只填写获准使用该单用户记忆空间的稳定 OAuth subject ID；多个值用逗号分隔）

认证后的 reader 只注册 `get_memory_context`、`get_active_memory`、`search_memory`；只有同时获得 `memory:write` 的客户端才注册四个写工具。签名正确但 subject 不在 allowlist 的 Token 仍会被拒绝。未认证客户端以及现有 `/mcp` 都看不到这七个工具。OAuth 服务需支持 PKCE、RFC 9728 Protected Resource Metadata、授权服务器发现和 refresh token；为 ChatGPT 配置时应允许 `offline_access`，避免短期 Token 过期后频繁重连。

启用后检查七个工具：`get_memory_context`、`get_active_memory`、`search_memory`、`set_active_memory`、`append_memory`、`revise_memory`、`forget_memory`。工具参数和结果都不应出现 namespace、`device_id` 或凭据。写入内容会在 MCP 与 server 两层经过敏感内容拒绝器；修订新增后继记录。

`forget_memory` 不再只是“检索隐藏”。它在单个数据库事务中定位目标记录的整条祖先/后继修订链，清空 `summary`、`searchable_text`，替换原内容摘要并标记 deleted，只保留 ID、修订关系、时间和删除状态等必要元数据。若 active memory 包含完全一致的原摘要，会同步移除并增加 revision；若只能疑似存在改写或概括，返回 `requires_manual_active_revision=true`，不得声称已经彻底忘记。数据库快照、Railway 备份或供应商备份仍可能在各自保留期内包含删除前数据，应按供应商保留策略等待过期或另行执行合规清除。

所有记忆工具使用独立 memory audit，只记录工具名、状态、耗时、revision 与 history item id。审计不得记录记忆正文、query、Token、credential digest 或 namespace，且审计失败不能改变已经成功的记忆操作。

## 6. Token 轮换

轮换时在同一个内部 namespace 下新增新 credential，再禁用旧 credential。不要重新执行空库 bootstrap，也不要创建新 namespace。reader 和 writer 分开轮换；Cyberboss 永远不使用 writer Token。

## 7. 回滚

将 server 的 `MEMORY_ENABLED` 改为 `false`，并将 MCP 的 `MEMORY_MCP_TOOLS_ENABLED`、`MEMORY_MCP_ENDPOINT_ENABLED` 改为 `false`。旧掌心窗接口继续使用原 `LINJIAN_TOKEN`，共享记忆表保留但不再访问。不要删除数据库或旧 JSON 数据。

## 8. ChatGPT 连接验证

先在身份提供方创建测试用户、OAuth resource/audience 和 scopes，确认授权服务器元数据包含 PKCE、refresh token/`offline_access`，再把 ChatGPT 连接地址设为 `https://<mcp-domain>/mcp-memory`。连接时应先收到 401 与 `WWW-Authenticate`，随后跳转到身份提供方登录；授权后扫描工具，reader 只能看到三项读取工具，writer 才能看到全部七项。

截至 2026 年 9 月，OpenAI 官方说明中的完整自定义 MCP 写操作主要面向 ChatGPT Business、Enterprise/Edu；Pro 的自定义 MCP 仍偏向读取能力。ChatGPT Plus 是否在当前账户界面开放自定义 OAuth MCP 写工具，必须在实际 `设置 -> 应用` 页面验证，不能仅凭后端实现推定可用。若 Plus 页面没有“创建应用/自定义 MCP”入口，应保持 `/mcp-memory` 关闭，不要退回未认证 writer。

## 9. 本地 PostgreSQL 集成测试

测试只接受显式设置的本机 `TEST_DATABASE_URL`，主机必须是 `127.0.0.1`、`localhost` 或 `::1`。未设置或指向非本机地址时测试会明确跳过，不会连接 Railway：

```powershell
$env:TEST_DATABASE_URL = "postgresql://test-user:test-password@127.0.0.1:5432/test-db"
python -m unittest server.tests.test_memory_postgres_integration -v
```

测试会创建随机命名的独立 schema，并在结束后只删除该测试 schema。不要把生产连接串用于此变量。
