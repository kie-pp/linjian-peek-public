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

使用 **Auth0** 作为本补丁选定的身份提供方，不在掌心窗内实现授权服务器。Auth0 已提供 MCP OAuth、PKCE S256、动态客户端注册、JWT/JWKS 和自定义 API scope。WorkOS 仍可作为以后替代方案，但本补丁不混用两套控制台契约。

Auth0 中将 `https://<mcp-domain>/mcp-memory` 创建为 API Identifier，并定义 `memory:read`、`memory:write` 两个权限。开启 RBAC 及“Add Permissions in the Access Token”，为 reader 角色只分配 `memory:read`，为 writer 角色分配两项权限。令牌中的 `aud` 必须与 API Identifier、`MEMORY_MCP_OAUTH_AUDIENCE`、`MEMORY_MCP_OAUTH_RESOURCE` 逐字一致。MCP 服务只作为 OAuth resource server，使用 `jose` 从 `MEMORY_MCP_OAUTH_JWKS_URL` 校验签名，同时校验 issuer、audience、过期时间和 `scope`/`permissions`；不会签发或保存 ChatGPT 的 access token。

Auth0 的通用授权服务器元数据不一定列出某个 API 的自定义 scope，因此服务端不会错误要求 `scopes_supported` 必须出现 `memory:*`。业务权限仍同时出现在受保护资源元数据、每个工具的 `securitySchemes` 以及最终 access token 的 `scope`/`permissions` 中，并由服务端逐次强制执行。

启用前配置：

- `MEMORY_MCP_ENDPOINT_ENABLED=true`
- `MEMORY_MCP_TOOLS_ENABLED=true`
- `MEMORY_MCP_OAUTH_ISSUER`
- `MEMORY_MCP_OAUTH_AUDIENCE`
- `MEMORY_MCP_OAUTH_JWKS_URL`
- `MEMORY_MCP_OAUTH_RESOURCE`（完整的 `https://.../mcp-memory`）
- `MEMORY_MCP_OAUTH_ALLOWED_SUBJECTS`（只填写获准使用该单用户记忆空间的稳定 OAuth subject ID；多个值用逗号分隔）

认证后的 reader 只注册 `get_memory_context`、`get_active_memory`、`search_memory`；只有同时获得 `memory:write` 的客户端才注册四个写工具。签名正确但 subject 不在 allowlist 的 Token 仍会被拒绝。未认证客户端以及现有 `/mcp` 都看不到这七个工具。OAuth 服务需支持 PKCE、RFC 9728 Protected Resource Metadata、授权服务器发现和 refresh token；为 ChatGPT 配置时应允许 `offline_access`，避免短期 Token 过期后频繁重连。

Auth0 控制台还需完成以下一致性配置：

1. `Applications -> APIs`：API Identifier 精确填写 `https://<mcp-domain>/mcp-memory`，签名算法使用 RS256，添加两个 `memory:*` 权限。
2. API RBAC：开启 RBAC 和 access token permissions；测试 reader、writer 使用不同角色或不同测试用户。
3. `Settings -> Advanced`：若 ChatGPT 使用动态客户端注册，开启 DCR。DCR 是公开注册入口，应结合 Auth0 的第三方应用默认权限和 ACL 限制滥用。API 的两项 scope 可以进入 DCR client 的可请求范围，但最终授予仍必须由用户角色限制：reader 只得到读权限，writer 才得到读写权限。
4. `Settings -> Tenant Settings -> API Authorization Settings`：开启 Resource Parameter Compatibility Profile，并把 Default Audience 设为同一个 API Identifier，确保 ChatGPT 发送的 `resource` 得到同 audience 的 JWT。
5. 为 DCR 创建的第三方应用开放可用的登录 connection；授权码流程必须为 PKCE S256，并允许 `authorization_code`、`refresh_token` 与 `offline_access`。
6. issuer 使用 Auth0 租户域名（通常带结尾 `/`），JWKS 使用同一租户的 `/.well-known/jwks.json`；实际值必须与 Auth0 元数据逐字一致。

启用后检查七个工具：`get_memory_context`、`get_active_memory`、`search_memory`、`set_active_memory`、`append_memory`、`revise_memory`、`forget_memory`。工具参数和结果都不应出现 namespace、`device_id` 或凭据。写入内容会在 MCP 与 server 两层经过敏感内容拒绝器；修订新增后继记录。

`forget_memory` 不再只是“检索隐藏”。它在单个数据库事务中定位目标记录的整条祖先/后继修订链，清空 `summary`、`searchable_text`，替换原内容摘要并标记 deleted，只保留 ID、修订关系、时间和删除状态等必要元数据。若 active memory 包含完全一致的原摘要，会同步移除并增加 revision；若只能疑似存在改写或概括，返回 `requires_manual_active_revision=true`，不得声称已经彻底忘记。数据库快照、Railway 备份或供应商备份仍可能在各自保留期内包含删除前数据，应按供应商保留策略等待过期或另行执行合规清除。

所有记忆工具使用独立 memory audit，只记录工具名、状态、耗时、revision 与 history item id。审计不得记录记忆正文、query、Token、credential digest 或 namespace，且审计失败不能改变已经成功的记忆操作。

## 6. Token 轮换

轮换时在同一个内部 namespace 下新增新 credential，再禁用旧 credential。不要重新执行空库 bootstrap，也不要创建新 namespace。reader 和 writer 分开轮换；Cyberboss 永远不使用 writer Token。

## 7. 回滚

将 server 的 `MEMORY_ENABLED` 改为 `false`，并将 MCP 的 `MEMORY_MCP_TOOLS_ENABLED`、`MEMORY_MCP_ENDPOINT_ENABLED` 改为 `false`。旧掌心窗接口继续使用原 `LINJIAN_TOKEN`，共享记忆表保留但不再访问。不要删除数据库或旧 JSON 数据。

## 8. ChatGPT 连接验证

先在 Auth0 创建隔离测试用户、API、角色和权限，确认授权服务器元数据包含 PKCE S256、授权码流程及 refresh token/`offline_access`，再把 ChatGPT 连接地址设为 `https://<mcp-domain>/mcp-memory`。连接时应先收到带 `resource_metadata` 的 401 `WWW-Authenticate`，随后完成 Auth0 登录；授权后扫描工具，reader 只能看到三项读取工具，writer 才能看到全部七项。

截至本文核对时，OpenAI 官方说明中完整 MCP（包括写入/修改）面向 ChatGPT Business、Enterprise/Edu；Pro 仅能在 developer mode 使用 read/fetch MCP。个人 Plus 是否显示自定义应用入口必须以账户页面为准，不能凭后端实现推定。没有可创建 OAuth 自定义应用的入口时，应保持 `/mcp-memory` 关闭，不得回退到未认证 writer。

ChatGPT 实测前需要在页面完成：

1. 确认当前套餐和 workspace 具有 `Settings/Workspace settings -> Apps -> Create` 及 developer mode 权限。
2. 在 Auth0 完成上述 API、角色、测试用户、DCR/CIMD、connection、resource/audience 与 refresh token 配置。
3. 部署到隔离测试域名后，把该域名的完整 `/mcp-memory` URL 填入 ChatGPT 自定义应用，选择 OAuth 并执行 Scan Tools。
4. 分别用 reader 和 writer 测试身份登录，核对工具数、写操作确认提示和 token 刷新。不要使用生产日记、生产记忆或生产凭据。

本地测试已经覆盖完整发现、401 登录挑战、授权服务器元数据、DCR、授权码、PKCE S256、resource 参数、JWT audience、reader/writer 工具隔离及无效令牌/权限不足响应。它不能替代 ChatGPT 页面与 Auth0 真实租户的兼容性实测。

## 9. 现有公开 `/mcp` 风险

现有 `/mcp` 为兼容当前掌心窗连接而保持不变，并明确排除全部七个共享记忆工具。但该入口本身没有独立客户端认证，仍暴露原有的写入和设备控制工具，例如账单增删改、日记写入/删除、通知、闹钟、应用控制和屏幕休息。`LINJIAN_TOKEN` 只保护 MCP 到 server 的后端调用，不能证明调用 `/mcp` 的客户端身份。因此公网 URL 泄露时存在未授权工具调用风险。

本阶段不改动 `/mcp`，以免破坏现有 ChatGPT 掌心窗连接。后续应为整个原入口增加独立 OAuth 或先拆分只读/写入路由；在完成迁移前，应限制域名暴露、监控调用记录，并继续让高风险动作依赖服务端确认约束。

## 10. 本地 PostgreSQL 集成测试

测试只接受显式设置的本机 `TEST_DATABASE_URL`，主机必须是 `127.0.0.1`、`localhost` 或 `::1`。未设置或指向非本机地址时测试会明确跳过，不会连接 Railway：

```powershell
$env:TEST_DATABASE_URL = "postgresql://test-user:test-password@127.0.0.1:5432/test-db"
python -m unittest server.tests.test_memory_postgres_integration -v
```

测试会创建随机命名的独立 schema，并在结束后只删除该测试 schema。不要把生产连接串用于此变量。
