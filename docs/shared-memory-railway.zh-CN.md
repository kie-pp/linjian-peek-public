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

`zhangxinchuang-mcp` 使用 writer Token，通过 `MEMORY_MCP_WRITER_TOKEN` 调用 server。`MEMORY_MCP_TOOLS_ENABLED` 默认必须保持 `false`。

## 5. 验证后启用 MCP 工具

当前公开 `/mcp` 尚未确认具有独立客户端认证。先确认 ChatGPT 连接能使用受保护 Header 或 OAuth，或者新增仅供已认证客户端访问的独立 MCP 路由。完成入口认证验证后，才可设置 `MEMORY_MCP_TOOLS_ENABLED=true`。

启用后检查七个工具：`get_memory_context`、`get_active_memory`、`search_memory`、`set_active_memory`、`append_memory`、`revise_memory`、`forget_memory`。工具参数和结果都不应出现 namespace、`device_id` 或凭据。写入内容会在 MCP 与 server 两层经过敏感内容拒绝器；修订新增后继记录，忘记采用软删除。

所有记忆工具使用独立 memory audit，只记录工具名、状态、耗时、revision 与 history item id。审计不得记录记忆正文、query、Token、credential digest 或 namespace，且审计失败不能改变已经成功的记忆操作。

## 6. Token 轮换

轮换时在同一个内部 namespace 下新增新 credential，再禁用旧 credential。不要重新执行空库 bootstrap，也不要创建新 namespace。reader 和 writer 分开轮换；Cyberboss 永远不使用 writer Token。

## 7. 回滚

将 server 的 `MEMORY_ENABLED` 改为 `false`，并将 MCP 的 `MEMORY_MCP_TOOLS_ENABLED` 改为 `false`。旧掌心窗接口继续使用原 `LINJIAN_TOKEN`，共享记忆表保留但不再访问。不要删除数据库或旧 JSON 数据。

## 8. 本地 PostgreSQL 集成测试

测试只接受显式设置的本机 `TEST_DATABASE_URL`，主机必须是 `127.0.0.1`、`localhost` 或 `::1`。未设置或指向非本机地址时测试会明确跳过，不会连接 Railway：

```powershell
$env:TEST_DATABASE_URL = "postgresql://test-user:test-password@127.0.0.1:5432/test-db"
python -m unittest server.tests.test_memory_postgres_integration -v
```

测试会创建随机命名的独立 schema，并在结束后只删除该测试 schema。不要把生产连接串用于此变量。
