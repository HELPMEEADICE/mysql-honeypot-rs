# `scripts/e2e_clients.py` — 蜜罐端到端验证

对一个**运行中的** MySQL 蜜罐（假 MySQL、真 Wire Protocol）做外部黑盒验证。
脚本自己不做任何连接，导入即安全；所有动作都在 `if __name__ == "__main__"` 之后。
`pymysql` / `mysql.connector` 都不在模块顶层导入，所以缺依赖也不影响导入。

## 依赖

```bash
python -m pip install pymysql mysql-connector-python
```

`pymysql` 必需；`mysql.connector` 只用于检查 2，缺它可以加 `--skip-connector`。

## 用法

```bash
python scripts/e2e_clients.py                                   # 127.0.0.1:3306, ./honeypot.db
python scripts/e2e_clients.py --host 127.0.0.1 --port 3307
python scripts/e2e_clients.py --db /tmp/honeypot.db --delay-min 2 --delay-max 6 --concurrency 8
python scripts/e2e_clients.py --skip-connector                 # 跳过 mysql.connector 那一步
python scripts/e2e_clients.py --json | jq .                      # 只输出一行 JSON
```

参数：`--host`（默认 127.0.0.1）、`--port`（3306）、`--db`（./honeypot.db）、
`--delay-min`（2.0）、`--delay-max`（6.0）、`--concurrency`（6）、
`--skip-connector`、`--json`。

退出码：所有检查 PASS 或 SKIP → `0`，否则 `1`。

## 三项互相独立的驱动方式

| 方式 | 用途 |
| --- | --- |
| `pymysql` | 主客户端，检查 1/4/5/6/7/8(存活探针)/9 |
| `mysql.connector` | 第二客户端实现，检查 2（默认文本 cursor，不设置 sql_mode） |
| 手写 raw socket MySQL 4.1 客户端 | 检查 3（认证延迟计时点）与检查 8（畸形包） |

raw 客户端实现了：读 greeting → 构造 handshake response（`CLIENT_PROTOCOL_41 |
CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA`，
plugin 名 `caching_sha2_password`，auth response 为 32 字节随机）→ 识别
`OK(0x00)` / `ERR(0xff)` / `AuthMoreData(0x01, 0x03|0x04)` / `AuthSwitchRequest(0xfe)`，
序列号双向递增。

## 11 个检查项

1. `pymysql` 用任意凭据认证成功（root/wrongpassword、admin/123456、test/随机串）
2. `mysql.connector` 同上
3. 认证延迟：从「发出 handshake response」到「收到最终 OK」的墙钟时间必须落在 `[--delay-min, --delay-max]` 且 `>= 1.8s`；打印毫秒精度实测值
4. `SHOW DATABASES` ≥ 5 行且含 `information_schema` / `mysql` / `performance_schema`
5. `SELECT 1` 返回单列单行且值为 1
6. `SELECT VERSION()` / `SELECT USER()` / `SELECT DATABASE()` 不抛异常
7. 同一连接连续 6 条语句后连接仍可用（末尾再 `SELECT 1`）
8. 4 种畸形包（随机 200 字节 / 声明 0xFFFFFF 只发 10 字节 / 裸 4 字节 header / 合法认证后未知命令 0x7f）后，进程仍能被 `pymysql` 连上
9. 并发 `--concurrency` 个连接全成功，且并发墙钟明显小于串行估算
10. SQLite 日志核对（见下）
11. `mysql.connector` 的 **prepared cursor**（`cursor(prepared=True)`）真实绑定参数：
    `WHERE id = %s` 传 `1` 必须返回 `admin`，传 `3` 必须返回 `bob`（同一语句重复执行），
    字符串参数 `alice` 必须命中，不存在的值必须返回空结果集，
    绑定 `' OR 1=1 -- ` 这类载荷必须**不能**放宽谓词。这一项是唯一端到端验证
    二进制协议参数块（`COM_STMT_EXECUTE` 的 NULL bitmap、类型块与取值）的检查，
    没有它，`?` 被当作 NULL 与真正绑定在外部表现上无法区分。

## SQLite 审计（检查 10）

文件不存在 → `SKIP`。以 `mode=ro` 只读打开，**列名靠正则模糊匹配**，因此 Rust 侧
命名只要语义一致即可：

- 表：`connections`、`queries`（大小写不敏感）
- `connections` 需要：用户名列（`user|login|account`）、IP 列（`ip|addr|host|remote|peer|client`）、
  延迟列（含 `delay`）、`connected_at` 类列、`authenticated_at` 类列
- `queries` 需要：SQL 文本列（`sql|query|statement|text|content|command`）

核对内容：本次来源 IP 有记录、测试过的用户名都在、`auth_delay_ms` 换算成秒后落在
窗口内（±0.25s / +1.0s 容差，字段值 ≥100 视为毫秒、否则视为秒）、两个时间戳非空、
`queries` 里能查到 `SHOW DATABASES` 与 `SELECT 1`，并打印两表 `COUNT(*)`。

## 超时

TCP 连接 5s，socket 读写 15s，全部显式设置，不会挂死。
