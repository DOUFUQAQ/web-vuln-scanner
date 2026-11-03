# HTTP API

所有接口都在 `/api` 下，返回 JSON。除 `/api/health` 外都挂在 `scan` 蓝图
（`backend/routes/scan_routes.py`），**没有任何鉴权**——这是本地工具，
不要直接暴露到公网（见 README「已知局限」）。

## 状态码约定

| 码 | 含义 |
| --- | --- |
| 200 | 成功 |
| 201 | 创建成功（目标 / 扫描任务） |
| 400 | 参数缺失或目标 URL 未通过策略校验 |
| 404 | 目标 / 任务不存在 |
| 500 | 服务端异常（异常信息会原样放进 `message`） |

成功响应统一是 `{"success": true, "data": ...}`（个别接口是 `{"success": true, "deleted": n}`），
失败是 `{"success": false, "message": "..."}`。

## 接口一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/health` | 健康检查，返回 `{"status": "ok", "message": "..."}` |
| GET | `/api/scan/targets` | 目标列表，按 `created_at` 倒序 |
| POST | `/api/scan/targets` | 新建目标 |
| DELETE | `/api/scan/targets/{id}` | 删除目标（级联删除其扫描任务与漏洞） |
| POST | `/api/scan/start` | 建任务并在后台线程里开扫 |
| GET | `/api/scan/tasks` | 任务列表，可选 `?target_id=` |
| GET | `/api/scan/tasks/{id}` | 任务详情，附带 `target` 与 `vulnerabilities` |
| DELETE | `/api/scan/tasks/clear` | 批量删任务，`?scope=recent\|all&limit=5&target_id=` |
| GET | `/api/scan/vulnerabilities` | 漏洞列表，可选 `?scan_id=` |
| GET | `/api/scan/statistics` | 统计：任务数 / 漏洞数 / 按严重度与类型分布 |

## POST /api/scan/targets

```json
{ "url": "http://127.0.0.1:8080/user?id=1", "name": "本地靶场", "description": "可选" }
```

`url` 会被 `scanner/target_policy.validate_target_url()` 校验：

* 协议必须是 `http` / `https`（`file://`、`ftp://`、`gopher://` 直接 400）；
* 必须有主机名；
* 若设置了 `SCANNER_ALLOWED_TARGET_HOSTS`，主机必须在白名单内；
* 若 `SCANNER_BLOCK_PRIVATE_TARGETS=true`，本机 / 私网 / 云元数据地址一律 400。

不通过时返回 400，`message` 是给用户看的中文原因。

## POST /api/scan/start

```json
{ "target_id": 1, "scan_type": "all" }
```

`scan_type` 取值：`all`（默认，三个扫描器全跑）、`sql_injection`、`xss`、`csrf`。

接口**立刻**返回 201 和一条 `status="pending"` 的任务记录，真正的扫描在
`threading.Thread(daemon=True)` 里跑，进度靠轮询 `GET /api/scan/tasks/{id}`。

任务字段：

| 字段 | 说明 |
| --- | --- |
| `status` | `pending` / `running` / `completed` / `failed` |
| `risk_score` | 该任务所有漏洞 CVSS 基本分的算术平均（保留 1 位小数） |
| `risk_level` | 由 `risk_score` 判档：>=9 `critical`、>=7 `high`、>=4 `medium`、其余 `low` |
| `vulnerabilities_count` | 关联漏洞数 |

## 漏洞对象

```json
{
  "vuln_type": "SQL注入",
  "severity": "critical",
  "title": "SQL注入漏洞 - id参数",
  "description": "...",
  "location": "http://127.0.0.1:8080/user?id=1 (参数: id)",
  "cvss_base_score": 9.7,
  "cvss_temporal_score": 8.8,
  "cvss_environmental_score": 6.9,
  "cvss_vector": "AV:N/AC:L/Au:N/C:C/I:C/A:P",
  "evidence": "数据库类型: SQLite\n测试载荷: ' OR '1'='1\n错误信息: syntax error",
  "recommendation": "..."
}
```

`severity` 来自 CVSS 分级，**不是**扫描器字典里写的那个 `severity` 字段
（扫描器把 XSS 标成 `high`，落库时被 CVSS 的 `medium` 覆盖，详见 README）。

## 统计接口

```json
{
  "total_scans": 12,
  "completed_scans": 10,
  "total_vulnerabilities": 27,
  "severity_distribution": { "critical": 3, "high": 5, "medium": 19 },
  "type_distribution": { "SQL注入": 3, "XSS（跨站脚本）": 20, "CSRF（跨站请求伪造）": 4 }
}
```

## curl 示例

```bash
curl -s http://127.0.0.1:5000/api/health

curl -s -X POST http://127.0.0.1:5000/api/scan/targets \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://127.0.0.1:8080/user?id=1","name":"本地靶场"}'

curl -s -X POST http://127.0.0.1:5000/api/scan/start \
  -H 'Content-Type: application/json' \
  -d '{"target_id":1,"scan_type":"all"}'

curl -s http://127.0.0.1:5000/api/scan/tasks/1
```
