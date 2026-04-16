# M1 評分失真修復 + httpx header 採集 + ports 去重

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 修復 M1 網站服務安全評分永遠 0 分的問題 — 根因是 httpx 沒採集 security headers，加上扣分無上限導致 findings 爆炸。

**Architecture:** 三層修復：(1) httpx_tool 加 `-irh` 旗標並從 JSON `header` 欄位解析 security headers，(2) M1 web_security 改為 per-header-type 扣分上限，(3) pipeline ports 去重。

**Tech Stack:** Python 3.10+, pytest, structlog, ProjectDiscovery httpx (Go)

---

## 背景

### 根因分析

PD httpx 的 JSON 輸出在加上 `-irh` (include-response-header) 後，`header` 欄位包含所有 response headers，key 格式為 **snake_case**（例如 `x_frame_options`、`strict_transport_security`、`content_security_policy`）。

目前的問題鏈：
1. `httpx_tool.py` 命令沒帶 `-irh` → JSON 無 header 資料
2. `httpx_tool.py` 沒解析 `header` 欄位 → 回傳 dict 無 `security_headers`
3. `pipeline.py` 取 `http_info.get("security_headers", {})` → 永遠 `{}`
4. `web_security.py` 判定所有 header 都缺失 → 每個子網域扣 9 分
5. 13 個 HTTP 子網域 × 3 headers × 3 分 = 117 分理論扣分（max_score 只有 25）
6. findings 爆炸（39 筆重複的 "Missing xxx"）

### PD httpx JSON header 格式

```json
{
  "header": {
    "strict_transport_security": "max-age=31536000",
    "content_security_policy": "default-src 'self'",
    "x_frame_options": "SAMEORIGIN",
    "server": "nginx",
    "content_type": "text/html"
  }
}
```

Key 是 snake_case（原本的 `strict-transport-security` → `strict_transport_security`）。

---

## Task 1: httpx_tool 加 `-irh` 並解析 security headers

**Files:**
- Modify: `cypulse/discovery/httpx_tool.py:21-55`
- Test: `tests/test_discovery/test_httpx.py`

### Step 1: 寫失敗測試 — 驗證 httpx 回傳 security_headers

```python
# tests/test_discovery/test_httpx.py 新增測試

@patch("subprocess.run")
@patch("cypulse.discovery.httpx_tool.check_tool", return_value=True)
def test_parses_security_headers(self, mock_check, mock_run):
    import json
    httpx_json = json.dumps({
        "url": "https://www.example.com",
        "status_code": 200,
        "title": "Example",
        "input": "www.example.com",
        "header": {
            "strict_transport_security": "max-age=31536000",
            "content_security_policy": "default-src 'self'",
            "x_frame_options": "DENY",
            "server": "nginx",
        },
    })
    mock_run.return_value = MagicMock(stdout=httpx_json + "\n")
    tool = HttpxTool()
    result = tool.run("www.example.com", {})
    assert len(result) == 1
    headers = result[0]["security_headers"]
    assert headers["strict-transport-security"] == "max-age=31536000"
    assert headers["content-security-policy"] == "default-src 'self'"
    assert headers["x-frame-options"] == "DENY"


@patch("subprocess.run")
@patch("cypulse.discovery.httpx_tool.check_tool", return_value=True)
def test_no_header_field_returns_empty(self, mock_check, mock_run):
    import json
    httpx_json = json.dumps({
        "url": "https://www.example.com",
        "status_code": 200,
        "title": "Example",
        "input": "www.example.com",
    })
    mock_run.return_value = MagicMock(stdout=httpx_json + "\n")
    tool = HttpxTool()
    result = tool.run("www.example.com", {})
    assert result[0]["security_headers"] == {}
```

### Step 2: 跑測試確認失敗

```bash
make test-filter FILTER=test_parses_security_headers
```

Expected: FAIL — `security_headers` key 不存在或值不對

### Step 3: 實作

修改 `cypulse/discovery/httpx_tool.py`：

**3a.** 命令加 `-irh`：

```python
cmd = [
    "httpx", "-silent", "-json",
    "-status-code", "-title", "-tech-detect",
    "-tls-grab", "-follow-redirects",
    "-include-response-header",
]
```

**3b.** 解析結果加 `security_headers`：

在 `results.append({...})` 區塊中，新增 `_extract_security_headers` 呼叫：

```python
results.append({
    "subdomain": data.get("input", data.get("url", "")),
    "url": data.get("url", ""),
    "http_status": data.get("status_code"),
    "http_title": data.get("title", ""),
    "tls_version": data.get("tls", {}).get("version", None) if isinstance(data.get("tls"), dict) else None,
    "tech": data.get("tech", []),
    "content_length": data.get("content_length"),
    "security_headers": _extract_security_headers(data.get("header", {})),
    "source": "httpx",
})
```

新增 module-level 函數：

```python
# 放在 class 外面、logger 下面
_SECURITY_HEADER_NAMES = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def _extract_security_headers(raw_headers: dict) -> dict:
    """從 PD httpx 的 snake_case header dict 提取安全相關 headers。

    PD httpx 回傳 header key 格式為 snake_case（如 strict_transport_security）。
    轉換回標準 kebab-case（如 strict-transport-security）以供 M1 分析模組使用。
    """
    if not isinstance(raw_headers, dict):
        return {}
    result = {}
    for header_name in _SECURITY_HEADER_NAMES:
        snake_key = header_name.replace("-", "_")
        value = raw_headers.get(snake_key)
        if value:
            result[header_name] = value
    return result
```

### Step 4: 跑測試確認通過

```bash
make test-filter FILTER=test_httpx
```

Expected: 全部 PASS（含原有 3 個 + 新增 2 個）

### Step 5: 更新原有測試的 mock 資料

原有 `test_json_output` 的 mock JSON 沒有 `header` 欄位，應確認 `security_headers` 回傳 `{}`（向後相容）。

### Step 6: Commit

```bash
git add cypulse/discovery/httpx_tool.py tests/test_discovery/test_httpx.py
git commit -m "fix: httpx_tool 加 -irh 採集 security headers 修復 M1 假陽性"
```

---

## Task 2: M1 web_security 扣分上限

**Files:**
- Modify: `cypulse/analysis/web_security.py:26-47`
- Test: `tests/test_analysis/test_web_security.py`

### 問題

目前每個子網域每個缺失 header 都獨立扣 3 分、獨立產生 finding。13 個子網域 × 3 headers = 39 筆 findings，score 早就 0 了但 findings 繼續堆疊。

### 設計

改為 **per-header-type 彙總**：
- 檢查所有有 HTTP 回應的子網域
- 每種 header 統計有多少子網域缺失
- 每種缺失 header 只產生 **1 筆 finding**（列出受影響的子網域清單）
- 每種 header 扣分 = min(缺失數 × 1, 5)（上限 5 分，避免單一 header 把分數吃完）
- 3 種 header 最多扣 15 分（max_score = 25，留空間給 TLS 和 nuclei）

### Step 1: 寫失敗測試

```python
# tests/test_analysis/test_web_security.py 新增

def test_many_subdomains_findings_capped(self):
    """多個子網域缺同一 header 時，每種 header 只產生一筆 finding。"""
    subs = [
        Asset(subdomain=f"sub{i}.example.com", http_status=200, security_headers={})
        for i in range(10)
    ]
    assets = Assets(domain="example.com", timestamp="test", subdomains=subs)
    m = WebSecurityModule()
    result = m.run(assets)
    # 3 種 header 各 1 筆 = 3 筆（不是 30 筆）
    header_findings = [f for f in result.findings if f.severity != "info"]
    assert len(header_findings) == 3
    # 每筆 finding 應包含受影響子網域數量
    for f in header_findings:
        assert "10" in f.description


def test_partial_headers_present(self):
    """部分子網域有設 header，只統計缺失的。"""
    assets = Assets(
        domain="example.com",
        timestamp="test",
        subdomains=[
            Asset(
                subdomain="good.example.com",
                http_status=200,
                security_headers={
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                },
            ),
            Asset(
                subdomain="bad.example.com",
                http_status=200,
                security_headers={},
            ),
        ],
    )
    m = WebSecurityModule()
    result = m.run(assets)
    header_findings = [f for f in result.findings if f.severity != "info"]
    assert len(header_findings) == 3  # bad.example.com 缺 3 種
    for f in header_findings:
        assert "bad.example.com" in f.description
        assert "good.example.com" not in f.description


def test_score_deduction_per_header_capped(self):
    """每種 header 扣分有上限。"""
    subs = [
        Asset(subdomain=f"sub{i}.example.com", http_status=200, security_headers={})
        for i in range(20)
    ]
    assets = Assets(domain="example.com", timestamp="test", subdomains=subs)
    m = WebSecurityModule()
    result = m.run(assets)
    # 3 headers × 5 分上限 = 最多扣 15 分 → score >= 10
    assert result.score >= 10
```

### Step 2: 跑測試確認失敗

```bash
make test-filter FILTER=test_web_security
```

### Step 3: 實作

重寫 `web_security.py` 的 header 檢查邏輯：

```python
def run(self, assets: Assets) -> ModuleResult:
    import time
    start = time.time()
    findings: list[Finding] = []
    score = self.max_score()

    # 統計每種 header 缺失的子網域
    http_assets = [a for a in assets.subdomains if a.http_status]
    header_missing: dict[str, list[str]] = {h: [] for h in CRITICAL_HEADERS}

    for asset in http_assets:
        headers = asset.security_headers or {}
        normalized = {k.lower(): v for k, v in headers.items()}
        for header in CRITICAL_HEADERS:
            if not normalized.get(header) and not normalized.get(header.replace("-", "_")):
                header_missing[header].append(asset.subdomain)

    # 每種 header 產生一筆彙總 finding
    for header, missing_subs in header_missing.items():
        if not missing_subs:
            continue
        count = len(missing_subs)
        deduction = min(count, 5)  # 每種 header 最多扣 5 分
        preview = ", ".join(missing_subs[:5])
        suffix = f" 等 {count} 個" if count > 5 else ""
        findings.append(Finding(
            severity="medium",
            title=f"Missing {header}",
            description=f"{count} 個子網域缺少 {header} header（{preview}{suffix}）",
            evidence=", ".join(missing_subs[:10]),
            score_impact=deduction,
        ))
        score = max(0, score - deduction)

    # TLS check（保持不變）
    for asset in http_assets:
        if asset.tls_version and asset.tls_version < "TLSv1.2":
            findings.append(Finding(
                severity="high",
                title="Weak TLS Version",
                description=f"{asset.subdomain} 使用 {asset.tls_version}",
                evidence=f"{asset.subdomain}: {asset.tls_version}",
                score_impact=10,
            ))
            score = max(0, score - 10)

    # nuclei（保持不變）
    nuclei_findings = self._run_nuclei(assets)
    status = "success"
    if nuclei_findings is None:
        status = "partial"
        findings.append(Finding(
            severity="info",
            title="nuclei not installed",
            description="nuclei 未安裝，弱點掃描未執行",
        ))
    else:
        for nf in nuclei_findings:
            findings.append(nf)
            score = max(0, score - nf.score_impact)

    elapsed = time.time() - start
    return ModuleResult(
        module_id=self.module_id(),
        module_name=self.module_name(),
        score=score,
        max_score=self.max_score(),
        findings=findings,
        raw_data={},
        execution_time=elapsed,
        status=status,
    )
```

### Step 4: 更新原有測試

`test_missing_headers` 需要更新：原本期望 `len(findings) >= 3`，現在 1 個子網域缺 3 種 header → 3 筆 findings（不變，但 description 格式變了）。

`test_all_headers_present` 不需改。

`test_no_http_assets` 不需改。

### Step 5: 跑測試

```bash
make test-filter FILTER=test_web_security
```

Expected: 全部 PASS

### Step 6: Commit

```bash
git add cypulse/analysis/web_security.py tests/test_analysis/test_web_security.py
git commit -m "fix: M1 per-header-type 彙總扣分，避免 findings 爆炸"
```

---

## Task 3: pipeline ports 去重

**Files:**
- Modify: `cypulse/discovery/pipeline.py:82-87`
- Test: `tests/test_discovery/test_pipeline.py`

### 問題

掃描結果出現 `ports: [443, 443]`、`[80, 80]`，naabu 有時回傳重複 port。

### Step 1: 寫失敗測試

```python
# tests/test_discovery/test_pipeline.py 新增測試 class

class TestPortDedup:
    @patch("cypulse.discovery.pipeline.HttpxTool")
    @patch("cypulse.discovery.pipeline.NaabuTool")
    @patch("cypulse.discovery.pipeline.resolve_subdomains")
    @patch("cypulse.discovery.pipeline.query_web_sources")
    @patch("cypulse.discovery.pipeline.AmassTool")
    @patch("cypulse.discovery.pipeline.SubfinderTool")
    def test_ports_deduped(self, MockSF, MockAmass, mock_web, mock_resolve, MockNaabu, MockHttpx):
        sf_instance = MockSF.return_value
        sf_instance.run.return_value = [{"subdomain": "www.example.com"}]
        am_instance = MockAmass.return_value
        am_instance.run.return_value = []
        mock_web.return_value = []
        mock_resolve.return_value = [
            {"subdomain": "example.com", "ip": "1.2.3.4"},
            {"subdomain": "www.example.com", "ip": "1.2.3.4"},
        ]
        naabu_instance = MockNaabu.return_value
        naabu_instance.run.return_value = [
            {"host": "www.example.com", "port": 443},
            {"host": "www.example.com", "port": 443},
            {"host": "www.example.com", "port": 80},
        ]
        httpx_instance = MockHttpx.return_value
        httpx_instance.run.return_value = []
        assets = run_discovery("example.com", {})
        www = next(a for a in assets.subdomains if a.subdomain == "www.example.com")
        assert www.ports == [80, 443]  # 去重且排序
```

### Step 2: 跑測試確認失敗

```bash
make test-filter FILTER=test_ports_deduped
```

Expected: FAIL — `www.ports == [443, 443, 80]`

### Step 3: 實作

修改 `pipeline.py` port_map 組裝邏輯：

```python
# Build host -> ports mapping
port_map: dict[str, set[int]] = {}
for r in port_results:
    host = r.get("host", "").lower()
    port = r.get("port")
    if host and port:
        port_map.setdefault(host, set()).add(port)
```

以及 Asset 組裝時：

```python
ports=sorted(port_map.get(sub, set())),
```

### Step 4: 跑全部測試

```bash
make test
```

Expected: 全部 PASS

### Step 5: Commit

```bash
git add cypulse/discovery/pipeline.py tests/test_discovery/test_pipeline.py
git commit -m "fix: pipeline ports 去重避免重複值"
```

---

## 驗證

全部修復後，重新掃描 `net-chinese.com.tw` 預期：
- M1: 分數 > 0（除非真的所有子網域都缺 header）
- M1 findings: 最多 3 筆（每種 header 一筆彙總）
- ports: 無重複值
- security_headers: 有實際值（非 `{}`）
