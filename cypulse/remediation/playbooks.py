from __future__ import annotations

PLAYBOOKS: dict[str, dict] = {
    "No SPF Record": {
        "priority": "P1",
        "target_team": "Email/IT",
        "timeline": "7 days",
        "effort": "1-2 hours",
        "steps": [
            {
                "step": 1,
                "action": "確認寄件 IP 清單（MX、A、include 等）",
                "command": "dig +short MX example.com",
            },
            {
                "step": 2,
                "action": "在 DNS 新增 SPF TXT 記錄",
                "command": 'v=spf1 include:_spf.google.com ~all',
            },
            {
                "step": 3,
                "action": "等待 DNS 傳播（通常 15-30 分鐘）",
                "command": None,
            },
            {
                "step": 4,
                "action": "驗證 SPF 記錄已生效",
                "command": "dig +short TXT example.com | grep spf",
            },
        ],
        "success_criteria": "dig +short TXT example.com 輸出包含 'v=spf1'",
    },
    "No DMARC Record": {
        "priority": "P1",
        "target_team": "Email/IT",
        "timeline": "7 days",
        "effort": "1-2 hours",
        "steps": [
            {
                "step": 1,
                "action": "確認 SPF 與 DKIM 已設定完成（DMARC 依賴兩者）",
                "command": "dig +short TXT _domainkey.example.com",
            },
            {
                "step": 2,
                "action": "在 DNS 新增 DMARC TXT 記錄（從寬鬆模式開始）",
                "command": "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
            },
            {
                "step": 3,
                "action": "等待 DNS 傳播，收集 DMARC 報告（至少 1 週）",
                "command": None,
            },
            {
                "step": 4,
                "action": "分析報告後逐步收緊策略（none → quarantine → reject）",
                "command": None,
            },
        ],
        "success_criteria": "dig +short TXT _dmarc.example.com 輸出包含 'v=DMARC1'",
    },
    "Missing DNSSEC": {
        "priority": "P2",
        "target_team": "DNS/Networking",
        "timeline": "30 days",
        "effort": "4-8 hours",
        "steps": [
            {
                "step": 1,
                "action": "確認 DNS 服務商支援 DNSSEC（部分服務商需升級方案）",
                "command": None,
            },
            {
                "step": 2,
                "action": "在 DNS 管理介面啟用 DNSSEC，產生 KSK/ZSK 金鑰",
                "command": None,
            },
            {
                "step": 3,
                "action": "將 DS 記錄提交至上層域名 registrar",
                "command": None,
            },
            {
                "step": 4,
                "action": "驗證 DNSSEC 鏈路完整",
                "command": "dig +dnssec +short example.com",
            },
        ],
        "success_criteria": "dig +dnssec example.com 回傳包含 RRSIG 記錄",
    },
    "Weak TLS Version": {
        "priority": "P1",
        "target_team": "Web/Security",
        "timeline": "14 days",
        "effort": "2-4 hours",
        "steps": [
            {
                "step": 1,
                "action": "確認目前支援的 TLS 版本（應停用 TLS 1.0/1.1）",
                "command": "nmap --script ssl-enum-ciphers -p 443 example.com",
            },
            {
                "step": 2,
                "action": "修改 Web 伺服器設定，停用弱版本（nginx 範例）",
                "command": "ssl_protocols TLSv1.2 TLSv1.3;",
            },
            {
                "step": 3,
                "action": "重新載入伺服器設定",
                "command": "nginx -t && systemctl reload nginx",
            },
            {
                "step": 4,
                "action": "驗證 TLS 設定",
                "command": "sslyze --regular example.com",
            },
        ],
        "success_criteria": "sslyze 報告顯示只啟用 TLSv1.2 和 TLSv1.3",
    },
    "Zone Transfer Allowed": {
        "priority": "P1",
        "target_team": "DNS/Networking",
        "timeline": "24 hours",
        "effort": "30 minutes",
        "steps": [
            {
                "step": 1,
                "action": "確認可執行 Zone Transfer 的 IP 清單",
                "command": "dig axfr example.com @ns1.example.com",
            },
            {
                "step": 2,
                "action": "在 DNS 伺服器設定中限制 AXFR 只允許授權的 slave NS",
                "command": "allow-transfer { 192.168.1.2; };  # BIND9 範例",
            },
            {
                "step": 3,
                "action": "重新載入 DNS 伺服器設定",
                "command": "rndc reload",
            },
            {
                "step": 4,
                "action": "驗證外部已無法執行 Zone Transfer",
                "command": "dig axfr example.com @ns1.example.com",
            },
        ],
        "success_criteria": "dig axfr 回傳 'Transfer failed' 或 'REFUSED'",
    },
}


def get_remediation(finding_title: str) -> dict | None:
    """根據 finding 標題取得對應的補救 playbook，找不到時回傳 None。"""
    return PLAYBOOKS.get(finding_title)
