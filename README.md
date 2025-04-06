# 🛡️ Shane's Sigma Rules for Threat Detection

Welcome to my personal collection of custom Sigma rules, detection logic, and threat hunting content.  
This repo is designed to share blue team tactics, especially around credential abuse, MFA bypass, and CVE-based detections.

---

## 🔍 Featured Rule: CVE-2024-7821 – MFA Bypass in WordPress Plugin

This rule detects suspicious successful logins to WordPress (`wp-login.php`) **without MFA verification**, a key weakness exploited in [CVE-2024-7821](https://nvd.nist.gov/vuln/detail/CVE-2024-7821).

### 🧠 Detection Use Case:
- **Credential stuffing + MFA bypass**
- **Admin logins without `/mfa/verify` sequence**
- **High-value target systems (e.g. Australian super accounts)**

📄 [View Sigma Rule](https://github.com/shanerwilson/sigma-rules/blob/main/web/CVE-2024-7821-mfa-bypass.yml)

---

## 📦 How to Use

1. Convert Sigma to your SIEM format (e.g., Elasticsearch, Splunk, Sentinel):
```bash
sigmac -t es-qs sigma-rules/web/CVE-2024-7821-mfa-bypass.yml
