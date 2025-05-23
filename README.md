# NuGet 套件漏洞檢查器

一個功能強大的 NuGet 套件漏洞檢查工具，支援 Web 介面和命令行兩種使用方式。

## 功能特色

🔍 **多資料源檢查**
- National Vulnerability Database (NVD)
- Open Source Vulnerabilities (OSV)
- GitHub Advisory Database
- Snyk Vulnerability Database

📦 **多種輸入格式**
- 直接指定套件名稱
- 從文字檔案讀取 (.txt)
- 從 JSON 檔案讀取 (.json)
- 從 CSV 檔案讀取 (.csv)
- 自動掃描專案目錄

📊 **豐富的輸出選項**
- 彩色終端顯示
- JSON 格式報告
- CSV 格式報告
- HTML 格式報告

⚡ **智慧版本檢查**
- 自動解析套件版本
- 精確的漏洞影響範圍判斷
- 支援多種版本格式

## 安裝需求

```bash
pip install -r requirements.txt
```

### 依賴套件
- requests >= 2.28.0
- pandas >= 1.5.0
- packaging >= 21.0

## 使用方式

### 1. 命令行版本 (推薦)

#### 基本使用

```bash
# 檢查單個套件
python nuget_cli.py -p "serilog.4.3.0"

# 檢查多個套件
python nuget_cli.py -p "serilog.4.3.0,newtonsoft.json.13.0.1"

# 從檔案讀取套件清單
python nuget_cli.py -f packages.txt

# 掃描專案目錄
python nuget_cli.py --scan-dir ./MyProject

# 詳細模式顯示
python nuget_cli.py -p "serilog.4.3.0" -v

# 安靜模式（只顯示結果）
python nuget_cli.py -p "serilog.4.3.0" -q
```

#### 輸出到檔案

```bash
# 輸出 JSON 報告
python nuget_cli.py -p "serilog.4.3.0" -o report.json

# 輸出 CSV 報告
python nuget_cli.py -f packages.txt --format csv -o report.csv

# 輸出 HTML 報告
python nuget_cli.py --scan-dir ./MyProject --format html -o report.html
```

#### CI/CD 整合

```bash
# 發現漏洞時以非零退出碼結束（適用於 CI/CD）
python nuget_cli.py -p "serilog.4.3.0" --fail-on-vuln
```

#### 創建範例檔案

```bash
# 創建範例套件清單檔案
python nuget_cli.py --create-samples
```

### 2. Web 介面版本

```bash
# 啟動 Web 伺服器
python server.py

# 在瀏覽器中開啟 http://localhost:8000
```

## 輸入檔案格式

### 文字檔案 (.txt)
```
# NuGet 套件清單
# 支援註解行
serilog.4.3.0
newtonsoft.json.13.0.1
microsoft.aspnetcore.app.2.1.0
```

### JSON 檔案 (.json)
```json
{
  "packages": [
    "serilog.4.3.0",
    "newtonsoft.json.13.0.1",
    "microsoft.aspnetcore.app.2.1.0"
  ],
  "description": "專案套件清單"
}
```

### CSV 檔案 (.csv)
```csv
package_name
serilog.4.3.0
newtonsoft.json.13.0.1
microsoft.aspnetcore.app.2.1.0
```

## 支援的專案檔案

工具會自動掃描以下檔案類型：

- **`.nupkg`** - NuGet 套件檔案
- **`packages.config`** - 傳統 NuGet 設定檔
- **`.csproj`** - .NET 專案檔案中的 PackageReference

## 命令行參數說明

### 輸入選項
- `-p, --packages` - 套件清單，用逗號分隔
- `-f, --file` - 從檔案讀取套件清單
- `--scan-dir` - 掃描目錄尋找 NuGet 套件檔案

### 輸出選項
- `-o, --output` - 輸出檔案路徑
- `--format` - 輸出格式 (json/csv/html)
- `-v, --verbose` - 顯示詳細資訊
- `-q, --quiet` - 安靜模式

### 行為選項
- `--fail-on-vuln` - 發現漏洞時以非零退出碼結束
- `--create-samples` - 創建範例檔案

## 使用範例

### 範例 1：檢查特定套件
```bash
python nuget_cli.py -p "serilog.4.3.0"
```

輸出：
```
╔══════════════════════════════════════════════════════════════╗
║                    NuGet 漏洞檢查器 CLI                      ║
║                  Vulnerability Scanner v1.0                 ║
╚══════════════════════════════════════════════════════════════╝

🚀 開始檢查 1 個套件...

================================================================================
🔍 發現的漏洞
================================================================================

[1] serilog
    🆔 CVE ID: CVE-2024-44930
    📊 CVSS 分數: 8.1
    🚨 嚴重程度: HIGH
    📦 套件版本: 4.3.0
    🌐 資料來源: NVD
    ------------------------------------------------------------

================================================================================
📊 掃描摘要
================================================================================
📦 檢查套件數量: 1
🔍 發現漏洞數量: 1
🌐 資料來源: NVD

🚨 嚴重程度分布:
  ● HIGH: 1

⚡ 整體風險等級: 高
⏱️  掃描耗時: 2.34 秒
```

### 範例 2：生成 HTML 報告
```bash
python nuget_cli.py -f packages.txt --format html -o vulnerability_report.html -v
```

### 範例 3：CI/CD 整合
```bash
# 在 CI/CD 管道中使用
python nuget_cli.py --scan-dir . --fail-on-vuln -q -o security_report.json
if [ $? -ne 0 ]; then
    echo "發現安全漏洞，建置失敗！"
    exit 1
fi
```

## 漏洞嚴重程度

| 等級 | CVSS 分數範圍 | 顏色 | 說明 |
|------|---------------|------|------|
| CRITICAL | 9.0 - 10.0 | 🔴 紅色 | 極嚴重，需立即處理 |
| HIGH | 7.0 - 8.9 | 🟣 紫色 | 高風險，優先處理 |
| MEDIUM | 4.0 - 6.9 | 🟡 黃色 | 中等風險，建議處理 |
| LOW | 0.1 - 3.9 | 🟢 綠色 | 低風險，可延後處理 |

## 故障排除

### 常見問題

**Q: 為什麼某些套件找不到漏洞資訊？**
A: 可能原因包括：
- 套件名稱拼寫錯誤
- 版本格式不正確
- 該套件確實沒有已知漏洞
- API 暫時無法存取

**Q: 掃描速度很慢怎麼辦？**
A: 工具會並行查詢多個資料源，但受限於 API 速率限制。可以：
- 減少同時檢查的套件數量
- 檢查網路連線狀況
- 等待 API 限制重置

**Q: 如何在企業環境中使用？**
A: 可以：
- 設定 HTTP 代理伺服器
- 使用內部漏洞資料庫
- 定期執行自動化掃描

## 開發資訊

### 專案結構
```
nuget-checker/
├── nuget_cli.py           # 命令行主程式
├── vulnerability_checker.py  # 核心檢查邏輯
├── server.py              # Web 伺服器
├── index.html             # Web 介面
├── style.css              # 樣式檔案
├── requirements.txt       # 依賴套件
└── README.md             # 說明文件
```

### 擴展功能

如果您想要擴展功能，可以：

1. **新增漏洞資料源**：在 `VulnerabilityChecker` 類別中新增搜尋方法
2. **自訂輸出格式**：在 `NuGetCLI` 類別中新增匯出方法
3. **整合其他工具**：透過 API 或檔案介面整合

### 貢獻指南

歡迎提交 Issue 和 Pull Request！

## 授權條款

本專案採用 MIT 授權條款。

## 更新日誌

### v1.0.0
- 初始版本發布
- 支援多資料源漏洞檢查
- 提供命令行和 Web 介面
- 支援多種輸入和輸出格式
