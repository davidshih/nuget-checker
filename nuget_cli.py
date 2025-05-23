#!/usr/bin/env python3
"""
NuGet 套件漏洞檢查器 - 命令行版本
支援多種輸入格式和輸出選項
"""

import argparse
import sys
import os
import json
import csv
import time
import ast
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
import requests
from vulnerability_checker import VulnerabilityChecker

class Colors:
    """終端機顏色定義"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class NuGetCLI:
    def __init__(self):
        self.checker = VulnerabilityChecker()
        self.start_time = None
        
    def print_banner(self):
        """顯示程式橫幅"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                    NuGet 漏洞檢查器 CLI                      ║
║                  Vulnerability Scanner v1.0                 ║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}
"""
        print(banner)
    
    def print_colored(self, text: str, color: str = Colors.WHITE, bold: bool = False):
        """印出有顏色的文字"""
        style = f"{color}{Colors.BOLD if bold else ''}"
        print(f"{style}{text}{Colors.END}")
    
    def get_severity_color(self, severity: str) -> str:
        """根據嚴重程度取得顏色"""
        severity_colors = {
            'CRITICAL': Colors.RED,
            'HIGH': Colors.MAGENTA,
            'MEDIUM': Colors.YELLOW,
            'LOW': Colors.GREEN,
            'UNKNOWN': Colors.CYAN
        }
        return severity_colors.get(severity.upper(), Colors.WHITE)
    
    def parse_package_list_format(self, list_string: str) -> List[str]:
        """解析 Python 列表格式的套件清單"""
        packages = []
        
        try:
            # 清理輸入字串，移除多餘的空白和換行
            cleaned_string = re.sub(r'\s+', ' ', list_string.strip())
            
            # 嘗試直接解析為 Python 列表
            try:
                parsed_list = ast.literal_eval(cleaned_string)
                if isinstance(parsed_list, list):
                    packages = [str(pkg).strip() for pkg in parsed_list if pkg]
                    self.print_colored(f"✅ 成功解析 Python 列表格式，找到 {len(packages)} 個套件", Colors.GREEN)
                    return packages
            except (ValueError, SyntaxError):
                pass
            
            # 如果直接解析失敗，嘗試提取列表內容
            # 尋找 [...] 格式
            list_match = re.search(r'\[(.*?)\]', cleaned_string, re.DOTALL)
            if list_match:
                list_content = list_match.group(1)
                
                # 分割項目，支援單引號、雙引號或無引號
                items = re.findall(r"['\"]([^'\"]+)['\"]|([^,\s]+)", list_content)
                
                for item in items:
                    # item 是一個 tuple，取非空的部分
                    pkg = item[0] if item[0] else item[1]
                    if pkg and pkg.strip():
                        packages.append(pkg.strip())
                
                if packages:
                    self.print_colored(f"✅ 成功解析列表格式，找到 {len(packages)} 個套件", Colors.GREEN)
                    return packages
            
            # 如果還是失敗，嘗試按逗號分割
            if ',' in cleaned_string:
                # 移除方括號
                content = re.sub(r'[\[\]]', '', cleaned_string)
                # 分割並清理
                items = [item.strip().strip('\'"') for item in content.split(',')]
                packages = [item for item in items if item and not item.isspace()]
                
                if packages:
                    self.print_colored(f"✅ 按逗號分割解析，找到 {len(packages)} 個套件", Colors.GREEN)
                    return packages
            
            # 最後嘗試：假設是單個套件
            cleaned = re.sub(r'[\[\]\'""]', '', cleaned_string).strip()
            if cleaned:
                packages = [cleaned]
                self.print_colored(f"✅ 解析為單個套件: {cleaned}", Colors.GREEN)
                return packages
                
        except Exception as e:
            self.print_colored(f"⚠️  解析列表格式時發生錯誤: {e}", Colors.YELLOW)
        
        return packages
    
    def parse_packages_from_file(self, file_path: str) -> List[str]:
        """從檔案解析套件清單"""
        packages = []
        path_obj = Path(file_path)
        
        if not path_obj.exists():
            self.print_colored(f"❌ 檔案不存在: {file_path}", Colors.RED, bold=True)
            return packages
        
        try:
            if path_obj.suffix.lower() == '.json':
                # 解析 packages.json 或類似格式
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                # 支援多種 JSON 格式
                if 'dependencies' in data:
                    # package.json 格式
                    for name, version in data['dependencies'].items():
                        packages.append(f"{name}.{version}")
                elif 'packages' in data:
                    # 自定義格式
                    packages.extend(data['packages'])
                elif isinstance(data, list):
                    # 簡單陣列格式
                    packages.extend(data)
                    
            elif path_obj.suffix.lower() == '.csv':
                # 解析 CSV 檔案
                with open(file_path, 'r', encoding='utf-8') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if row and not row[0].startswith('#'):  # 跳過註解
                            packages.append(row[0].strip())
                            
            else:
                # 純文字檔案，每行一個套件
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):  # 跳過空行和註解
                            packages.append(line)
                            
        except Exception as e:
            self.print_colored(f"❌ 讀取檔案失敗: {e}", Colors.RED, bold=True)
            
        return packages
    
    def scan_directory_for_packages(self, directory: str) -> List[str]:
        """掃描目錄尋找 NuGet 套件檔案"""
        packages = []
        dir_path = Path(directory)
        
        if not dir_path.exists():
            self.print_colored(f"❌ 目錄不存在: {directory}", Colors.RED, bold=True)
            return packages
        
        # 尋找 .nupkg 檔案
        nupkg_files = list(dir_path.rglob("*.nupkg"))
        packages.extend([f.name for f in nupkg_files])
        
        # 尋找 packages.config
        config_files = list(dir_path.rglob("packages.config"))
        for config_file in config_files:
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(config_file)
                root = tree.getroot()
                
                for package in root.findall('.//package'):
                    name = package.get('id')
                    version = package.get('version')
                    if name and version:
                        packages.append(f"{name}.{version}")
                        
            except Exception as e:
                self.print_colored(f"⚠️  解析 {config_file} 失敗: {e}", Colors.YELLOW)
        
        # 尋找 .csproj 檔案中的 PackageReference
        csproj_files = list(dir_path.rglob("*.csproj"))
        for csproj_file in csproj_files:
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(csproj_file)
                root = tree.getroot()
                
                for package_ref in root.findall('.//PackageReference'):
                    name = package_ref.get('Include')
                    version = package_ref.get('Version')
                    if name and version:
                        packages.append(f"{name}.{version}")
                        
            except Exception as e:
                self.print_colored(f"⚠️  解析 {csproj_file} 失敗: {e}", Colors.YELLOW)
        
        return packages
    
    def display_summary(self, vulnerabilities: List[Dict], packages_count: int):
        """顯示掃描摘要"""
        print("\n" + "="*80)
        self.print_colored("📊 掃描摘要", Colors.CYAN, bold=True)
        print("="*80)
        
        # 統計資訊
        total_vulns = len(vulnerabilities)
        severity_counts = {}
        sources = set()
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN').upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            sources.add(vuln.get('source', 'Unknown'))
        
        # 基本統計
        print(f"📦 檢查套件數量: {Colors.BOLD}{packages_count}{Colors.END}")
        print(f"🔍 發現漏洞數量: {Colors.BOLD}{total_vulns}{Colors.END}")
        print(f"🌐 資料來源: {Colors.BOLD}{', '.join(sources)}{Colors.END}")
        
        # 嚴重程度分布
        if severity_counts:
            print(f"\n🚨 嚴重程度分布:")
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    color = self.get_severity_color(severity)
                    print(f"  {color}● {severity}: {count}{Colors.END}")
        
        # 風險評估
        risk_level = "低"
        risk_color = Colors.GREEN
        
        if severity_counts.get('CRITICAL', 0) > 0:
            risk_level = "極高"
            risk_color = Colors.RED
        elif severity_counts.get('HIGH', 0) > 0:
            risk_level = "高"
            risk_color = Colors.MAGENTA
        elif severity_counts.get('MEDIUM', 0) > 0:
            risk_level = "中"
            risk_color = Colors.YELLOW
        
        print(f"\n⚡ 整體風險等級: {risk_color}{Colors.BOLD}{risk_level}{Colors.END}")
        
        # 執行時間
        if self.start_time:
            duration = time.time() - self.start_time
            print(f"⏱️  掃描耗時: {Colors.BOLD}{duration:.2f} 秒{Colors.END}")
    
    def display_vulnerabilities(self, vulnerabilities: List[Dict], detailed: bool = False):
        """顯示漏洞詳情"""
        if not vulnerabilities:
            self.print_colored("✅ 未發現已知漏洞！", Colors.GREEN, bold=True)
            return
        
        print("\n" + "="*80)
        self.print_colored("🔍 發現的漏洞", Colors.RED, bold=True)
        print("="*80)
        
        for i, vuln in enumerate(vulnerabilities, 1):
            severity_color = self.get_severity_color(vuln.get('severity', 'UNKNOWN'))
            is_conservative = vuln.get('is_conservative_match', False)
            
            print(f"\n{Colors.BOLD}[{i}] {vuln.get('package', 'Unknown')}{Colors.END}")
            print(f"    🆔 CVE ID: {Colors.CYAN}{vuln.get('cve_id', 'N/A')}{Colors.END}")
            print(f"    📊 CVSS 分數: {Colors.BOLD}{vuln.get('cvss_score', 'N/A')}{Colors.END}")
            print(f"    🚨 嚴重程度: {severity_color}{Colors.BOLD}{vuln.get('severity', 'UNKNOWN')}{Colors.END}")
            print(f"    📦 套件版本: {Colors.YELLOW}{vuln.get('package_version', 'N/A')}{Colors.END}")
            print(f"    🌐 資料來源: {Colors.BLUE}{Colors.BOLD}{vuln.get('source', 'Unknown')}{Colors.END}")
            
            # 高亮顯示保守判斷的情況
            if is_conservative:
                print(f"    {Colors.YELLOW}{Colors.BOLD}⚠️  注意: 套件名稱匹配但無明確版本範圍，採保守判斷{Colors.END}")
            
            if detailed:
                description = vuln.get('description', 'N/A')
                if len(description) > 100:
                    description = description[:100] + "..."
                print(f"    📝 描述: {description}")
                # 高亮顯示連結
                print(f"    🔗 連結: {Colors.CYAN}{Colors.UNDERLINE}{Colors.BOLD}{vuln.get('link', 'N/A')}{Colors.END}")
            else:
                # 即使在非詳細模式下也顯示高亮的連結
                print(f"    🔗 連結: {Colors.CYAN}{Colors.UNDERLINE}{Colors.BOLD}{vuln.get('link', 'N/A')}{Colors.END}")
            
            print(f"    {'-'*60}")
    
    def export_results(self, vulnerabilities: List[Dict], output_file: str, format_type: str):
        """匯出結果到檔案"""
        try:
            output_path = Path(output_file)
            
            if format_type.lower() == 'json':
                # JSON 格式
                export_data = {
                    'scan_time': datetime.now().isoformat(),
                    'total_vulnerabilities': len(vulnerabilities),
                    'vulnerabilities': vulnerabilities
                }
                
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, ensure_ascii=False, indent=2)
                    
            elif format_type.lower() == 'csv':
                # CSV 格式
                with open(output_path, 'w', newline='', encoding='utf-8') as f:
                    if vulnerabilities:
                        writer = csv.DictWriter(f, fieldnames=vulnerabilities[0].keys())
                        writer.writeheader()
                        writer.writerows(vulnerabilities)
                        
            elif format_type.lower() == 'html':
                # HTML 報告
                html_content = self.generate_html_report(vulnerabilities)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                    
            self.print_colored(f"✅ 結果已匯出至: {output_path}", Colors.GREEN, bold=True)
            
        except Exception as e:
            self.print_colored(f"❌ 匯出失敗: {e}", Colors.RED, bold=True)
    
    def generate_html_report(self, vulnerabilities: List[Dict]) -> str:
        """生成 HTML 報告"""
        html_template = """
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NuGet 漏洞掃描報告</title>
    <style>
        body { font-family: 'Microsoft JhengHei', Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .header h1 { color: #2c3e50; margin-bottom: 10px; }
        .summary { background: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .vulnerability { border: 1px solid #ddd; margin-bottom: 15px; border-radius: 5px; overflow: hidden; }
        .vuln-header { padding: 15px; font-weight: bold; }
        .vuln-body { padding: 15px; background: #fafafa; }
        .critical { border-left: 5px solid #e74c3c; }
        .high { border-left: 5px solid #e67e22; }
        .medium { border-left: 5px solid #f39c12; }
        .low { border-left: 5px solid #27ae60; }
        .severity-critical { background-color: #e74c3c; color: white; }
        .severity-high { background-color: #e67e22; color: white; }
        .severity-medium { background-color: #f39c12; color: white; }
        .severity-low { background-color: #27ae60; color: white; }
        .badge { padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }
        .conservative-warning { background-color: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 10px; border-radius: 5px; margin: 10px 0; }
        .highlighted-link { color: #007bff; font-weight: bold; text-decoration: underline; }
        .highlighted-link:hover { color: #0056b3; }
        .footer { text-align: center; margin-top: 30px; color: #7f8c8d; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 NuGet 漏洞掃描報告</h1>
            <p>掃描時間: {scan_time}</p>
        </div>
        
        <div class="summary">
            <h3>📊 掃描摘要</h3>
            <p><strong>發現漏洞總數:</strong> {total_vulns}</p>
            <p><strong>嚴重程度分布:</strong> {severity_distribution}</p>
        </div>
        
        <div class="vulnerabilities">
            <h3>🚨 漏洞詳情</h3>
            {vulnerability_list}
        </div>
        
        <div class="footer">
            <p>此報告由 NuGet 漏洞檢查器 CLI 生成</p>
        </div>
    </div>
</body>
</html>
"""
        
        # 生成漏洞列表 HTML
        vuln_html = ""
        severity_counts = {}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            is_conservative = vuln.get('is_conservative_match', False)
            
            # 保守判斷警告
            conservative_warning = ""
            if is_conservative:
                conservative_warning = """
                    <div class="conservative-warning">
                        ⚠️ <strong>注意:</strong> 套件名稱匹配但無明確版本範圍，採保守判斷
                    </div>
                """
            
            vuln_html += f"""
            <div class="vulnerability {severity}">
                <div class="vuln-header">
                    <span class="badge severity-{severity}">{vuln.get('severity', 'UNKNOWN')}</span>
                    {vuln.get('package', 'Unknown')} - {vuln.get('cve_id', 'N/A')}
                </div>
                <div class="vuln-body">
                    <p><strong>CVSS 分數:</strong> {vuln.get('cvss_score', 'N/A')}</p>
                    <p><strong>套件版本:</strong> {vuln.get('package_version', 'N/A')}</p>
                    <p><strong>資料來源:</strong> <strong>{vuln.get('source', 'Unknown')}</strong></p>
                    <p><strong>描述:</strong> {vuln.get('description', 'N/A')}</p>
                    <p><strong>詳細資訊:</strong> <a href="{vuln.get('link', '#')}" target="_blank" class="highlighted-link">🔗 查看詳情</a></p>
                    {conservative_warning}
                </div>
            </div>
            """
        
        # 生成嚴重程度分布字串
        severity_dist = ", ".join([f"{k.upper()}: {v}" for k, v in severity_counts.items()])
        
        return html_template.format(
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_vulns=len(vulnerabilities),
            severity_distribution=severity_dist,
            vulnerability_list=vuln_html
        )
    
    def run(self, args):
        """執行主程式"""
        self.start_time = time.time()
        
        if not args.quiet:
            self.print_banner()
        
        # 收集套件清單
        packages = []
        
        # 從命令行參數
        if args.packages:
            packages.extend([pkg.strip() for pkg in args.packages.split(',')])
        
        # 從 Python 列表格式
        if args.list_format:
            list_packages = self.parse_package_list_format(args.list_format)
            packages.extend(list_packages)
            if not args.quiet:
                self.print_colored(f"📋 從列表格式載入 {len(list_packages)} 個套件", Colors.BLUE)
        
        # 從檔案
        if args.file:
            file_packages = self.parse_packages_from_file(args.file)
            packages.extend(file_packages)
            if not args.quiet:
                self.print_colored(f"📁 從檔案載入 {len(file_packages)} 個套件", Colors.BLUE)
        
        # 從目錄掃描
        if args.scan_dir:
            dir_packages = self.scan_directory_for_packages(args.scan_dir)
            packages.extend(dir_packages)
            if not args.quiet:
                self.print_colored(f"📂 從目錄掃描到 {len(dir_packages)} 個套件", Colors.BLUE)
        
        # 移除重複項目
        packages = list(set(packages))
        
        if not packages:
            self.print_colored("❌ 未指定任何套件進行檢查", Colors.RED, bold=True)
            self.print_colored("💡 使用 --help 查看使用說明", Colors.YELLOW)
            return 1
        
        if not args.quiet:
            self.print_colored(f"🚀 開始檢查 {len(packages)} 個套件...", Colors.GREEN, bold=True)
            if args.verbose:
                print("套件清單:")
                for pkg in packages:
                    print(f"  • {pkg}")
        
        # 執行漏洞檢查
        try:
            vulnerabilities = self.checker.check_vulnerabilities(packages)
            
            # 顯示結果
            if not args.quiet:
                self.display_vulnerabilities(vulnerabilities, detailed=args.verbose)
                self.display_summary(vulnerabilities, len(packages))
            
            # 匯出結果
            if args.output:
                format_type = args.format or 'json'
                self.export_results(vulnerabilities, args.output, format_type)
            
            # 根據發現的漏洞設定退出碼
            if args.fail_on_vuln and vulnerabilities:
                return 1
            
            return 0
            
        except KeyboardInterrupt:
            self.print_colored("\n⚠️  掃描被使用者中斷", Colors.YELLOW, bold=True)
            return 130
        except Exception as e:
            self.print_colored(f"❌ 掃描過程發生錯誤: {e}", Colors.RED, bold=True)
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1

def create_sample_files():
    """創建範例檔案"""
    # 範例套件清單
    sample_packages = [
        "serilog.4.3.0",
        "newtonsoft.json.13.0.1", 
        "microsoft.aspnetcore.app.2.1.0",
        "system.text.json.6.0.0"
    ]
    
    # 創建範例文字檔案
    with open('sample_packages.txt', 'w', encoding='utf-8') as f:
        f.write("# NuGet 套件清單範例\n")
        f.write("# 每行一個套件，支援註解\n\n")
        for pkg in sample_packages:
            f.write(f"{pkg}\n")
    
    # 創建範例 JSON 檔案
    sample_json = {
        "packages": sample_packages,
        "description": "範例 NuGet 套件清單"
    }
    
    with open('sample_packages.json', 'w', encoding='utf-8') as f:
        json.dump(sample_json, f, ensure_ascii=False, indent=2)
    
    print("✅ 已創建範例檔案:")
    print("  • sample_packages.txt")
    print("  • sample_packages.json")

def main():
    """主函數"""
    parser = argparse.ArgumentParser(
        description='NuGet 套件漏洞檢查器 - 命令行版本',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用範例:
  %(prog)s -p "serilog.4.3.0,newtonsoft.json.13.0.1"
  %(prog)s -f packages.txt -o report.json
  %(prog)s --scan-dir ./MyProject -v --format html -o report.html
  %(prog)s -p "serilog.4.3.0" --fail-on-vuln
  %(prog)s --list "['microsoft.data.sqlclient.6.0.2.nupkg', 'newtonsoft.json.13.0.1.nupkg']"
  
支援的輸入格式:
  • -p/--packages: 逗號分隔的套件清單
  • --list: Python 列表格式 (例: "['pkg1.nupkg', 'pkg2.nupkg']")
  • -f/--file: 從檔案讀取 (.txt, .json, .csv)
  • --scan-dir: 掃描目錄尋找套件檔案
  
支援的檔案格式:
  • .txt - 每行一個套件名稱
  • .json - JSON 格式的套件清單
  • .csv - CSV 格式的套件清單
  
輸出格式:
  • json - JSON 格式報告
  • csv - CSV 格式報告  
  • html - HTML 格式報告
        """
    )
    
    # 輸入選項
    input_group = parser.add_argument_group('輸入選項')
    input_group.add_argument('-p', '--packages', 
                           help='套件清單，用逗號分隔 (例: "pkg1.1.0,pkg2.2.0")')
    input_group.add_argument('--list', dest='list_format',
                           help='Python 列表格式的套件清單 (例: "[\'pkg1.nupkg\', \'pkg2.nupkg\']")')
    input_group.add_argument('-f', '--file', 
                           help='從檔案讀取套件清單 (.txt, .json, .csv)')
    input_group.add_argument('--scan-dir', 
                           help='掃描目錄尋找 NuGet 套件檔案')
    
    # 輸出選項
    output_group = parser.add_argument_group('輸出選項')
    output_group.add_argument('-o', '--output', 
                            help='輸出檔案路徑')
    output_group.add_argument('--format', choices=['json', 'csv', 'html'],
                            help='輸出格式 (預設: json)')
    output_group.add_argument('-v', '--verbose', action='store_true',
                            help='顯示詳細資訊')
    output_group.add_argument('-q', '--quiet', action='store_true',
                            help='安靜模式，只顯示結果')
    
    # 行為選項
    behavior_group = parser.add_argument_group('行為選項')
    behavior_group.add_argument('--fail-on-vuln', action='store_true',
                              help='發現漏洞時以非零退出碼結束')
    behavior_group.add_argument('--create-samples', action='store_true',
                              help='創建範例檔案')
    
    args = parser.parse_args()
    
    # 創建範例檔案
    if args.create_samples:
        create_sample_files()
        return 0
    
    # 檢查是否有輸入
    if not any([args.packages, args.list_format, args.file, args.scan_dir]):
        parser.print_help()
        return 1
    
    # 執行掃描
    cli = NuGetCLI()
    return cli.run(args)

if __name__ == "__main__":
    sys.exit(main())
