"""
前置检查模块 - Playwright 依赖检测与自动修复

检测顺序:
1. Playwright (首选)
2. Pyppeteer (异步无头浏览器)
3. Selenium (多浏览器支持)
4. MCP: headless_browser
5. Skill: headless_browser skill

自动修复:
- playwright install-deps
- playwright install chromium
- pip install playwright
"""

import subprocess
import sys


def check_playwright():
    """检查 Playwright 是否可用"""
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
        return True, "playwright"
    except ImportError:
        return False, "playwright_not_installed"
    except Exception as e:
        return False, f"playwright_error: {e}"


def check_pyppeteer():
    """检查 Pyppeteer 是否可用"""
    try:
        import pyppeteer
        return True, "pyppeteer"
    except ImportError:
        return False, "pyppeteer_not_installed"
    except Exception as e:
        return False, f"pyppeteer_error: {e}"


def check_selenium():
    """检查 Selenium 是否可用"""
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        driver = webdriver.Chrome(options=options)
        driver.quit()
        return True, "selenium"
    except ImportError:
        return False, "selenium_not_installed"
    except Exception as e:
        return False, f"selenium_error: {e}"


def check_mcp_headless_browser():
    """检查 MCP: headless_browser 是否可用"""
    try:
        import mcp
        # 尝试导入 headless_browser MCP
        from mcp.server import Server
        return True, "mcp_headless_browser"
    except ImportError:
        return False, "mcp_not_installed"
    except Exception as e:
        return False, f"mcp_error: {e}"


def check_skill_headless_browser():
    """检查 headless_browser skill 是否存在"""
    import os
    skill_paths = [
        "/root/.claude/skills/headless_browser/SKILL.md",
        "./skills/headless_browser/SKILL.md",
        "../headless_browser/SKILL.md",
    ]
    for path in skill_paths:
        if os.path.exists(path):
            return True, f"headless_browser_skill: {path}"
    return False, "headless_browser_skill_not_found"


def auto_install_playwright():
    """自动安装 Playwright"""
    print("  [尝试自动安装 Playwright...]")
    
    commands = [
        ["pip", "install", "playwright"],
        ["playwright", "install-deps", "chromium"],
        ["playwright", "install", "chromium"],
    ]
    
    for cmd in commands:
        try:
            print(f"  [执行] {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode == 0:
                print(f"  [OK] {' '.join(cmd)}")
            else:
                print(f"  [FAIL] {' '.join(cmd)}: {result.stderr[:100]}")
        except subprocess.TimeoutExpired:
            print(f"  [TIMEOUT] {' '.join(cmd)}")
        except Exception as e:
            print(f"  [ERROR] {' '.join(cmd)}: {e}")
    
    # 验证安装
    available, reason = check_playwright()
    if available:
        print("  [OK] Playwright 安装成功!")
        return True
    else:
        print(f"  [FAIL] Playwright 仍不可用: {reason}")
        return False


def check_browser_alternatives():
    """
    检测无头浏览器平替方案
    
    Returns:
        (available, browser_type, can_proceed)
    """
    print("\n[无头浏览器检测]")
    print("-" * 40)
    
    # 1. 检查 Playwright
    available, reason = check_playwright()
    if available:
        print(f"  [OK] Playwright 可用")
        return True, "playwright", True
    
    print(f"  [FAIL] Playwright 不可用: {reason}")
    
    # 2. 检查平替方案
    alternatives = [
        ("Pyppeteer", check_pyppeteer),
        ("Selenium", check_selenium),
        ("MCP: headless_browser", check_mcp_headless_browser),
        ("Skill: headless_browser", check_skill_headless_browser),
    ]
    
    found_alternatives = []
    for name, check_func in alternatives:
        available, reason = check_func()
        if available:
            print(f"  [发现平替] {name}")
            found_alternatives.append(name)
        else:
            print(f"  [未发现] {name}: {reason}")
    
    # 3. 尝试自动安装 Playwright
    print("\n[尝试自动安装...]")
    if auto_install_playwright():
        return True, "playwright", True
    
    # 4. 如果有平替方案，提示用户
    if found_alternatives:
        print(f"\n  [提示] 发现 {len(found_alternatives)} 个平替方案:")
        for alt in found_alternatives:
            print(f"    - {alt}")
        print("  [建议] 可以使用平替方案继续测试")
        return False, found_alternatives[0], True
    
    # 5. 无任何方案
    print("\n  [FATAL] 没有任何可用的无头浏览器方案")
    print("  [建议] 请手动安装 Playwright:")
    print("    pip install playwright")
    print("    playwright install-deps chromium")
    print("    playwright install chromium")
    
    return False, None, False


def prerequisite_check():
    """
    前置检查主函数
    
    Returns:
        (playwright_available, browser_type, can_proceed)
    """
    print("\n" + "=" * 50)
    print("  [0] 前置检查")
    print("=" * 50)
    
    # 检查 requests
    print("\n[Requests 检测]")
    try:
        import requests
        print("  [OK] requests 可用")
        requests_available = True
    except ImportError:
        print("  [FAIL] requests 未安装")
        requests_available = False
    
    if not requests_available:
        print("\n  [FATAL] requests 是必需依赖")
        print("  [建议] pip install requests")
        return False, None, False
    
    # 检查无头浏览器
    playwright_available, browser_type, can_proceed = check_browser_alternatives()
    
    print("\n" + "=" * 50)
    print("  前置检查结果:")
    print(f"    requests: {'OK' if requests_available else 'FAIL'}")
    print(f"    无头浏览器: {'OK' if playwright_available else 'FAIL'}")
    if browser_type:
        print(f"    浏览器类型: {browser_type}")
    print("=" * 50 + "\n")
    
    return playwright_available, browser_type, can_proceed


if __name__ == "__main__":
    prerequisite_check()
