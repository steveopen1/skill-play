"""
Intelligent API Discovery - Environment Checker

自动检查和安装运行依赖

在启动浏览器采集器前检查必要的系统依赖，
如有缺失则自动安装，而不是跳过。
"""

import subprocess
import sys
import shutil
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class EnvironmentChecker:
    """环境依赖检查器"""
    
    PLAYWRIGHT_SYSTEM_DEPS = [
        'libglib2.0-0',
        'libnss3',
        'libnspr4',
        'libdbus-1-3',
        'libatk1.0-0',
        'libatk-bridge2.0-0',
        'libcups2',
        'libdrm2',
        'libxkbcommon0',
        'libxcomposite1',
        'libxdamage1',
        'libxfixes3',
        'libxrandr2',
        'libgbm1',
        'libasound2',
        'libpango-1.0-0',
        'libcairo2',
    ]
    
    @classmethod
    def check_all(cls) -> Dict[str, Any]:
        """
        检查所有依赖
        
        Returns:
            Dict: {
                'playwright_installed': bool,
                'playwright_ready': bool,
                'system_deps_missing': List[str],
                'can_launch_browser': bool,
                'issues': List[str]
            }
        """
        result = {
            'playwright_installed': cls.check_playwright_installed(),
            'playwright_ready': False,
            'system_deps_missing': [],
            'can_launch_browser': False,
            'issues': []
        }
        
        if not result['playwright_installed']:
            result['issues'].append('Playwright not installed')
            return result
        
        result['system_deps_missing'] = cls.check_system_deps()
        
        if result['system_deps_missing']:
            result['issues'].append(
                f'Missing system dependencies: {result["system_deps_missing"]}'
            )
            return result
        
        playwright_ready = cls.check_playwright_browser()
        result['playwright_ready'] = playwright_ready
        
        if not playwright_ready:
            result['issues'].append('Playwright browser not installed')
            return result
        
        result['can_launch_browser'] = True
        return result
    
    @staticmethod
    def check_playwright_installed() -> bool:
        """检查 Playwright 是否安装"""
        return shutil.which('playwright') is not None or (
            shutil.which('python3') is not None and 
            subprocess.run(
                ['python3', '-c', 'import playwright'],
                capture_output=True
            ).returncode == 0
        )
    
    @staticmethod
    def check_system_deps() -> List[str]:
        """检查系统依赖是否完整"""
        missing = []
        
        for dep in EnvironmentChecker.PLAYWRIGHT_SYSTEM_DEPS:
            result = subprocess.run(
                ['dpkg', '-s', dep],
                capture_output=True
            )
            if result.returncode != 0:
                missing.append(dep)
        
        return missing
    
    @staticmethod
    def check_playwright_browser() -> bool:
        """检查 Playwright 浏览器是否安装"""
        try:
            result = subprocess.run(
                ['python3', '-c', 
                 'from playwright.sync_api import sync_playwright; '
                 'p = sync_playwright().start(); '
                 'p.chromium.launch(headless=True); '
                 'p.stop()'],
                capture_output=True,
                timeout=30
            )
            return result.returncode == 0
        except Exception:
            return False
    
    @classmethod
    def install_system_deps(cls) -> bool:
        """
        安装缺失的系统依赖
        
        Returns:
            bool: 安装是否成功
        """
        missing = cls.check_system_deps()
        
        if not missing:
            logger.info('All system dependencies already installed')
            return True
        
        logger.info(f'Installing missing system dependencies: {missing}')
        
        try:
            subprocess.run(
                ['apt-get', 'update'],
                check=True,
                capture_output=True
            )
            
            result = subprocess.run(
                ['apt-get', 'install', '-y'] + missing,
                check=True,
                capture_output=True
            )
            
            logger.info('System dependencies installed successfully')
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f'Failed to install system dependencies: {e}')
            return False
    
    @classmethod
    def install_playwright(cls) -> bool:
        """
        安装 Playwright
        
        Returns:
            bool: 安装是否成功
        """
        logger.info('Installing Playwright...')
        
        try:
            subprocess.run(
                [sys.executable, '-m', 'pip', 'install', 'playwright', '--break-system-packages'],
                check=True,
                capture_output=True
            )
            
            subprocess.run(
                ['playwright', 'install', 'chromium'],
                check=True,
                capture_output=True,
                timeout=300
            )
            
            logger.info('Playwright installed successfully')
            return True
            
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            logger.error(f'Failed to install Playwright: {e}')
            return False
    
    @classmethod
    def ensure_environment(cls) -> bool:
        """
        确保所有依赖完整，如缺失则自动安装
        
        Returns:
            bool: 环境是否就绪
        """
        logger.info('Checking environment...')
        
        status = cls.check_all()
        
        if status['can_launch_browser']:
            logger.info('Environment ready - all dependencies satisfied')
            return True
        
        logger.info('Environment not ready, attempting to fix...')
        
        if not status['playwright_installed']:
            logger.info('Playwright not found, installing...')
            if not cls.install_playwright():
                logger.error('Failed to install Playwright')
                return False
        
        if status['system_deps_missing']:
            logger.info('System dependencies missing, installing...')
            if not cls.install_system_deps():
                logger.error('Failed to install system dependencies')
                return False
        
        if not status['playwright_ready']:
            logger.info('Playwright browser not ready, installing...')
            try:
                subprocess.run(
                    ['playwright', 'install', 'chromium'],
                    check=True,
                    capture_output=True,
                    timeout=300
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                logger.error(f'Failed to install Playwright browser: {e}')
                return False
        
        final_status = cls.check_all()
        return final_status['can_launch_browser']
