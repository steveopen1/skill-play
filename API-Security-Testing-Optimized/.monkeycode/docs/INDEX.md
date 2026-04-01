# API Security Testing Skill - Project Index

## Overview

API Security Testing Skill 是一个由 AI 驱动的自动化 API 渗透测试工具。基于多层级推理引擎、采集器联动和动态策略池的智能安全测试工具。

## Documentation Structure

- [Architecture](./ARCHITECTURE.md) - 系统架构文档
- [Developer Guide](./DEVELOPER_GUIDE.md) - 开发者指南

## Core Modules

### Intelligent Discovery (`scripts/intelligent_discovery/`)

真正由 AI 驱动的智能 API 发现系统，核心特点：
- 不使用硬编码正则表达式
- 通过 LLM 理解代码逻辑发现 API
- 真正的自主推理和动态适应

**组件**：
- `AgentBrain` - LLM 决策引擎
- `ContextManager` - 动态上下文管理
- `BrowserCollector` - 动态交互引擎
- `SourceAnalyzer` - 全资源分析
- `ResponseAnalyzer` - 响应推导
- `DiscoveryOrchestrator` - 协调器

### Legacy Modules (`scripts/`)

原有扫描模块：
- `orchestrator.py` - 编排器
- `collectors_coordinator.py` - 采集器联动
- `reasoning_engine.py` - 推理引擎
- `context_manager.py` - 上下文管理
- `strategy_pool.py` - 策略池
- `testing_loop.py` - 测试循环
- `api_tester.py` - API 测试器
- `browser_collector.py` - 浏览器采集器
- `js_collector.py` - JS 分析器

## Feature Specifications

- [Intelligent API Discovery](./specs/intelligent-api-discovery/) - 智能 API 发现机制

## Quick Start

```python
from intelligent_discovery import run_discovery

context = await run_discovery("https://target.com")
print(f"Discovered {len(context.discovered_endpoints)} endpoints")
```
