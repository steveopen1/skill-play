# Intelligent API Discovery - Developer Guide

## Testing

### Running Tests

```bash
# Run all tests
PYTHONPATH=/workspace/API-Security-Testing-Optimized/scripts python3 -m pytest tests/intelligent_discovery/ -v

# Run specific test
PYTHONPATH=/workspace/API-Security-Testing-Optimized/scripts python3 tests/intelligent_discovery/test_e2e.py

# Run unit tests only
PYTHONPATH=/workspace/API-Security-Testing-Optimized/scripts python3 -m pytest tests/intelligent_discovery/test_models.py -v
```

### Test Structure

```
tests/
└── intelligent_discovery/
    ├── __init__.py
    ├── test_models.py           # Data model tests
    ├── test_context_manager.py  # Context manager tests
    ├── test_learning_engine.py  # Learning engine tests
    ├── test_integration.py      # Component integration tests
    └── test_e2e.py              # End-to-end test script
```

### Writing Tests

```python
from scripts.intelligent_discovery.models import Endpoint, DiscoveryContext

def test_endpoint_creation():
    ep = Endpoint(path="/api/users", method="GET")
    assert ep.path == "/api/users"
    assert ep.method == "GET"
```

## Usage

### Basic Usage

```python
from intelligent_discovery import run_discovery

async def main():
    context = await run_discovery("https://target.com")
    print(f"Discovered {len(context.discovered_endpoints)} endpoints")
    
    for ep in context.discovered_endpoints:
        print(f"{ep.method} {ep.path}")

asyncio.run(main())
```

### With LLM Client

```python
from intelligent_discovery import DiscoveryOrchestrator
from your_llm_client import YourLLMClient

llm = YourLLMClient(api_key="...")

orchestrator = DiscoveryOrchestrator(
    target="https://target.com",
    llm_client=llm,
    use_browser=True,
    max_iterations=50
)

context = await orchestrator.run()
```

### Without Browser (Fast Mode)

```python
orchestrator = DiscoveryOrchestrator(
    target="https://target.com",
    use_browser=False,
    max_iterations=30
)

context = await orchestrator.run()
```

## Architecture

### Component Overview

```
AgentBrain: LLM 决策核心
ContextManager: 上下文管理
LearningEngine: 持续学习
InsightGenerator: 洞察生成
StrategyGenerator: 策略生成
BrowserCollector: 浏览器交互
SourceAnalyzer: 资源分析
ResponseAnalyzer: 响应推导
```

### Data Flow

```
1. Agent.initialize(target) → Context
2. Collector.collect() → Observations
3. Agent.analyze() → Insights
4. Agent.generate_strategy() → Strategy
5. Agent.execute_action() → Results
6. LearningEngine.record() → Updated Context
7. Repeat until converged
```

## Configuration

### Environment Variables

```bash
PLAYWRIGHT_BROWSERS_PATH=/path/to/browsers
```

### Dependencies

```
# Install dependencies
pip install -r requirements.txt

# Key dependencies
- playwright (browser automation)
- requests (HTTP client)
```

## Troubleshooting

### Common Issues

1. **Browser not starting**: Install playwright browsers with `playwright install`
2. **Import errors**: Ensure PYTHONPATH includes the scripts directory
3. **LLM not available**: System falls back to heuristic methods

### Debug Mode

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```
