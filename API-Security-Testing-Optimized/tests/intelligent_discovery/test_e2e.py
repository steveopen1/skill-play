"""
End-to-End Test Script for Intelligent Discovery

这个脚本演示了完整的 API 发现流程
"""

import asyncio
import sys
from datetime import datetime
sys.path.insert(0, 'scripts')

from intelligent_discovery.models import (
    DiscoveryContext, Endpoint, Observation, Insight, Strategy, Action,
    NetworkRequest, PageStructure, ObservationType, InsightType, ActionType
)
from intelligent_discovery.agent_brain import create_agent_brain
from intelligent_discovery.context_manager import create_context_manager
from intelligent_discovery.learning_engine import create_learning_engine
from intelligent_discovery.insight_generator import create_insight_generator
from intelligent_discovery.strategy_generator import create_strategy_generator
from intelligent_discovery.collectors.source_analyzer import SourceAnalyzer
from intelligent_discovery.collectors.response_analyzer import ResponseAnalyzer


async def simulate_discovery():
    """
    模拟完整的 API 发现流程
    
    这个演示展示了当没有真实浏览器和 LLM 时，
    系统如何使用启发式方法进行发现
    """
    print("=" * 60)
    print("Intelligent API Discovery - End-to-End Test")
    print("=" * 60)
    
    target = "http://example.com"
    
    print(f"\n[*] Initializing discovery for: {target}")
    
    agent = create_agent_brain(llm_client=None)
    context = await agent.initialize(target)
    cm = create_context_manager(target)
    engine = create_learning_engine()
    insight_gen = create_insight_generator(llm_client=None)
    strategy_gen = create_strategy_generator(llm_client=None)
    
    print(f"[*] Context initialized")
    print(f"    Target: {context.target}")
    print(f"    Tech Stack: {context.tech_stack.to_dict()}")
    
    # 模拟 1: 从网络请求发现端点
    print("\n[*] Simulating: Network Request Discovery")
    
    api_responses = [
        {
            "url": "/api/users",
            "method": "GET",
            "status": 200,
            "body": '{"data": [{"id": 1, "name": "John"}], "page": 1, "total": 100}'
        },
        {
            "url": "/api/products",
            "method": "GET", 
            "status": 200,
            "body": '{"data": [{"id": 1, "name": "Product A"}]}'
        },
        {
            "url": "/api/users/1/profile",
            "method": "GET",
            "status": 200,
            "body": '{"id": 1, "name": "John", "email": "john@example.com"}'
        }
    ]
    
    for resp_data in api_responses:
        req = NetworkRequest(
            url=f"http://example.com{resp_data['url']}",
            method=resp_data['method'],
            headers={"content-type": "application/json"},
            body=None,
            response_status=resp_data['status'],
            response_body=resp_data['body'],
            response_headers={"content-type": "application/json"},
            timestamp=datetime.now(),
            source="simulation"
        )
        
        obs = Observation(
            type=ObservationType.NETWORK_REQUEST,
            content=req,
            source="simulation"
        )
        
        insights = agent.analyze(context, [obs])
        
        for insight in insights:
            cm.add_insight(insight)
        
        print(f"    Found: {resp_data['method']} {resp_data['url']}")
    
    # 模拟 2: 从响应推导更多端点
    print("\n[*] Simulating: Response Inference")
    
    analyzer = ResponseAnalyzer(llm_client=None)
    
    inferred_count = 0
    for resp_data in api_responses:
        req = NetworkRequest(
            url=f"http://example.com{resp_data['url']}",
            method=resp_data['method'],
            headers={},
            body=None,
            response_status=resp_data['status'],
            response_body=resp_data['body'],
            response_headers={"content-type": "application/json"},
            timestamp=datetime.now(),
            source="simulation"
        )
        
        inferred = analyzer.infer_endpoints(req, context)
        for ep in inferred:
            if cm.add_endpoint(ep):
                inferred_count += 1
                print(f"    Inferred: {ep.method} {ep.path} (confidence: {ep.confidence:.2f})")
    
    print(f"\n[*] Total inferred endpoints: {inferred_count}")
    
    # 模拟 3: JS 源代码分析
    print("\n[*] Simulating: Source Code Analysis")
    
    js_content = '''
    const API_BASE = "http://example.com/api";
    
    // User endpoints
    axios.get("/users").then(...);
    axios.post("/users").then(...);
    axios.get("/users/" + id + "/profile").then(...);
    
    // Product endpoints
    fetch("/products").then(...);
    fetch("/products/" + id).then(...);
    
    // Order endpoints
    request({
        url: "/orders",
        method: "POST"
    });
    '''
    
    source_analyzer = SourceAnalyzer(llm_client=None)
    source_result = source_analyzer.analyze_js(js_content, context, "main.js")
    
    for ep in source_result.endpoints:
        if cm.add_endpoint(ep):
            print(f"    From JS: {ep.method} {ep.path}")
    
    # 模拟 4: 策略生成和执行
    print("\n[*] Simulating: Strategy Generation")
    
    insights = insight_gen.generate_from_observations([], context)
    strategy = strategy_gen.generate(context, insights)
    
    print(f"    Generated {len(strategy.actions)} actions:")
    for action in strategy.actions:
        print(f"      - {action.type.value}: {action.target or 'N/A'}")
    
    # 记录学习
    for action in strategy.actions[:3]:
        engine.record_decision(action, True, context, 0)
    
    learning_summary = engine.get_learning_summary()
    print(f"\n[*] Learning Summary:")
    print(f"    Total records: {learning_summary['total_records']}")
    print(f"    Patterns learned: {learning_summary['patterns_learned']}")
    print(f"    Action success rates: {learning_summary['action_success_rates']}")
    
    # 最终结果
    print("\n" + "=" * 60)
    print("Discovery Results")
    print("=" * 60)
    
    print(f"\nTotal Endpoints Discovered: {len(context.discovered_endpoints)}")
    print("\nEndpoints:")
    for ep in context.discovered_endpoints:
        print(f"  [{ep.source}] {ep.method:6} {ep.path} (confidence: {ep.confidence:.2f})")
    
    print("\nHigh Confidence Endpoints:")
    high_conf = cm.get_high_confidence_endpoints(threshold=0.7)
    for ep in high_conf:
        print(f"  {ep.method:6} {ep.path}")
    
    print("\nPatterns Discovered:")
    for pattern in context.known_patterns[:5]:
        print(f"  {pattern.template}")
    
    print("\n" + "=" * 60)
    print("End-to-End Test Complete!")
    print("=" * 60)
    
    return context


async def main():
    try:
        context = await simulate_discovery()
        return 0
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(asyncio.run(main()))
