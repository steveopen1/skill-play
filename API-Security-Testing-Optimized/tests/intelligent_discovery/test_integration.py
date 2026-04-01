"""
Integration Tests for Intelligent Discovery

测试各组件之间的协作
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime

from scripts.intelligent_discovery.models import (
    DiscoveryContext, Endpoint, Observation, Insight, Strategy, Action,
    NetworkRequest, PageStructure, ObservationType, InsightType, ActionType
)
from scripts.intelligent_discovery.context_manager import ContextManager, create_context_manager
from scripts.intelligent_discovery.learning_engine import LearningEngine, create_learning_engine
from scripts.intelligent_discovery.insight_generator import InsightGenerator, create_insight_generator
from scripts.intelligent_discovery.strategy_generator import StrategyGenerator, create_strategy_generator
from scripts.intelligent_discovery.agent_brain import AgentBrain, create_agent_brain


class TestAgentBrainIntegration:
    """Test AgentBrain integration with other components"""
    
    def test_agent_initialization(self):
        """Test agent can initialize context"""
        agent = create_agent_brain(llm_client=None)
        assert agent is not None
        
        context = agent.context
        assert context is None
    
    def test_agent_initialize_target(self):
        """Test agent can initialize with target"""
        agent = create_agent_brain(llm_client=None)
        context = agent.initialize("http://example.com")
        
        assert context is not None
        assert context.target == "http://example.com"
    
    def test_analyze_observations(self):
        """Test agent can analyze observations"""
        agent = create_agent_brain(llm_client=None)
        context = agent.initialize("http://example.com")
        
        req = NetworkRequest(
            url="http://example.com/api/users",
            method="GET",
            headers={},
            body=None,
            response_status=200,
            response_body='{"data": []}',
            response_headers={"content-type": "application/json"},
            timestamp=datetime.now(),
            source="test"
        )
        
        obs = Observation(
            type=ObservationType.NETWORK_REQUEST,
            content=req,
            source="test"
        )
        
        insights = agent.analyze(context, [obs])
        
        assert isinstance(insights, list)
    
    def test_generate_strategy(self):
        """Test agent can generate strategy"""
        agent = create_agent_brain(llm_client=None)
        context = agent.initialize("http://example.com")
        
        strategy = agent.generate_strategy(context, [])
        
        assert strategy is not None
        assert isinstance(strategy.actions, list)
        assert len(strategy.actions) > 0


class TestContextManagerIntegration:
    """Test ContextManager integration"""
    
    def test_add_multiple_endpoints(self):
        """Test adding multiple endpoints"""
        cm = create_context_manager("http://example.com")
        
        endpoints = [
            Endpoint(path="/api/users", method="GET"),
            Endpoint(path="/api/users", method="POST"),
            Endpoint(path="/api/products", method="GET"),
        ]
        
        for ep in endpoints:
            cm.add_endpoint(ep)
        
        assert len(cm.context.discovered_endpoints) == 3
    
    def test_deduplicate_endpoints(self):
        """Test endpoint deduplication"""
        cm = create_context_manager("http://example.com")
        
        ep1 = Endpoint(path="/api/users", method="GET")
        ep2 = Endpoint(path="/api/users", method="GET")
        
        result1 = cm.add_endpoint(ep1)
        result2 = cm.add_endpoint(ep2)
        
        assert result1 is True
        assert result2 is False
        assert len(cm.context.discovered_endpoints) == 1
    
    def test_convergence_detection(self):
        """Test convergence detection"""
        cm = create_context_manager("http://example.com")
        
        assert cm.converged() is False
        
        for i in range(50):
            action = Action(type=ActionType.WAIT, target=None)
            cm.record_action(action)
        
        assert cm.converged() is True


class TestLearningEngineIntegration:
    """Test LearningEngine integration"""
    
    def test_record_and_learn(self):
        """Test learning from actions"""
        engine = create_learning_engine()
        cm = create_context_manager("http://example.com")
        
        action = Action(type=ActionType.CLICK, target="button")
        engine.record_decision(action, True, cm.context, 2)
        
        assert len(engine._records) == 1
        
        confidence = engine.get_action_confidence(ActionType.CLICK)
        assert confidence > 0.5
    
    def test_pattern_extraction(self):
        """Test pattern extraction from history"""
        engine = create_learning_engine()
        cm = create_context_manager("http://example.com")
        
        for i in range(10):
            action = Action(
                type=ActionType.NAVIGATE,
                target=f"http://example.com/page{i}"
            )
            engine.record_decision(action, i % 2 == 0, cm.context, i)
        
        patterns = engine.extract_patterns()
        assert isinstance(patterns, list)


class TestInsightGeneratorIntegration:
    """Test InsightGenerator integration"""
    
    def test_generate_from_network_request(self):
        """Test generating insight from network request"""
        generator = create_insight_generator(llm_client=None)
        cm = create_context_manager("http://example.com")
        
        req = NetworkRequest(
            url="http://example.com/api/users",
            method="GET",
            headers={},
            body=None,
            response_status=200,
            response_body='{"data": []}',
            response_headers={"content-type": "application/json"},
            timestamp=datetime.now(),
            source="test"
        )
        
        obs = Observation(
            type=ObservationType.NETWORK_REQUEST,
            content=req,
            source="test"
        )
        
        insights = generator.generate_from_observations([obs], cm.context)
        
        assert len(insights) > 0
        assert insights[0].type in [InsightType.ENDPOINT, InsightType.PATTERN]
    
    def test_generate_from_page_structure(self):
        """Test generating insight from page structure"""
        generator = create_insight_generator(llm_client=None)
        cm = create_context_manager("http://example.com")
        
        page = PageStructure(
            url="http://example.com",
            title="Test Page",
            forms=[{"selector": "form", "fields": ["username", "password"]}],
            interactive_elements=[{"selector": "button", "type": "button"}]
        )
        
        obs = Observation(
            type=ObservationType.PAGE_STRUCTURE,
            content=page,
            source="test"
        )
        
        insights = generator.generate_from_observations([obs], cm.context)
        
        assert len(insights) > 0


class TestStrategyGeneratorIntegration:
    """Test StrategyGenerator integration"""
    
    def test_generate_strategy_with_context(self):
        """Test generating strategy with context"""
        generator = create_strategy_generator(llm_client=None)
        cm = create_context_manager("http://example.com")
        
        strategy = generator.generate(cm.context, [])
        
        assert strategy is not None
        assert len(strategy.actions) > 0
        assert all(isinstance(a, Action) for a in strategy.actions)
    
    def test_decide_next_action(self):
        """Test deciding next action"""
        generator = create_strategy_generator(llm_client=None)
        cm = create_context_manager("http://example.com")
        
        action, priority = generator.decide_next_action(cm.context)
        
        assert action is not None
        assert priority in ["high", "medium", "low"]


class TestFullPipeline:
    """Test complete discovery pipeline"""
    
    def test_simple_discovery_flow(self):
        """Test a simple discovery flow"""
        agent = create_agent_brain(llm_client=None)
        cm = create_context_manager("http://example.com")
        engine = create_learning_engine()
        
        context = agent.initialize("http://example.com")
        
        req = NetworkRequest(
            url="http://example.com/api/users",
            method="GET",
            headers={},
            body=None,
            response_status=200,
            response_body='{"data": [], "page": 1}',
            response_headers={"content-type": "application/json"},
            timestamp=datetime.now(),
            source="test"
        )
        
        obs = Observation(
            type=ObservationType.NETWORK_REQUEST,
            content=req,
            source="test"
        )
        
        insights = agent.analyze(context, [obs])
        
        cm.context.insights.extend(insights)
        for ep in context.discovered_endpoints:
            cm.add_endpoint(ep)
        
        assert len(cm.context.discovered_endpoints) >= 1
        
        action = Action(type=ActionType.ANALYZE_SOURCE, target="current_page")
        engine.record_decision(action, True, cm.context, 1)
        
        assert len(engine._records) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
