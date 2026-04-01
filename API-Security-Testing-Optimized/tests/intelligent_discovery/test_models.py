"""
Tests for Intelligent Discovery - Models
"""

import pytest
from datetime import datetime

from scripts.intelligent_discovery.models import (
    Endpoint, Observation, Insight, Strategy, Action,
    NetworkRequest, Pattern, DiscoveryContext, TechStack,
    ObservationType, InsightType, ActionType, Finding,
    AnalysisResult, ExecutionResult, PageStructure, AuthInfo
)


class TestEndpoint:
    """Test Endpoint model"""
    
    def test_endpoint_creation(self):
        ep = Endpoint(path="/api/users", method="GET")
        assert ep.path == "/api/users"
        assert ep.method == "GET"
        assert ep.confidence == 0.5
        assert ep.source == "unknown"
    
    def test_endpoint_url_property(self):
        ep = Endpoint(path="/api/users", method="GET")
        assert ep.url == "GET /api/users"
    
    def test_endpoint_to_dict(self):
        ep = Endpoint(path="/api/users", method="GET", confidence=0.9)
        d = ep.to_dict()
        assert d["path"] == "/api/users"
        assert d["method"] == "GET"
        assert d["confidence"] == 0.9


class TestDiscoveryContext:
    """Test DiscoveryContext model"""
    
    def test_context_creation(self):
        ctx = DiscoveryContext(target="http://example.com")
        assert ctx.target == "http://example.com"
        assert len(ctx.discovered_endpoints) == 0
        assert ctx.api_base is None
    
    def test_add_endpoint(self):
        ctx = DiscoveryContext(target="http://example.com")
        ep = Endpoint(path="/api/users", method="GET")
        
        result1 = ctx.add_endpoint(ep)
        assert result1 is True
        assert len(ctx.discovered_endpoints) == 1
        
        result2 = ctx.add_endpoint(ep)
        assert result2 is False
        assert len(ctx.discovered_endpoints) == 1
    
    def test_add_network_request(self):
        ctx = DiscoveryContext(target="http://example.com")
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
        
        ctx.add_network_request(req)
        assert len(ctx.network_requests) == 1
    
    def test_converged_empty(self):
        ctx = DiscoveryContext(target="http://example.com")
        assert ctx.converged() is False
    
    def test_converged_max_iterations(self):
        ctx = DiscoveryContext(target="http://example.com")
        for i in range(51):
            ctx.record_action(Action(type=ActionType.NAVIGATE, target="test"))
        assert ctx.converged() is True
    
    def test_high_confidence_endpoints(self):
        ctx = DiscoveryContext(target="http://example.com")
        ctx.add_endpoint(Endpoint(path="/api/a", method="GET", confidence=0.9))
        ctx.add_endpoint(Endpoint(path="/api/b", method="GET", confidence=0.5))
        ctx.add_endpoint(Endpoint(path="/api/c", method="GET", confidence=0.8))
        
        high_conf = ctx.get_high_confidence_endpoints(threshold=0.7)
        assert len(high_conf) == 2


class TestObservation:
    """Test Observation model"""
    
    def test_observation_creation(self):
        obs = Observation(
            type=ObservationType.NETWORK_REQUEST,
            content={"url": "test"},
            source="test"
        )
        assert obs.type == ObservationType.NETWORK_REQUEST
        assert obs.source == "test"


class TestInsight:
    """Test Insight model"""
    
    def test_insight_creation(self):
        insight = Insight(
            type=InsightType.PATTERN,
            content="Test pattern",
            confidence=0.8
        )
        assert insight.type == InsightType.PATTERN
        assert insight.confidence == 0.8
    
    def test_insight_with_findings(self):
        finding = Finding(
            what="Found something",
            so_what="It means something",
            evidence=["evidence1"]
        )
        insight = Insight(
            type=InsightType.ENDPOINT,
            content="Test",
            confidence=0.9,
            findings=[finding]
        )
        assert len(insight.findings) == 1


class TestAction:
    """Test Action model"""
    
    def test_action_creation(self):
        action = Action(
            type=ActionType.CLICK,
            target="button#submit",
            reasoning="Click submit"
        )
        assert action.type == ActionType.CLICK
        assert action.target == "button#submit"
        assert action.success is False


class TestNetworkRequest:
    """Test NetworkRequest model"""
    
    def test_is_api_true(self):
        req = NetworkRequest(
            url="http://example.com/api/users",
            method="GET",
            headers={},
            body=None,
            response_status=200,
            response_body="",
            response_headers={},
            timestamp=datetime.now(),
            source="test"
        )
        assert req.is_api is True
    
    def test_is_api_false(self):
        req = NetworkRequest(
            url="http://example.com/style.css",
            method="GET",
            headers={},
            body=None,
            response_status=200,
            response_body="",
            response_headers={},
            timestamp=datetime.now(),
            source="test"
        )
        assert req.is_api is False


class TestPattern:
    """Test Pattern model"""
    
    def test_pattern_creation(self):
        pattern = Pattern(
            template="/api/{resource}/{id}",
            example="/api/users/123",
            confidence=0.8
        )
        assert pattern.template == "/api/{resource}/{id}"
        assert pattern.confidence == 0.8


class TestTechStack:
    """Test TechStack model"""
    
    def test_tech_stack_creation(self):
        from scripts.intelligent_discovery.models import TechStackType
        
        ts = TechStack(frontend=TechStackType.REACT)
        assert ts.frontend == TechStackType.REACT
        assert ts.backend == TechStackType.BACKEND_UNKNOWN


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
