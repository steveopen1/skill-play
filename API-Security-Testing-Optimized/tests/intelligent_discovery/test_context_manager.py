"""
Tests for Intelligent Discovery - Context Manager
"""

import pytest

from scripts.intelligent_discovery.models import Endpoint, Action, ActionType, Pattern
from scripts.intelligent_discovery.context_manager import ContextManager, create_context_manager


class TestContextManager:
    """Test ContextManager"""
    
    def test_creation(self):
        cm = create_context_manager("http://example.com")
        assert cm.context.target == "http://example.com"
    
    def test_add_endpoint(self):
        cm = create_context_manager("http://example.com")
        ep = Endpoint(path="/api/users", method="GET")
        
        result = cm.add_endpoint(ep)
        assert result is True
        assert len(cm.context.discovered_endpoints) == 1
        
        result2 = cm.add_endpoint(ep)
        assert result2 is False
    
    def test_add_network_request(self):
        cm = create_context_manager("http://example.com")
        
        from scripts.intelligent_discovery.models import NetworkRequest
        from datetime import datetime
        
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
        
        cm.add_network_request(req)
        assert len(cm.context.network_requests) == 1
    
    def test_record_action(self):
        cm = create_context_manager("http://example.com")
        action = Action(type=ActionType.CLICK, target="button")
        
        cm.record_action(action, success=True)
        assert len(cm.context.exploration_history) == 1
        assert cm.context.exploration_history[0].success is True
    
    def test_converged(self):
        cm = create_context_manager("http://example.com")
        assert cm.converged() is False
        
        for i in range(51):
            cm.record_action(Action(type=ActionType.WAIT))
        assert cm.converged() is True
    
    def test_get_summary(self):
        cm = create_context_manager("http://example.com")
        summary = cm.get_summary()
        
        assert "target" in summary
        assert "endpoints_count" in summary
        assert summary["endpoints_count"] == 0
    
    def test_update_tech_stack(self):
        cm = create_context_manager("http://example.com")
        cm.update_tech_stack({"frontend": "react"})
        
        assert cm.context.tech_stack.frontend.value == "react"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
