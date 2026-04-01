"""
Tests for Intelligent Discovery - Learning Engine
"""

import pytest
from datetime import datetime

from scripts.intelligent_discovery.models import (
    DiscoveryContext, Endpoint, Action, ActionType
)
from scripts.intelligent_discovery.learning_engine import (
    LearningEngine, create_learning_engine
)


class TestLearningEngine:
    """Test LearningEngine"""
    
    def test_creation(self):
        engine = create_learning_engine()
        assert engine is not None
        assert len(engine._records) == 0
    
    def test_record_decision(self):
        engine = create_learning_engine()
        context = DiscoveryContext(target="http://example.com")
        action = Action(type=ActionType.NAVIGATE, target="http://example.com")
        
        engine.record_decision(
            action=action,
            result=True,
            context=context,
            new_endpoints=2
        )
        
        assert len(engine._records) == 1
    
    def test_action_success_rate(self):
        engine = create_learning_engine()
        context = DiscoveryContext(target="http://example.com")
        
        for i in range(5):
            action = Action(type=ActionType.CLICK, target="button")
            engine.record_decision(action, True, context, 1)
        
        rate = engine.get_action_confidence(ActionType.CLICK)
        assert rate > 0.5
    
    def test_extract_patterns(self):
        engine = create_learning_engine()
        patterns = engine.extract_patterns()
        assert isinstance(patterns, list)
    
    def test_learning_summary(self):
        engine = create_learning_engine()
        summary = engine.get_learning_summary()
        assert "total_records" in summary
        assert "patterns_learned" in summary
        assert "action_success_rates" in summary
    
    def test_export_learning_data(self):
        engine = create_learning_engine()
        data = engine.export_learning_data()
        assert "records" in data
        assert "patterns" in data
        assert "action_rates" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
