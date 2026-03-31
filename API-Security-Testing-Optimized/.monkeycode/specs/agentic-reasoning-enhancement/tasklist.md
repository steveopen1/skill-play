# Agentic Reasoning Enhancement - 任务列表

## 概述

基于 `agentic-reasoning-enhancement` 设计文档，本任务列表将三大增强方向分解为可执行的任务。

## 任务列表

### Phase 1: 核心架构重构

- [x] **T1.1** 创建增强版推理引擎 `core/reasoning_engine.py`
  - 实现多层级推理流程 (Surface → Context → Causal → Strategic)
  - 实现推理规则引擎和规则注册机制
  - 实现置信度计算算法
  - 创建 `Finding` 和 `Insight` 数据类

- [x] **T1.2** 创建上下文管理器 `core/context_manager.py`
  - 实现 `GlobalContext` 数据结构
  - 实现 `TechStackContext`, `NetworkContext`, `SecurityContext`, `ContentContext`
  - 实现上下文更新和查询接口
  - 实现上下文持久化和恢复

- [x] **T1.3** 创建策略池系统 `core/strategy_pool.py`
  - 定义策略数据结构 `Strategy`, `Condition`, `Action`
  - 实现预定义策略库（8种策略）
  - 实现策略选择算法
  - 实现策略适应性调整机制

### Phase 2: 推理深度增强

- [x] **T2.1** 实现 SPA Fallback 推理规则 (已集成于 reasoning_engine.py)
- [x] **T2.2** 实现内网地址发现推理规则 (已集成于 reasoning_engine.py)
- [x] **T2.3** 实现 WAF 检测推理规则 (已集成于 reasoning_engine.py)
- [x] **T2.4** 实现响应矛盾检测 (已集成于 reasoning_engine.py)
- [x] **T2.5** 实现模式识别引擎 (已集成于 reasoning_engine.py)

### Phase 3: 动态策略调整

- [x] **T3.1** 实现策略切换状态机 (已集成于 strategy_pool.py)

- [x] **T3.2** 实现 WAF 绕过策略 (已集成于 strategy_pool.py)
- [x] **T3.3** 实现限速自适应策略 (已集成于 strategy_pool.py)
- [x] **T3.4** 实现高价值端点策略 (已集成于 strategy_pool.py)
- [x] **T3.5** 实现敏感操作安全策略 (已集成于 strategy_pool.py)

### Phase 4: 上下文感知增强

- [x] **T4.1** 实现技术栈指纹识别 (已集成于 reasoning_engine.py)
- [x] **T4.2** 实现网络环境感知 (已集成于 context_manager.py)
- [x] **T4.3** 实现安全态势感知 (已集成于 context_manager.py)
- [x] **T4.4** 实现内容特征感知 (已集成于 context_manager.py)

### Phase 5: 测试循环与验证

- [x] **T5.1** 实现洞察驱动循环 (已集成于 testing_loop.py)
- [x] **T5.2** 实现验证器 (已集成于 testing_loop.py)
- [x] **T5.3** 实现收敛检测 (已集成于 testing_loop.py)

### Phase 6: 人机交互

- [x] **T6.1** 实现暂停确认机制 (已集成于 testing_loop.py)
- [x] **T6.2** 实现推理解释接口 (已集成于 reasoning_engine.py Insight.to_dict)
- [x] **T6.3** 实现用户偏好记忆 (已集成于 context_manager.py user_preferences)

### Phase 7: 集成与测试

- [x] **T7.1** 更新 orchestrator.py
  - 集成新的推理引擎
  - 集成策略池系统
  - 集成上下文管理器

- [ ] **T7.2** 更新 SKILL.md
  - 添加新功能文档
  - 更新使用示例

- [ ] **T7.3** 创建单元测试
  - 推理引擎测试
  - 策略系统测试
  - 上下文管理测试

- [ ] **T7.4** 创建集成测试
  - 端到端测试场景
  - 性能测试

## 任务依赖关系

```
Phase 1 (核心架构)
├── T1.1, T1.2, T1.3
└── ↓
Phase 2 (推理增强) ← T1.1
├── T2.1 ~ T2.5
└── ↓
Phase 3 (策略调整) ← T1.3
├── T3.1 ~ T3.5
└── ↓
Phase 4 (上下文感知) ← T1.2
├── T4.1 ~ T4.4
└── ↓
Phase 5 (测试循环) ← T2.x, T3.x, T4.x
├── T5.1 ~ T5.3
└── ↓
Phase 6 (人机交互) ← T2.x
├── T6.1 ~ T6.3
└── ↓
Phase 7 (集成测试) ← 所有阶段
└── T7.1 ~ T7.4
```

## 优先级排序

1. **P0 (核心):** T1.1, T1.2, T1.3
2. **P1 (高):** T2.1, T2.2, T3.1, T4.1, T5.1, T7.1
3. **P2 (中):** T2.3, T2.4, T3.2, T3.3, T4.2, T4.3, T6.1
4. **P3 (低):** T2.5, T3.4, T3.5, T4.4, T5.2, T5.3, T6.2, T6.3, T7.2, T7.3, T7.4

## 预估工作量

| Phase | 任务数 | 预估工时 |
|-------|-------|---------|
| Phase 1 | 3 | 8h |
| Phase 2 | 5 | 10h |
| Phase 3 | 5 | 8h |
| Phase 4 | 4 | 6h |
| Phase 5 | 3 | 6h |
| Phase 6 | 3 | 4h |
| Phase 7 | 4 | 6h |
| **总计** | **27** | **48h** |
