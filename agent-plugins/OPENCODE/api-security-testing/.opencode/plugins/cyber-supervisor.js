/**
 * API Security Testing - Cyber Supervisor Plugin
 * 
 * 赛博监工：自动监督 API 安全测试进度，失败时触发压力升级
 * 
 * Hook Events:
 * - session.created: 初始化测试状态
 * - tool.execute.after: 监控测试进度，检测失败
 * - session.idle: 检查测试是否完成
 */

const state = {
  progress: 0,
  failureCount: 0,
  lastDiscovery: null,
  hookEnabled: false,
  pressureLevel: 0
};

// 压力等级阈值
const PRESSURE_THRESHOLDS = {
  L1: 2,  // 2次失败
  L2: 3,  // 3次失败
  L3: 5,  // 5次失败
  L4: 7   // 7次失败
};

// 进度阈值
const PROGRESS_THRESHOLDS = {
  LOW: 30,    // < 30% 进度过低
  MEDIUM: 60, // 30-60%
  HIGH: 90    // > 90% 快完成了
};

/**
 * 获取压力等级描述
 */
function getPressureMessage(level) {
  const messages = {
    0: "",
    1: "▎[赛博监工 L1] 发现失败，切换方法继续",
    2: "▎[赛博监工 L2] 失败累积，执行深度分析",
    3: "▎[赛博监工 L3] 触发检查清单，7点验证",
    4: "▎[赛博监工 L4] 绝望模式，拼死一搏"
  };
  return messages[level] || "";
}

/**
 * 判断是否发现新漏洞
 */
function isNewDiscovery(output) {
  if (!output || !output.content) return false;
  const content = JSON.stringify(output).toLowerCase();
  const keywords = ['vulnerability', '漏洞', 'injection', 'xss', 'exposure', 'bypass'];
  return keywords.some(k => content.includes(k));
}

/**
 * 判断是否失败
 */
function isFailure(output) {
  if (!output || !output.content) return false;
  const content = JSON.stringify(output).toLowerCase();
  const failureKeywords = ['failed', 'error', '错误', '失败', 'timeout', 'denied'];
  return failureKeywords.some(k => content.includes(k));
}

export const CyberSupervisorPlugin = async ({ client, directory }) => {
  console.log("[赛博监工] API Security Testing 插件已加载");

  return {
    /**
     * 会话创建时初始化
     */
    "session.created": async ({ event }) => {
      state.progress = 0;
      state.failureCount = 0;
      state.lastDiscovery = null;
      state.pressureLevel = 0;
      
      await client.app.log({
        body: {
          service: "cyber-supervisor",
          level: "info",
          message: "赛博监工已初始化",
          progress: state.progress,
          hookEnabled: state.hookEnabled
        }
      });
    },

    /**
     * 工具执行后检查
     */
    "tool.execute.after": async (input, output) => {
      if (!state.hookEnabled) return;

      const toolName = input.tool || "unknown";

      // 检测新发现
      if (isNewDiscovery(output)) {
        state.lastDiscovery = Date.now();
        state.progress = Math.min(state.progress + 10, 100);
        
        await client.app.log({
          body: {
            service: "cyber-supervisor",
            level: "info",
            message: "发现新漏洞或端点",
            progress: state.progress,
            tool: toolName
          }
        });
      }

      // 检测失败
      if (isFailure(output)) {
        state.failureCount++;
        
        // 压力升级
        if (state.failureCount >= PRESSURE_THRESHOLDS.L4) {
          state.pressureLevel = 4;
        } else if (state.failureCount >= PRESSURE_THRESHOLDS.L3) {
          state.pressureLevel = 3;
        } else if (state.failureCount >= PRESSURE_THRESHOLDS.L2) {
          state.pressureLevel = 2;
        } else if (state.failureCount >= PRESSURE_THRESHOLDS.L1) {
          state.pressureLevel = 1;
        }

        const msg = getPressureMessage(state.pressureLevel);
        if (msg) {
          await client.app.log({
            body: {
              service: "cyber-supervisor",
              level: "warn",
              message: msg,
              failureCount: state.failureCount,
              pressureLevel: state.pressureLevel
            }
          });
        }
      }

      // 进度更新
      if (toolName === "read" || toolName === "write" || toolName === "edit") {
        state.progress = Math.min(state.progress + 2, 100);
      }
    },

    /**
     * 会话空闲时检查
     */
    "session.idle": async ({ event }) => {
      if (!state.hookEnabled) return;

      // 检查进度是否过低
      if (state.progress < PROGRESS_THRESHOLDS.LOW && state.failureCount > 0) {
        await client.app.log({
          body: {
            service: "cyber-supervisor",
            level: "warn",
            message: `▎[赛博监工警告] 进度 ${state.progress}% 低于预期，失败次数 ${state.failureCount}`,
            suggestion: "考虑切换测试策略或扩大扫描范围"
          }
        });
      }

      // 检查是否完成
      if (state.progress >= 100) {
        await client.app.log({
          body: {
            service: "cyber-supervisor",
            level: "info",
            message: "▎[赛博监工] 测试完成！"
          }
        });
      }
    },

    /**
     * 赛博监工控制接口
     */
    tool: {
      "cyber-supervisor": {
        description: "赛博监工控制 - 监督 API 安全测试进度",
        args: {
          action: {
            schema: {
              type: "string",
              enum: ["on", "off", "status", "reset"]
            },
            description: "操作: on=开启, off=关闭, status=状态, reset=重置"
          }
        },
        async execute(args) {
          switch (args.action) {
            case "on":
              state.hookEnabled = true;
              return "▎[赛博监工] 已开启，自动监督测试进度";
            
            case "off":
              state.hookEnabled = false;
              return "▎[赛博监工] 已关闭";
            
            case "status":
              return `▎[赛博监工状态]
进度: ${state.progress}%
失败次数: ${state.failureCount}
压力等级: L${state.pressureLevel || 0}
监控: ${state.hookEnabled ? "开启" : "关闭"}`;
            
            case "reset":
              state.progress = 0;
              state.failureCount = 0;
              state.pressureLevel = 0;
              state.lastDiscovery = null;
              return "▎[赛博监工] 状态已重置";
            
            default:
              return "▎[赛博监工] 未知操作，请使用 on/off/status/reset";
          }
        }
      }
    }
  };
};

export default CyberSupervisorPlugin;