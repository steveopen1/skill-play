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

const PRESSURE_THRESHOLDS = { L1: 2, L2: 3, L3: 5, L4: 7 };
const PROGRESS_THRESHOLDS = { LOW: 30, MEDIUM: 60, HIGH: 90 };

function getPressureMessage(level) {
  const messages = { 0: "", 1: "▎[赛博监工 L1] 切换方法", 2: "▎[赛博监工 L2] 深度分析", 3: "▎[赛博监工 L3] 7点检查", 4: "▎[赛博监工 L4] 绝望模式" };
  return messages[level] || "";
}

function isNewDiscovery(output) {
  if (!output || !output.content) return false;
  const content = JSON.stringify(output).toLowerCase();
  return ['vulnerability', '漏洞', 'injection', 'xss', 'exposure', 'bypass'].some(k => content.includes(k));
}

function isFailure(output) {
  if (!output || !output.content) return false;
  const content = JSON.stringify(output).toLowerCase();
  return ['failed', 'error', '错误', '失败', 'timeout', 'denied'].some(k => content.includes(k));
}

export const CyberSupervisorPlugin = async ({ project, client, $, directory, worktree }) => {
  const state = {
    progress: 0,
    failureCount: 0,
    lastDiscovery: null,
    hookEnabled: true,
    pressureLevel: 0,
    autoActivate: true
  };

  console.log("[赛博监工] API Security Testing 插件已加载");

  return {
    "session.created": async ({ event }) => {
      state.progress = 0;
      state.failureCount = 0;
      state.lastDiscovery = null;
      state.pressureLevel = 0;
      state.hookEnabled = state.autoActivate;
      
      await client.app.log({
        body: {
          service: "cyber-supervisor",
          level: "info",
          message: state.autoActivate ? "赛博监工已自动激活" : "赛博监工已初始化",
          progress: state.progress,
          hookEnabled: state.hookEnabled
        }
      });
    },

    "tool.execute.after": async (input, output) => {
      if (!state.hookEnabled) return;
      const toolName = input.tool || "unknown";

      if (isNewDiscovery(output)) {
        state.lastDiscovery = Date.now();
        state.progress = Math.min(state.progress + 10, 100);
        await client.app.log({ body: { service: "cyber-supervisor", level: "info", message: "发现新漏洞或端点", progress: state.progress, tool: toolName }});
      }

      if (isFailure(output)) {
        state.failureCount++;
        if (state.failureCount >= PRESSURE_THRESHOLDS.L4) state.pressureLevel = 4;
        else if (state.failureCount >= PRESSURE_THRESHOLDS.L3) state.pressureLevel = 3;
        else if (state.failureCount >= PRESSURE_THRESHOLDS.L2) state.pressureLevel = 2;
        else if (state.failureCount >= PRESSURE_THRESHOLDS.L1) state.pressureLevel = 1;

        const msg = getPressureMessage(state.pressureLevel);
        if (msg) {
          await client.app.log({ body: { service: "cyber-supervisor", level: "warn", message: msg, failureCount: state.failureCount, pressureLevel: state.pressureLevel }});
        }
      }

      if (toolName === "read" || toolName === "write" || toolName === "edit") {
        state.progress = Math.min(state.progress + 2, 100);
      }
    },

    "session.idle": async ({ event }) => {
      if (!state.hookEnabled) return;
      if (state.progress < PROGRESS_THRESHOLDS.LOW && state.failureCount > 0) {
        await client.app.log({ body: { service: "cyber-supervisor", level: "warn", message: `▎[赛博监工警告] 进度 ${state.progress}% 低于预期`, suggestion: "考虑切换测试策略" }});
      }
      if (state.progress >= 100) {
        await client.app.log({ body: { service: "cyber-supervisor", level: "info", message: "▎[赛博监工] 测试完成！" }});
      }
    },

    tool: {
      "cyber-supervisor": {
        description: "赛博监工控制 - 监督 API 安全测试进度",
        args: {
          action: { schema: { type: "string", enum: ["on", "off", "status", "reset"] }, description: "操作: on=开启, off=关闭, status=状态, reset=重置" }
        },
        async execute(args) {
          switch (args.action) {
            case "on": state.hookEnabled = true; state.autoActivate = true; return "▎[赛博监工] 已开启";
            case "off": state.hookEnabled = false; state.autoActivate = false; return "▎[赛博监工] 已关闭";
            case "status": return `▎[赛博监工状态]\n进度: ${state.progress}%\n失败: ${state.failureCount}\n等级: L${state.pressureLevel || 0}\n监控: ${state.hookEnabled ? "开启" : "关闭"}`;
            case "reset": state.progress = 0; state.failureCount = 0; state.pressureLevel = 0; state.lastDiscovery = null; return "▎[赛博监工] 状态已重置";
            default: return "▎[赛博监工] 未知操作";
          }
        }
      }
    }
  };
};

export default CyberSupervisorPlugin;
