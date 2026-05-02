package ai.burp.ui;

import java.awt.Color;
import java.awt.Font;

/**
 * 中文UI常量和统一样式。
 * 所有界面文字集中管理，一处修改全局生效。
 */
public final class ChineseUI
{
    private ChineseUI() {}

    // ==================== 标签页名称 ====================
    public static final String TAB_MAIN = "by ai";
    public static final String TAB_CHAT = "AI 对话";
    public static final String TAB_DASHBOARD = "安全仪表盘";
    public static final String TAB_TRAFFIC = "流量分析";
    public static final String TAB_AI_REQUEST = "AI 请求";
    public static final String TAB_REPORT = "漏洞报告";
    public static final String TAB_SETTINGS = "设置";

    // ==================== 仪表盘主机选择器 ====================
    public static final String DASHBOARD_HOST_LABEL = "目标主机:";
    public static final String DASHBOARD_BTN_START = "开始分析";
    public static final String DASHBOARD_BTN_STOP = "暂停";
    public static final String DASHBOARD_STATUS_ANALYZING = "正在分析...";
    public static final String DASHBOARD_STATUS_DONE = "分析完成";

    // ==================== 按钮文字 ====================
    public static final String BTN_SEND = "发送";
    public static final String BTN_STOP = "停止";
    public static final String BTN_CLEAR = "清空";
    public static final String BTN_SETTINGS = "设置";
    public static final String BTN_START_ANALYZE = "开始分析";
    public static final String BTN_STOP_ANALYZE = "停止分析";
    public static final String BTN_TEST_CONN = "测试连接";
    public static final String BTN_SAVE = "保存";
    public static final String BTN_OPEN_CONFIG = "打开配置目录";
    public static final String BTN_TO_REPEATER = "\u25B6 Repeater";
    public static final String BTN_DETAIL = "详情";

    // ==================== 状态文字 ====================
    public static final String STATUS_THINKING = "正在思考...";
    public static final String STATUS_STREAMING = "正在生成...";
    public static final String STATUS_NOT_CONFIGURED = "未配置";
    public static final String STATUS_CONFIGURED = "已配置";
    public static final String STATUS_ANALYZING = "正在分析...";
    public static final String STATUS_QUEUED = "排队中 (%d)...";
    public static final String MSG_STOPPED_CONTINUE = "已跳过，继续下一个...";
    public static final String MSG_QUEUE_EMPTY = "已跳过，无排队任务";

    // ==================== 系统消息 ====================
    public static final String MSG_NOT_CONFIGURED = "API 未配置。点击「设置」配置您的 AI 服务。";
    public static final String MSG_SETTINGS_SAVED = "设置已保存。已连接: %s";
    public static final String MSG_TEST_OK = "连接成功！响应: %s";
    public static final String MSG_TEST_FAIL = "连接失败: %s";
    public static final String MSG_API_NOT_CONFIGURED = "API 未配置。点击「设置」配置后使用。";
    public static final String MSG_NO_HISTORY = "代理历史为空，无数据可分析。";
    public static final String MSG_ANALYSIS_COMPLETE = "分析完成，共发现 %d 个风险点。";
    public static final String MSG_ANALYSIS_EMPTY = "分析完成，未发现明显风险。";

    // ==================== 右键菜单 ====================
    public static final String MENU_AI = "by ai";
    public static final String MENU_EXPLAIN_REQ = "分析此请求";
    public static final String MENU_EXPLAIN_RESP = "分析此响应";
    public static final String MENU_FIND_VULN = "查找漏洞";
    public static final String MENU_SUGGEST_PAYLOAD = "生成攻击载荷";
    public static final String MENU_AUTO_VERIFY = "自动验证漏洞";
    public static final String MENU_ANALYZE_AUTH = "分析认证机制";
    public static final String MENU_CSRF_POC = "生成 CSRF PoC";
    public static final String MENU_DECODE = "解码与分析";
    public static final String MENU_SEND_TO_CHAT = "发送到 AI 对话";
    public static final String MENU_FULL_SCAN = "全量扫描此目标";
    public static final String MENU_AI_REWRITE = "AI 智能改写";
    public static final String MENU_SEND_ANALYZE = "发送并分析";

    // ==================== 设置面板 ====================
    public static final String SETTINGS_QUICK = "快速设置:";
    public static final String SETTINGS_URL = "API 地址:";
    public static final String SETTINGS_KEY = "API 密钥:";
    public static final String SETTINGS_MODEL = "模型:";
    public static final String SETTINGS_PROMPT = "系统提示词:";
    public static final String SETTINGS_STREAMING = "启用流式响应";
    public static final String SETTINGS_COMPATIBLE = "兼容服务: OpenAI, Azure OpenAI, Ollama, LM Studio, vLLM, DeepSeek, ChatGLM 等任何 OpenAI 兼容 API";

    // ==================== 实时分析配置 ====================

    // ==================== 预设名称 ====================
    public static final String PRESET_OPENAI = "OpenAI";
    public static final String PRESET_OLLAMA = "Ollama";
    public static final String PRESET_LMSTUDIO = "LM Studio";
    public static final String PRESET_DEEPSEEK = "DeepSeek";
    public static final String PRESET_CUSTOM = "自定义";

    // ==================== 实时分析配置 ====================
    public static final String SETTINGS_REALTIME_SECTION = "实时分析配置";
    public static final String SETTINGS_THRESHOLD = "可疑度阈值:";
    public static final String SETTINGS_THRESHOLD_TIP = "低于此值的请求不会被AI分析(0-20，默认5)";
    public static final String SETTINGS_DEBOUNCE = "防抖间隔(秒):";
    public static final String SETTINGS_DEBOUNCE_TIP = "同一域名两次分析的间隔(5-300秒，默认120)";

    // ==================== OOB 带外测试配置 ====================
    public static final String SETTINGS_OOB_SECTION = "OOB 带外测试配置";
    public static final String SETTINGS_USE_COLLABORATOR = "使用 Burp Collaborator（推荐）";
    public static final String SETTINGS_USE_COLLABORATOR_TIP = "使用 Burp Suite 内置 Collaborator 进行 SSRF/XXE 等带外检测";
    public static final String SETTINGS_DNSLOG_DOMAIN = "自定义 DNSLog 域名:";
    public static final String SETTINGS_DNSLOG_TIP = "用于 SSRF/XXE 等带外检测，留空则不使用自定义域名";

    // ==================== 流量分析面板 ====================
    public static final String TRAFFIC_CONFIG = "分析配置";
    public static final String TRAFFIC_RECENT = "分析最近";
    public static final String TRAFFIC_ITEMS = "条代理历史";
    public static final String TRAFFIC_FOCUS = "关注类型:";
    public static final String TRAFFIC_LOG = "分析日志";
    public static final String TRAFFIC_RESULTS = "分析结果";
    public static final String TRAFFIC_ALL_TYPES = "全部";
    public static final String TRAFFIC_FOUND_COUNT = "发现 %d 个风险点 (已验证: %d / 待验证: %d)";
    public static final String TRAFFIC_STATS = "统计";
    public static final String TRAFFIC_FILTER_HOST = "域名筛选:";
    public static final String TRAFFIC_FILTER_METHOD = "方法:";
    public static final String TRAFFIC_FILTER_STATUS = "状态码:";
    public static final String TRAFFIC_FILTER_KEYWORD = "关键词:";
    public static final String TRAFFIC_FILTER_SHOW = "筛选条件";
    public static final String TRAFFIC_EXPORT = "导出报告";
    public static final String TRAFFIC_TO_CHAT = "发送到对话";
    public static final String TRAFFIC_TO_CHAT_TIP = "将分析结果新建聊天会话，支持追问和漏洞验证";
    public static final String TRAFFIC_REALTIME = "实时监控";
    public static final String TRAFFIC_REALTIME_TIP = "自动分析新产生的代理流量";
    public static final String[] TRAFFIC_TYPE_OPTIONS = {
        "全部", "SQL注入", "XSS", "SSRF", "IDOR", "认证问题", "信息泄露", "命令注入", "路径遍历",
        "CORS配置错误", "JWT安全", "反序列化", "XXE", "文件上传"
    };
    public static final String[] TRAFFIC_METHOD_OPTIONS = {
        "全部", "GET", "POST", "PUT", "DELETE", "PATCH"
    };

    // ==================== 表格列名 ====================
    public static final String COL_URL = "URL";
    public static final String COL_METHOD = "方法";
    public static final String COL_RISK_TYPE = "风险类型";
    public static final String COL_SEVERITY = "严重性";
    public static final String COL_PARAMETER = "参数";
    public static final String COL_SUGGESTION = "AI 建议";
    public static final String COL_STATUS = "状态";
    public static final String COL_ACTION = "操作";

    // ==================== 漏洞严重性 ====================
    public static final String SEV_CRITICAL = "严重";
    public static final String SEV_HIGH = "高";
    public static final String SEV_MEDIUM = "中";
    public static final String SEV_LOW = "低";
    public static final String SEV_INFO = "信息";

    // ==================== 漏洞报告面板 ====================
    public static final String REPORT_COL_TIME = "时间";
    public static final String REPORT_COL_VULN_TYPE = "漏洞类型";
    public static final String REPORT_COL_SEVERITY = "严重性";
    public static final String REPORT_COL_PARAMETER = "参数";
    public static final String REPORT_COL_STATUS = "验证状态";
    public static final String REPORT_COL_ACTION = "操作";
    public static final String REPORT_SEARCH_PLACEHOLDER = "搜索漏洞类型、URL、参数...";
    public static final String REPORT_SEVERITY_FILTER_ALL = "全部";
    public static final String REPORT_STATUS_FILTER_ALL = "全部";
    public static final String REPORT_COUNT_FORMAT = "共 %d 个漏洞";
    public static final String REPORT_BTN_CLEAR_ALL = "清空";
    public static final String REPORT_BTN_DELETE = "删除";
    public static final String REPORT_MENU_MARK_CONFIRMED = "标记为已确认";
    public static final String REPORT_MENU_MARK_FALSE_POSITIVE = "标记为误报";
    public static final String REPORT_MENU_MARK_PENDING = "标记为待验证";
    public static final String REPORT_MENU_DELETE = "删除此报告";
    public static final String REPORT_CONFIRM_DELETE = "确认删除选中的 %d 条报告？";
    public static final String REPORT_CONFIRM_CLEAR = "确认清空全部 %d 条报告？";
    public static final String[] REPORT_SEVERITY_OPTIONS = {
        "全部", "严重", "高", "中", "低", "信息"
    };
    public static final String[] REPORT_STATUS_OPTIONS = {
        "全部", "待验证", "已确认", "误报", "无法验证"
    };

    // ==================== 颜色方案 ====================
    public static final Color COLOR_USER_BG = new Color(0xe3, 0xf2, 0xfd);
    public static final Color COLOR_USER_FG = new Color(0x15, 0x65, 0xc0);
    public static final Color COLOR_AI_BG = new Color(0xf1, 0xf8, 0xe9);
    public static final Color COLOR_AI_FG = new Color(0x2e, 0x7d, 0x32);
    public static final Color COLOR_SYSTEM_BG = new Color(0xf5, 0xf5, 0xf5);
    public static final Color COLOR_SYSTEM_FG = new Color(0x61, 0x61, 0x61);
    public static final Color COLOR_ERROR_BG = new Color(0xff, 0xeb, 0xee);
    public static final Color COLOR_ERROR_FG = new Color(0xc6, 0x28, 0x28);

    // ==================== 字体 ====================
    public static Font getMonospaceFont()
    {
        return new Font(Font.MONOSPACED, Font.PLAIN, 13);
    }
}
