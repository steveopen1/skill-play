"""
API Base Path 字典 - 常见API前缀/父路径
当无法从JS中获取baseURL时使用此字典进行fuzzing
"""

# 常见API前缀/父路径（按优先级排序）
COMMON_API_PREFIXES = [
    # 标准REST API
    "/api",
    "/api/v1",
    "/api/v2", 
    "/api/v3",
    "/api/rest",
    
    # 常见变体
    "/webapi",
    "/openapi",
    "/rest",
    "/rest/api",
    "/api/rest",
    
    # 管理类
    "/admin",
    "/manager",
    "/backend",
    "/server",
    "/service",
    
    # 认证类
    "/auth",
    "/oauth",
    "/oauth2",
    "/public",
    
    # 业务类
    "/user",
    "/users",
    "/customer",
    "/customers",
    "/order",
    "/orders",
    "/product",
    "/products",
]

# 常见后端技术栈默认端口对应
TECH_STACK_PORTS = {
    "java": [8080, 8443, 8000, 9000],
    "python": [5000, 8000, 8001],
    "nodejs": [3000, 3001, 8080],
    "php": [80, 8080, 443],
    "go": [8080, 8000, 9090],
    "asp.net": [80, 443, 8080],
}

# 常见API路径模式（用于识别已发现的API的父路径）
API_PATH_PATTERNS = [
    # user相关
    r"/user/([^/]+)",  # /user/login, /user/info
    r"/users?/([^/]+)",
    
    # auth相关
    r"/auth/([^/]+)",
    r"/oauth/([^/]+)",
    
    # admin相关
    r"/admin/([^/]+)",
    r"/manage/([^/]+)",
    
    # api相关
    r"/api/([^/]+)",
    r"/v([0-9]+)/([^/]+)",
]

# 完整的base_path fuzzing字典（组合前缀）
BASE_PATH_FUZZ_PATTERNS = [
    # 直接拼接常见前缀
    "/api/{}",
    "/api/v1/{}",
    "/api/v2/{}",
    "/webapi/{}",
    "/rest/{}",
    "/auth/{}",
    "/admin/{}",
    "/backend/{}",
    
    # 带版本的
    "/{}/v1",
    "/{}/v2",
    "/{}/v3",
    
    # 带api前缀
    "/api/{}/v1",
    "/api/{}/v2",
]

def get_base_path_candidates(discovered_path):
    """
    根据已发现的API路径生成可能的base_path候选
    
    例如:
    - discovered = "/user/login" -> candidates = ["/user", "/", ""]
    - discovered = "/api/v1/user/info" -> candidates = ["/api/v1", "/api", "/"]
    """
    candidates = []
    parts = discovered_path.strip("/").split("/")
    
    for i in range(1, len(parts)):
        candidate = "/" + "/".join(parts[:i])
        candidates.append(candidate)
    
    candidates.append("/")  # 根路径
    candidates.append("")   # 空路径（相对路径）
    
    return list(set(candidates))


def generate_fuzz_paths(path, prefixes=None):
    """
    生成fuzzing用的完整路径列表
    
    参数:
        path: 已发现的API路径（如 "user/login"）
        prefixes: 自定义前缀列表（可选）
    
    返回:
        完整的fuzzing路径列表
    """
    if prefixes is None:
        prefixes = COMMON_API_PREFIXES
    
    fuzz_paths = []
    path_parts = path.strip("/").split("/")
    
    # 生成各种组合
    for prefix in prefixes:
        # prefix + 完整path
        fuzz_paths.append(f"{prefix}/{path}")
        
        # prefix + 最后一个path
        if path_parts:
            fuzz_paths.append(f"{prefix}/{path_parts[-1]}")
    
    # 加上原始path
    fuzz_paths.append("/" + path)
    fuzz_paths.append(path)
    
    return list(set(fuzz_paths))


# 测试
if __name__ == "__main__":
    print("=== Base Path Dictionary ===")
    print(f"Common prefixes: {len(COMMON_API_PREFIXES)}")
    print(f"Tech stack ports: {len(TECH_STACK_PORTS)}")
    
    print("\n=== Candidates for /api/v1/user/login ===")
    candidates = get_base_path_candidates("/api/v1/user/login")
    for c in candidates:
        print(f"  {c}")
    
    print("\n=== Fuzz paths for 'user/login' ===")
    fuzz_paths = generate_fuzz_paths("user/login")
    for p in fuzz_paths[:10]:
        print(f"  {p}")
