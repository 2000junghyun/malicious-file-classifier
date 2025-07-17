# 확장자 기반 정적 필터링

def is_suspicious_extension(ext: str) -> bool:
    
    suspicious_exts = {
        ".php", ".exe", ".js", ".jsp", ".asp",
        ".sh", ".bat", ".dll", ".py", ".vbs",
        ".wsf", ".pl", ".scr", ".ps1", ".cmd"
    }
    
    return ext.lower() in suspicious_exts