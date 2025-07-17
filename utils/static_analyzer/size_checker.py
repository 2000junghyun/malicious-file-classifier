# 파일 크기 기반 정적 검사

def is_suspicious_size(ext: str, size: int) -> bool:

    ext = ext.lower()

    # 확장자별 허용 파일 크기 범위 (Byte 단위)
    size_limits = {
        ".php": (100, 5 * 1024 * 1024),     # 100B ~ 5MB
        ".js": (100, 2 * 1024 * 1024),      # 100B ~ 2MB
        ".exe": (10 * 1024, 50 * 1024 * 1024), # 10KB ~ 50MB
        ".dll": (10 * 1024, 50 * 1024 * 1024),
        ".bat": (50, 1 * 1024 * 1024),
        ".sh":  (50, 1 * 1024 * 1024),
        ".py":  (50, 2 * 1024 * 1024),
        ".vbs": (50, 512 * 1024),
    }

    # 정의된 확장자만 검사
    if ext in size_limits:
        min_size, max_size = size_limits[ext]
        if size < min_size or size > max_size:
            return True

    return False