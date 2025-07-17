# MIME 불일치 검사 모듈

def is_mismatched_mime(ext: str, content_type: str) -> bool:

    ext = ext.lower()
    content_type = content_type.lower()

    # 확장자별 정상 MIME 목록
    expected_mime_map = {
        ".js": {"application/javascript", "text/javascript"},
        ".php": {"application/x-httpd-php"},
        ".exe": {"application/x-msdownload", "application/octet-stream"},
        ".dll": {"application/x-msdownload"},
        ".bat": {"application/x-msdos-program"},
        ".sh": {"application/x-sh"},
        ".py": {"text/x-python", "application/x-python-code"},
        ".vbs": {"text/vbscript", "application/vbscript"},
        ".html": {"text/html"},
        ".txt": {"text/plain"},
    }

    # 확장자에 대해 정의된 MIME이 없다면 검사 생략
    if ext not in expected_mime_map:
        return False

    # 기대 MIME 목록과 다르면 불일치
    if content_type not in expected_mime_map[ext]:
        return True

    return False