import boto3
import json
import re
import os

s3 = boto3.client("s3")

# test.php 파일 로드
current_dir = os.path.dirname(os.path.abspath(__file__))
target_path = os.path.join(current_dir, "..", "test_files", "test.php")

with open(target_path, "r", encoding="utf-8") as f:
    TEST_CONTENT = f.read()

def check_content_signature(bucket: str, key: str, test_mode: bool = True) -> dict:
    matches = []
    _, ext = os.path.splitext(key)
    ext = ext.lower()

    try:
        if test_mode:
            response = {
                'Body': TEST_CONTENT.encode("utf-8")  # s3.get_object()와 유사하게 바이너리
            }
            content = response['Body'].decode(errors="ignore")  # 실제 S3와 유사하게 처리
        else:
            # S3 객체 다운로드
            response = s3.get_object(Bucket=bucket, Key=key)
            content = response['Body'].read().decode(errors="ignore")  # 바이너리 포함 고려

        # 확장자별 시그니처 매핑
        signature_map = {
            ".php": [
                (r'\beval\s*\(', "eval"),
                (r'\bsystem\s*\(', "system"),
                (r'\bexec\s*\(', "exec"),
                (r'\bpassthru\s*\(', "passthru"),
                (r'\bshell_exec\s*\(', "shell_exec"),
                (r'\bbase64_decode\s*\(', "base64_decode"),
            ],
            ".js": [
                (r'\beval\s*\(', "eval"),
                (r'document\.write\s*\(\s*atob\s*\(', "document.write(atob)"),
                (r'\bFunction\s*\(', "Function"),
                (r'window\s*\[\s*["\']setTimeout["\']\s*\]', "window['setTimeout']"),
            ],
            ".exe": [
                (r'^MZ', "MZ Header"),
                (r'PE\0\0', "PE Header"),
            ],
            ".sh": [
                (r'\bcurl\b', "curl"),
                (r'\bwget\b', "wget"),
                (r'\bchmod\s+\+x\b', "chmod +x"),
                (r'bash\s+-i', "bash reverse shell"),
                (r'rm\s+-rf', "rm -rf"),
            ],
            ".bat": [
                (r'\bpowershell\b', "powershell"),
                (r'\bshutdown\b', "shutdown"),
                (r'\bdel\s+', "del"),
                (r'\bstart\s+', "start"),
                (r'\bcopy\s+', "copy"),
            ],
            ".py": [
                (r'\bos\.system\s*\(', "os.system"),
                (r'\bsubprocess\.(Popen|call|run)\s*\(', "subprocess"),
                (r'\beval\s*\(', "eval"),
                (r'\bexec\s*\(', "exec"),
            ],
            ".vbs": [
                (r'\bCreateObject\s*\(', "CreateObject"),
                (r'\bShell\s*\(', "Shell"),
                (r'\bExecute\s*\(', "Execute"),
                (r'\bWScript\.Shell\b', "WScript.Shell"),
            ],
        }

        # 정의되지 않은 확장자 탐지 생략
        if ext not in signature_map:
            return {
                "status": "bypass"
            }

        # 시그니처 탐지
        for pattern, name in signature_map[ext]:
            if re.search(pattern, content, re.IGNORECASE):
                matches.append(name)

        status = "malicious" if len(matches) >= 2 else "suspicious" if len(matches) == 1 else "clear"
        return {
            "status": status,
            "matches": matches,
            "ext": ext
        }

    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }