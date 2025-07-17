import os
import json
import boto3

from utils.static_analyzer.ext_filter import is_suspicious_extension
from utils.static_analyzer.mime_checker import is_mismatched_mime
from utils.static_analyzer.size_checker import is_suspicious_size

# meta_data.json 파일 로드
current_dir = os.path.dirname(os.path.abspath(__file__))
target_path = os.path.join(current_dir, "..", "test_files", "meta_data.json")

with open(target_path, "r", encoding="utf-8") as f:
    TEST_RESPONSE = json.load(f)

s3 = boto3.client("s3")


def metadata_classifier_handler(bucket, key):
    result = classify__metadata(bucket, key)

    if result["status"] == "error":
        print("[!] Error during metadata analysis:", result["error"])
        print("[TODO] Invoke log_handler(event)")
        return result["status"]

    if result["status"] == "malicious":
        print(f"[!] Metadata analysis flagged the file: reasons={result['reasons']}, ext={result['ext']}, type={result['content_type']}, size={result['size']}, weight={result['weight']}")
        print("[TODO] Invoke threat_handler(event)")
        print("[TODO] Invoke alert_handler(event)")
        return result["status"]
    
    elif result["status"] == "suspicious":
        print(f"[!] Metadata analysis flagged the file: reasons={result['reasons']}, ext={result['ext']}, type={result['content_type']}, size={result['size']}, weight={result['weight']}")
        print("[TODO] Invoke alert_handler(event)")
        return result["status"]
    
    else:
        print("[+] File passed the metadata analysis")
        return result["status"]


def classify__metadata(bucket: str, key: str, test_mode: bool = True) -> dict:
    total_weight = 0
    reasons = []

    # 확장자 추출
    _, ext = os.path.splitext(key)
    ext = ext.lower()

    try:
        if test_mode:
            response = TEST_RESPONSE
            content_type = response.get("ContentType", "")
            size = response.get("ContentLength", 0)
        else:
            # S3 객체 메타데이터 조회
            response = s3.head_object(Bucket=bucket, Key=key)
            content_type = response.get("ContentType", "")
            size = response.get("ContentLength", 0)

        # 1. 확장자 필터링 (30 점)
        if is_suspicious_extension(ext):
            reasons.append("Suspicious extension")
            total_weight += 30
            

        # 2. MIME 불일치 검사 (50 점)
        if is_mismatched_mime(ext, content_type):
            reasons.append("MIME type mismatch")
            total_weight += 50

        # 3. 파일 크기 검사 (30 점)
        if is_suspicious_size(ext, size):
            reasons.append("Abnormal file size")
            total_weight += 30

        status = "malicious" if total_weight >= 50 else "suspicious" if total_weight >= 30 else "clear"
        return {
            "status": status,
            "reasons": reasons,
            "ext": ext,
            "content_type": content_type,
            "size": size,
            "weight": total_weight
        }

    except Exception as e:
        return {
            "error": str(e)
        }