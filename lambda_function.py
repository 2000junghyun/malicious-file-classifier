from utils.ti_checker import check_file_hash_in_ti
from utils.static_analyzer.metadata_classifier import classify_static_metadata
from utils.content_signature_checker import check_content_signature

def lambda_handler(event, context=None):
    try:
        bucket = event["detail"]["requestParameters"]["bucketName"]
        key = event["detail"]["requestParameters"]["key"]
        print(f"[+] Processing file: {bucket}/{key}")

        # 1. TI comparison
        print(f"[+] Start TI check")
        ti_result = ti_checker_handler(bucket, key)
        print(f"[+] TI analysis result: {ti_result}\n")

        # 2. Metadata analysis
        print(f"[+] Start metadata analysis")
        static_result = static_classifier_handler(bucket, key)
        print(f"[+] Metadata analysis result: {static_result}\n")
        
        # 3. Content Signature analysis
        print(f"[+] Start content signature analysis")
        signature_result = content_signature_checker_handler(bucket, key)
        print(f"[+] Content signature analysis result: {signature_result}\n")

        # 4. Similarity analysis

        # 5. AI bases analysis


        # 최종 파일 검사 통과
        if ti_result == "clear" and static_result == "clear" and signature_result == "clear":
            print(f"[+] File is safe: {key}")

    except KeyError as e:
        print(f"[!] Missing expected key in event: {e}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")


def ti_checker_handler(bucket, key):
    result = check_file_hash_in_ti(bucket, key)

    if result["status"] == "error":
        print("[!] Error during TI analysis:", result["error"])
        print("[TODO] Invoke log_handler(event)")
        return result["status"]

    if result["status"] == "malicious":
        print("[!] TI analysis flagged the file")
        print(f"[!] source: {result['source']}, sha256: {result['sha256']}")
        print("[TODO] Invoke threat_handler(event)")
        print("[TODO] Invoke alert_handler(event)")
        return result["status"]

    else:
        print("[+] File passed the TI analysis")
        return result["status"]


def static_classifier_handler(bucket, key):
    result = classify_static_metadata(bucket, key)

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


def content_signature_checker_handler(bucket, key):
    result = check_content_signature(bucket, key)

    if result["status"] == "error":
        print("[!] Error during content signature analysis:", result["error"])
        print("[TODO] Invoke log_handler(event)")
        return result["status"]

    if result["status"] == "malicious":
        print(f"[!] Content signature analysis flagged the file: ext: {result['ext']}, matches: {result['matches']}")
        print("[TODO] Invoke threat_handler(event)")
        print("[TODO] Invoke alert_handler(event)")
        return result["status"]
    
    elif result["status"] == "suspicious":
        print(f"[!] Content signature analysis flagged the file: ext: {result['ext']}, matches: {result['matches']}")
        print("[TODO] Invoke alert_handler(event)")
        return result["status"]
    
    else:
        print("[+] File passed the content signature analysis")
        return result["status"]