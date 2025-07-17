import hashlib
import requests
import boto3
import os
from dotenv import load_dotenv

# .env 파일 로드
load_dotenv()

# 환경 변수
VT_API_KEY = os.getenv("VT_API_KEY")
HY_API_KEY = os.getenv("HY_API_KEY")

s3 = boto3.client('s3')


def ti_checker_handler(bucket, key):
    result = check_file_hash_in_ti(bucket, key)

    if result["status"] == "error":
        print("[!] Error during TI analysis:", result["error"])
        print("[TODO] Invoke log_handler(event)")
        return result["status"]

    if result["status"] == "malicious":
        print(f"[!] TI analysis flagged the file: source={result['source']}, sha256={result['sha256']}")
        print("[TODO] Invoke threat_handler(event)")
        print("[TODO] Invoke alert_handler(event)")
        return result["status"]

    else:
        print("[+] File passed the TI analysis")
        return result["status"]


def check_file_hash_in_ti(bucket: str, key: str, test_mode: bool = True) -> dict:
    try:
        if test_mode:
            sha256 = '0123456789aaa34d2d20bc74b3b2c10a185a9f8d1584015aecacaa0123456789' # false
            # sha256 = 'eca60a139afa34d2d20bc74b3b2c10ea185a9f8d1584015aecac4ee8ad89200a' # true VY
            # sha256 = '77a2edc850a4dbe94ad33f2ed194a1125d912e09d0f999b98d6c5994c2c59a02' # true HA
        else:
            # 실제 S3 객체에서 SHA256 계산
            response = s3.get_object(Bucket=bucket, Key=key)
            file_bytes = response['Body'].read()
            sha256 = hashlib.sha256(file_bytes).hexdigest()

        # VirusTotal 조회
        vt_result = check_virustotal(sha256)

        if vt_result.get("error"):
            return {"error": vt_result["error"]}

        if vt_result["status"] == "malicious":
            return {
                "status": vt_result["status"],
                "sha256": sha256,
                "source": "VirusTotal"
            }
        
        # Fallback: Hybrid Analysis 조회
        ha_result = check_hybrid_analysis(sha256)

        if ha_result.get("error"):
            return {"error": ha_result["error"]}

        if ha_result["status"] == "malicious":
            return {
                "status": ha_result["status"],
                "sha256": sha256,
                "source": "Hybrid Analysis"
            }
        
        # Hash 검사 통과
        return {
            "status": ha_result["status"],
            "sha256": sha256
        }

    except Exception as e:
        return {"error": str(e)}


def check_virustotal(sha256: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(url, headers=headers)

    if r.status_code == 200:
        data = r.json()
        mal_count = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        if mal_count > 0:
            return {"status": "malicious"}
        else:
            return {"status": "clear"}
        
    elif r.status_code == 404:
        return {"status": "clear"}
    
    else:
        return {"error": f"VirusTotal error: {r.status_code}, sha256: {sha256}"}
  
  
def check_hybrid_analysis(sha256: str) -> dict:
    url = f"https://www.hybrid-analysis.com/api/v2/search/hash?hash={sha256}"
    headers = {
        "api-key": HY_API_KEY,
        "User-Agent": "FalconSandbox"
    }
    r = requests.get(url, headers=headers)

    if r.status_code == 200:
        data = r.json()
        if len(data) > 0:
            return {"status": "malicious"}
        else:
            return {"status": "clear"}

    elif r.status_code == 400:
        return {"status": "clear"}
    
    elif r.status_code == 404:
        return {"status": "clear"}
    
    else:
        return {"error": f"HybridAnalysis error: {r.status_code}, sha256: {sha256}"}