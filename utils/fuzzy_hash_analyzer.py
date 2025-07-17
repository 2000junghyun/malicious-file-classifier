import os
import csv
import tlsh
import boto3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def fuzzy_hash_handler(bucket, key):
    target_file = calculate_fuzzy_hash(bucket, key)
    if target_file["tlsh"]:
        result = fuzzy_hash_similarity_test(target_file["tlsh"], target_file["ext"])
    else:
        result = {"status": "error", "error": target_file["error"]}

    if result["status"] in ("error", "unknown"):
        print("[!] Error during fuzzy hash analysis:", result["error"])
        print("[TODO] Invoke log_handler(event)")
        return result["status"]

    if result["status"] == "malicious":
        print(f"[!] Fuzzy hash analysis flagged the file: TLSH minimum distance={result['min_distance']}")
        print("[TODO] Invoke threat_handler(event)")
        print("[TODO] Invoke alert_handler(event)")
        return result["status"]
    
    elif result["status"] == "suspicious":
        print(f"[!] Fuzzy hash analysis flagged the file: TLSH minimum distance={result['min_distance']}")
        print("[TODO] Invoke alert_handler(event)")
        return result["status"]
    
    else:
        print(f"[+] File passed the content signature analysis | TLSH minimum distance: {result['min_distance']}")
        return result["status"] # clear


# Calculate fuzzy hash
def calculate_fuzzy_hash(bucket, key, test_mode = True):    
    try:
        if test_mode:
            # 테스트 파일 로드
            file_path = os.path.join(os.path.dirname(__file__), "..", "test_files", "37fa8226afd30998dbb541e203e1b96a3ae586c80792cb390a336d91c2a4df5c.exe")
            with open(file_path, "rb") as f:
                file_data = f.read()
            file_ext = "exe"
        else:
            # S3 객체에서 파일 로드 (bucket, key 사용)
            s3 = boto3.client("s3")
            obj = s3.get_object(Bucket=bucket, Key=key)
            file_data = obj["Body"].read()
            file_ext = os.path.splitext(key)[1].lstrip(".").lower()

        # 타겟 파일 tlsh hash 계산
        fuzzy_hash = tlsh.hash(file_data)

        return {
            "tlsh": fuzzy_hash,
            "ext": file_ext
        }

    except Exception as e:
        return {
            "tlsh": None,
            "ext": None,
            "error": str(e)
        }


# Similarity test
def fuzzy_hash_similarity_test(tlsh_hash, ext):
    MALICIOUS_THRESHOLD = 50
    SUSPICIOUS_THRESHOLD = 100

    if not ext:
        return {"status": "error", "error": "File extension is missing"}


    try:
        # fuzzy hash db 로드
        try:
            db_hashes = load_fuzzy_hash_db(ext)
        except FileNotFoundError as e:
            return {"status": "unknown", "error": str(e)}

        # 유사도 거리 측정
        distances = []
        for db_hash in db_hashes:
            try:
                distance = tlsh.diff(tlsh_hash, db_hash)
                distances.append(distance)
            except Exception:
                continue

        if not distances:
            return {"status": "unknown", "error": "No valid hashes to compare"}

        # 최소 거리 확인
        min_distance = min(distances)

        # 거리 기준으로 상태 판단
        if min_distance <= MALICIOUS_THRESHOLD:
            return {"status": "malicious", "min_distance": min_distance}
        elif min_distance <= SUSPICIOUS_THRESHOLD:
            return {"status": "suspicious", "min_distance": min_distance}
        else:
            return {"status": "clear", "min_distance": min_distance}

    except Exception as e:
        return {"status": "error", "error": str(e)}


# Load fuzzy hash db
def load_fuzzy_hash_db(ext):
    db_path = os.path.join(BASE_DIR, "..", "fuzzy_hash_db", f"{ext.lower()}_fuzzy_hash.csv")
    db_path = os.path.abspath(db_path)

    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Hash DB not found: {db_path}")

    hashes = []
    with open(db_path, newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            db_hash = row.get("tlsh_hash")
            if db_hash and len(db_hash) >= 70:
                hashes.append(db_hash)
    return hashes