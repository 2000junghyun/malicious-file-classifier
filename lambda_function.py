from utils.ti_checker import ti_checker_handler
from utils.metadata_classifier import metadata_classifier_handler
from utils.content_signature_checker import content_signature_checker_handler
from utils.fuzzy_hash_analyzer import fuzzy_hash_handler

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
        static_result = metadata_classifier_handler(bucket, key)
        print(f"[+] Metadata analysis result: {static_result}\n")
        
        # 3. Content Signature analysis
        print(f"[+] Start content signature analysis")
        signature_result = content_signature_checker_handler(bucket, key)
        print(f"[+] Content signature analysis result: {signature_result}\n")

        # 4. Similarity analysis (Fuzzy Hash)
        print(f"[+] Start fuzzy hash analysis")
        fuzzy_hash_result = fuzzy_hash_handler(bucket, key)
        print(f"[+] Fuzzy hash analysis result: {fuzzy_hash_result}\n")

        # 5. Similarity analysis (ATS)

        # 6. AI bases analysis


        # 최종 파일 검사 통과
        if ti_result == "clear" and static_result == "clear" and signature_result == "clear" and fuzzy_hash_result == "clear":
            print(f"[+] File is safe: {key}")

    except KeyError as e:
        print(f"[!] Missing expected key in event: {e}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")