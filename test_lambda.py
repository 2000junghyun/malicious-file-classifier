import os
import json
from lambda_function import lambda_handler

# event.json 파일 로드
current_dir = os.path.dirname(os.path.abspath(__file__))
target_path = os.path.join(current_dir, "test_files", "event.json")

with open(target_path, "r", encoding="utf-8") as f:
    TEST_EVENT = json.load(f)

lambda_handler(TEST_EVENT)