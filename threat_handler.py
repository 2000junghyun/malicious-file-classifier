import json
import boto3
import os

# 환경 변수
NOTIFIER_LAMBDA = os.environ.get('NOTIFIER_LAMBDA_ARN')
LOGGER_LAMBDA = os.environ.get('LOGGER_LAMBDA_ARN')
RESPONSER_LAMBDA = os.environ.get('RESPONSER_LAMBDA_ARN') # Access Key 비활성화

lambda_client = boto3.client('lambda')

def threat_handler(event):
    payload = {
        "classifierSource": "Classifier_MassResourceCreation",
        "event": event
    }

    # Responser Lambda 호출
    lambda_client.invoke(
        FunctionName=RESPONSER_LAMBDA,
        InvocationType='Event',
        Payload=json.dumps(payload)
    )
    print("[OK] Responser lambda invoked")

    # Notifier Lambda 호출
    lambda_client.invoke(
        FunctionName=NOTIFIER_LAMBDA,
        InvocationType='Event',
        Payload=json.dumps(payload)
    )
    print("[OK] Notifier lambda invoked")

    # Logger Lambda 호출
    lambda_client.invoke(
        FunctionName=LOGGER_LAMBDA,
        InvocationType='Event',
        Payload=json.dumps(payload)
    )
    print("[OK] Logger lambda invoked")