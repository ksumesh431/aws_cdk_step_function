import json
import requests

def lambda_handler(event, context):
    # Example: Make a GET request to a public API
    response = requests.get('https://api.github.com')
    data = response.json()
    return {
        'statusCode': 200,
        'body': json.dumps(data)
    }