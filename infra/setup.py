import boto3

def create_table():
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.create_table(
        TableName='cloud-posture-results',
        KeySchema=[{'AttributeName': 'result_type', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'result_type', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST'
    )
    table.wait_until_exists()
    print("✅ DynamoDB table created!")

if __name__ == "__main__":
    create_table()