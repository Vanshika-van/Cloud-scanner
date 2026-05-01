import boto3
import json
from datetime import datetime

ec2 = boto3.client('ec2', region_name='us-east-1')
s3  = boto3.client('s3', region_name='us-east-1')
iam = boto3.client('iam', region_name='us-east-1')
cloudtrail = boto3.client('cloudtrail', region_name='us-east-1')
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')

TABLE_NAME = "cloud-posture-results"

def get_ec2_instances():
    instances = []
    response = ec2.describe_instances()
    for reservation in response['Reservations']:
        for inst in reservation['Instances']:
            instances.append({
                'instance_id': inst['InstanceId'],
                'instance_type': inst['InstanceType'],
                'region': 'us-east-1',
                'public_ip': inst.get('PublicIpAddress', 'N/A'),
                'security_groups': [sg['GroupId'] for sg in inst.get('SecurityGroups', [])],
                'state': inst['State']['Name']
            })
    return instances

def get_s3_buckets():
    buckets = []
    response = s3.list_buckets()
    for bucket in response['Buckets']:
        name = bucket['Name']

        loc = s3.get_bucket_location(Bucket=name)
        region = loc['LocationConstraint'] or 'us-east-1'

        try:
            s3.get_bucket_encryption(Bucket=name)
            encrypted = True
        except Exception:
            encrypted = False

        try:
            acl = s3.get_bucket_acl(Bucket=name)
            public = any(
                grant['Grantee'].get('URI', '') == 'http://acs.amazonaws.com/groups/global/AllUsers'
                for grant in acl['Grants']
            )
        except Exception:
            public = False

        buckets.append({
            'bucket_name': name,
            'region': region,
            'encrypted': encrypted,
            'access': 'public' if public else 'private'
        })
    return buckets

def check_no_public_s3(buckets):
    failed = [b['bucket_name'] for b in buckets if b['access'] == 'public']
    return {
        'check_id': 'CIS-2.1.5',
        'name': 'No S3 buckets publicly accessible',
        'status': 'PASS' if not failed else 'FAIL',
        'evidence': f"Public buckets: {failed}" if failed else "All buckets are private"
    }

def check_s3_encryption(buckets):
    unencrypted = [b['bucket_name'] for b in buckets if not b['encrypted']]
    return {
        'check_id': 'CIS-2.1.1',
        'name': 'All S3 buckets encrypted',
        'status': 'PASS' if not unencrypted else 'FAIL',
        'evidence': f"Unencrypted: {unencrypted}" if unencrypted else "All buckets encrypted"
    }

def check_root_mfa():
    summary = iam.get_account_summary()['SummaryMap']
    mfa_enabled = summary.get('AccountMFAEnabled', 0) == 1
    return {
        'check_id': 'CIS-1.5',
        'name': 'Root account MFA enabled',
        'status': 'PASS' if mfa_enabled else 'FAIL',
        'evidence': 'Root MFA is enabled' if mfa_enabled else 'Root MFA is NOT enabled'
    }

def check_cloudtrail():
    trails = cloudtrail.describe_trails()['trailList']
    active = [t for t in trails if t.get('IsMultiRegionTrail')]
    return {
        'check_id': 'CIS-3.1',
        'name': 'CloudTrail is enabled (multi-region)',
        'status': 'PASS' if active else 'FAIL',
        'evidence': f"{len(active)} active multi-region trail(s)" if active else "No multi-region CloudTrail found"
    }

def check_no_ssh_open_to_world():
    sgs = ec2.describe_security_groups()['SecurityGroups']
    violations = []
    for sg in sgs:
        for perm in sg.get('IpPermissions', []):
            if perm.get('FromPort') in [22, 3389]:
                for r in perm.get('IpRanges', []):
                    if r['CidrIp'] == '0.0.0.0/0':
                        violations.append(sg['GroupId'])
    return {
        'check_id': 'CIS-5.2',
        'name': 'No SGs open SSH/RDP to 0.0.0.0/0',
        'status': 'PASS' if not violations else 'FAIL',
        'evidence': f"Violating SGs: {violations}" if violations else "No open SSH/RDP rules found"
    }

def store_results(data, result_type):
    table = dynamodb.Table(TABLE_NAME)
    table.put_item(Item={
        'result_type': result_type,
        'timestamp': datetime.utcnow().isoformat(),
        'data': json.dumps(data)
    })
    print(f"Stored {result_type} → DynamoDB")

def run_scanner():
    print("🔍 Discovering EC2 instances...")
    instances = get_ec2_instances()

    print("🔍 Discovering S3 buckets...")
    buckets = get_s3_buckets()

    print("✅ Running CIS checks...")
    cis_results = [
        check_no_public_s3(buckets),
        check_s3_encryption(buckets),
        check_root_mfa(),
        check_cloudtrail(),
        check_no_ssh_open_to_world()
    ]

    store_results(instances, 'ec2_instances')
    store_results(buckets, 's3_buckets')
    store_results(cis_results, 'cis_results')

    print("✅ Scan complete!")
    return instances, buckets, cis_results

if __name__ == "__main__":
    run_scanner()