from flask import Flask, jsonify
from flask_cors import CORS
import boto3
import json
from mangum import Mangum

app = Flask(__name__)
CORS(app)

dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
TABLE = dynamodb.Table('cloud-posture-results')

def fetch(result_type):
    resp = TABLE.get_item(Key={'result_type': result_type})
    item = resp.get('Item', {})
    return json.loads(item.get('data', '[]'))

@app.route('/instances')
def instances():
    return jsonify(fetch('ec2_instances'))

@app.route('/buckets')
def buckets():
    return jsonify(fetch('s3_buckets'))

@app.route('/cis-results')
def cis_results():
    return jsonify(fetch('cis_results'))

handler = Mangum(app)

if __name__ == "__main__":
    app.run(debug=True, port=5000)