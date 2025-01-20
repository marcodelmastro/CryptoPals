from flask import Flask, request, jsonify
import time
import hmac
import hashlib

app = Flask(__name__)

# Secret key for HMAC
SECRET_KEY = b'supersecretkey'

# Function to perform insecure comparison with a timing leak
def insecure_compare(provided_sig, valid_sig):
    if len(provided_sig) != len(valid_sig):
        return False

    for x, y in zip(provided_sig, valid_sig):
        if x != y:
            return False
        time.sleep(0.005)  # Artificial delay to simulate timing vulnerability
    return True

# Endpoint for testing the file and signature
@app.route('/test', methods=['GET'])
def test_signature():
    file = request.args.get('file', '')
    provided_signature = request.args.get('signature', '')

    # Compute the valid HMAC signature
    valid_signature = hmac.new(SECRET_KEY, file.encode(), hashlib.sha1).hexdigest()

    # Perform insecure comparison
    if insecure_compare(provided_signature, valid_signature):
        return jsonify({'status': 'Valid signature'}), 200
    else:
        return jsonify({'status': 'Invalid signature'}), 403

# Endpoint to output the correct signature for debugging purposes
@app.route('/get_signature', methods=['GET'])
def get_signature():
    file = request.args.get('file', '')
    valid_signature = hmac.new(SECRET_KEY, file.encode(), hashlib.sha1).hexdigest()
    return jsonify({'file': file, 'correct_signature': valid_signature}), 200

if __name__ == '__main__':
    app.run(host='localhost', port=9001)
