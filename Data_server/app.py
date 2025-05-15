import requests
import time

from dataclasses import dataclass
from flask import Flask, request, jsonify
from flask_cors import CORS


@dataclass
class EncryptedData:
    file_name: str
    key: str
    file: str


app = Flask(__name__)
CORS(app)

# morse code per device
files = {}
KMS_BASE_URL = "http://localhost:5000/api/verify"


def verify_device(uuid, token):
    if not uuid or not token:
        return False
    try:
        response = requests.post(KMS_BASE_URL, json={"uuid": uuid, "token": token})
        return response.status_code == 200
    except Exception as e:
        app.logger.info(f"Error verifying device: {e}")
        return False


@app.route("/morsecode", methods=["POST"])
def set_morse():
    data = request.get_json()
    file_name = data.get("file_name")
    uuid = data.get("uuid")
    uuids = data.get("uuids")
    keys = data.get("keys")
    token = data.get("token")
    code = data.get("code")

    if not verify_device(uuid, token):
        return "Unauthorized device", 403
    if not file_name or not uuids or not keys or not code:
        return "Missing parameters", 400
    for i in range(len(uuids)):
        if uuids[i] not in files:
            files[uuids[i]] = []
        files[uuids[i]].append(EncryptedData(file_name, keys[i], code))
    app.logger.info(f"UUID: {uuid}, UUIDS:{uuids},\n Keys: {keys}, Code: {code}")

    return "OK", 200


@app.route("/morsecode/get", methods=["POST"])
def get_morse():
    data = request.get_json()
    uuid = data.get("uuid")
    token = data.get("token")
    name = data.get("file_name")
    app.logger.info(f"UUID: {uuid}, Token: {token}")
    if not verify_device(uuid, token):
        return "Unauthorized device", 403

    if not name:
        return "File name not provided", 400
    target = next(x for x in files[uuid] if x.file_name == name)

    return jsonify({"encryptedKey": target.key, "encryptedFile": target.file})


@app.route("/getList", methods=["POST"])
def get_list():
    data = request.get_json()
    uuid = data.get("uuid")
    app.logger.info(f"UUID: {uuid}")
    app.logger.info(f"Files: {files}")
    return jsonify({"files": [i.file_name for i in files[uuid]]})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)


@app.route("/")
def home():
    return "IoT Registration Server Running"
