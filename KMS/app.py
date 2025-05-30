import time
import base64

from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

app = Flask(__name__)
CORS(app)


public_keys = {}
private_keys = {}

uuids = set()
passphrases = {}

valid_token = set()


@app.route("/api/registration", methods=["POST"])
def register():
    app.logger.info(f"Request: {request.data}")
    request_data = request.get_json()
    if not request_data:
        return jsonify({"error": "Invalid input"}), 400
    uuid = request_data.get("uuid")
    passphrase = request_data.get("passphrase")

    if not uuid or not passphrase:
        return jsonify({"error": "Missing uuid or passphrase"}), 400

    if uuid in uuids:
        return jsonify({"error": "UUID already exists"}), 400

    uuids.add(uuid)
    passphrases[uuid] = passphrase

    key = RSA.generate(1024, e=65537)

    tmp_n = key.n
    tmp_e = key.e
    tmp_d = key.d

    hex_n = hex(tmp_n)[2:]
    hex_e = hex(tmp_e)[2:]
    hex_d = hex(tmp_d)[2:]

    public_keys[uuid] = (hex_n, hex_e)
    private_keys[uuid] = (hex_n, hex_d)
    app.logger.info(f"UUID: {uuid}, Public Key: (n: {hex_n}, e: {hex_e})")
    return jsonify({"n": hex_n, "e": hex_e})


@app.route("/api/verify", methods=["POST"])
def verify():
    request_data = request.get_json()
    if not request_data:
        return 400
    uuid = request_data.get("uuid")
    token = request_data.get("token")

    if not uuid or not token:
        return "", 400

    if uuid not in uuids:
        return "", 404

    if (uuid, token) not in valid_token:
        return "", 403

    app.logger.info(f"UUID: {uuid}, Token: {token} is valid")
    return "", 200


@app.route("/api/token", methods=["POST"])
def get_token():
    app.logger.info(f"Request: {request.data}")
    request_data = request.get_json()
    if not request_data:
        return "", 400
    uuid = request_data.get("uuid")
    passphrase = request_data.get("passphrase")

    if not uuid or not passphrase:
        return jsonify({"error": "Missing uuid or passphrase"}), 400
    if uuid not in uuids:
        return jsonify({"error": "UUID not found"}), 404
    if passphrase != passphrases[uuid]:
        return jsonify({"error": "Invalid passphrase"}), 403

    token = SHA256.new((str(time.time()) + uuid + passphrase).encode()).hexdigest()
    valid_token.add((uuid, token))

    app.logger.info(f"UUID: {uuid}, Token: {token} generated")
    return jsonify({"token": token}), 200


@app.route("/api/decrypt", methods=["POST"])
def decrypt():
    request_data = request.get_json()
    if not request_data:
        return 400
    uuid = request_data.get("uuid")
    token = request_data.get("token")
    passphrase = request_data.get("passphrase")
    encrypted_key_base64: str = request_data.get("encryptedKey")

    if not uuid or not token or not passphrase or not encrypted_key_base64:
        return (
            jsonify({"error": "Missing uuid, token, passphrase or encryptedKey"}),
            400,
        )
    if uuid not in uuids:
        return jsonify({"error": "UUID not found"}), 404
    if (uuid, token) not in valid_token:
        return jsonify({"error": "Invalid token"}), 403
    if passphrase != passphrases[uuid]:
        return jsonify({"error": "Invalid passphrase"}), 403

    encrypted_key = base64.b64decode(encrypted_key_base64.encode())

    n_hex, d_hex = private_keys[uuid]
    n = int(n_hex, 16)
    d = int(d_hex, 16)

    decryptor = PKCS1_v1_5.new(RSA.construct((n, 65537, d)))
    decrypted_key_byte = decryptor.decrypt(encrypted_key, sentinel=object())

    decrypted_key = base64.b64encode(decrypted_key_byte).decode("utf-8")
    app.logger.info(f"decryptedKey: {decrypted_key}")
    valid_token.remove((uuid, token))
    app.logger.info(f"UUID: {uuid}, Token: {token} is used")
    return jsonify({"decryptedSenderKey": decrypted_key})


@app.route("/api/publicKey", methods=["POST"])
def get_public_key():
    request_data = request.get_json()
    if not request_data:
        return jsonify({"error": "Invalid input"}), 400
    queries = request_data.get("queries")

    if not queries:
        return jsonify({"error": "Missing uuid"}), 400

    ns = [public_keys[uuid][0] for uuid in queries if uuid in public_keys]
    es = [public_keys[uuid][1] for uuid in queries if uuid in public_keys]

    if len(ns) != len(queries):
        return jsonify({"error": "Some UUIDs not found"}), 404

    app.logger.info(f"UUIDs: {queries}, Public Keys: {ns, es}")
    return jsonify({"ns": ns, "es": es})


if __name__ == "__main__":
    app.run("0.0.0.0", debug=True)
