from flask import Flask, jsonify, redirect, render_template, request, url_for, session
from flask_socketio import SocketIO, emit
from dotenv import load_dotenv
from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel, ValidationError, model_validator
import os
import sys
import uuid as Uuid
import cachetools
load_dotenv()

app = Flask(__name__)
socketio = SocketIO(app, path="ws", async_mode="eventlet", cors_allowed_origins="*")
uuid_store = cachetools.TTLCache(maxsize=128, ttl=30 * 60)
user_sessions = {}

class UUIDData(BaseModel):
	host_name: str
	host_icon_url: str
	user_name: str
	user_avatar_url: str
	user_id: int

	@model_validator(mode="before")
	@classmethod
	def decrypt_fields(cls, data):
		if isinstance(data, dict):
			decrypted = {}
			for k, v in data.items():
				try:
					decrypted[k] = fernet.decrypt(str(v))
				except InvalidToken:
					raise ValueError(f"Field '{k}' is not encrypted, or encryption is invalid")
			return decrypted
		return data

try:
	app.secret_key = os.environ["APP_SECRET"]
	fernet = Fernet(os.environ["ID_ENC_KEY"])
	token_secret = os.environ["TOKEN_SECRET"]
except KeyError:
	print("APP_SECRET, ID_ENC_KEY or TOKEN_SECRET not found. Exiting...")
	sys.exit(0)

@app.route("/", endpoint="index")
def index():
	return "This is the D2WT API home page."

@app.route("/uuid", methods=["POST"])
def uuid_func():
	try:
		json = request.json
		if not json:
			return jsonify({"status": 400, "message": "No data presented."})
		
		data = UUIDData.model_validate(json)
	except ValidationError as e:
		not_found = [dt for dt in e.errors() if dt["type"] == "missing"]
		if len(not_found) > 0:
			return jsonify({"status": 400, "message": f"The following field(s) were not found: {", ".join([", ".join(str([i for i in dt["loc"]])) for dt in not_found])}"}), 400
		else:
			return jsonify({"status": 400, "message": f"Malformed data."}), 400
	
	if (1420070400000 > data.user_id):
		return jsonify({"status": 400, "message": "Invalid user ID."}), 400

	gen = Uuid.uuid4()	
	uuid_store[gen] = data

	return jsonify({"status": 200, "uuid": gen}), 200

@socketio.on("connect")
def handle_connect(auth):
	uuid = auth.get("uuid")
	if not uuid:
		return False

	if uuid not in uuid_store:
		return False

	user_sessions[uuid] = request.sid # type: ignore

@socketio.on("disconnect")
def handle_disconnect():
    for user_id, sid in list(user_sessions.items()):
        if sid == request.sid: # type: ignore
            del user_sessions[user_id]
            print(f"User {user_id} disconnected")
            break

@app.route("/callback", methods=["GET"])
def callback():
	if not (code := request.args.get("code")) or not (uuid := request.args.get("state")):
		return jsonify({"status": 400, "message": "Code or state not present."}), 400

	sid = user_sessions.get(uuid)
	if not sid:
		return jsonify({"status": 404, "message": "Session not found."}), 404 

	data = uuid_store.get(uuid)
	if not data:
		return jsonify({"status": 404, "message": "Malformed data."}), 404 

	emit("callback", {"code": code}, to=sid, namespace="/")
	session["data"] = data
	return redirect(url_for("/authorized"))

@app.route("/authorized", methods=["GET"])
def authorized():
	if "data" not in session:
		return jsonify({"status": 401, "message": "Unauthorized."}), 401

	data = session.pop("data")
	if not data:
		return jsonify({"status": 404, "message": "Session data not found."}), 404

	return render_template(
		"authorized.html",
		host_name=data.host_name,
		user_name=data.user_name,
		user_avatar_url=data.user_avatar_url,
		host_icon_url=data.host_icon_url
	)

if __name__ == "__main__":
	socketio.run(app)