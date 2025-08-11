from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO, emit
from dotenv import load_dotenv
from cryptography.fernet import Fernet, InvalidToken
from datetime import timedelta, datetime, timezone
import jwt
import os
import sys
load_dotenv()

app = Flask(__name__)
socketio = SocketIO(app)
user_sessions = {}

try:
	app.secret_key = os.environ["APP_SECRET"]
except KeyError:
	print("APP_SECRET not found. Exiting...")
	sys.exit(0)

try:
	fernet = Fernet(os.environ["ID_ENC_KEY"])
except KeyError:
	print("ID_ENC_KEY not found. Exiting...")
	sys.exit(0)

try:
	token_secret = os.environ["TOKEN_SECRET"]
except KeyError:
	print("TOKEN_SECRET not found. Exiting...")
	sys.exit(0)

@app.route("/", endpoint="index")
def index():
	return "This is the D2WT API home page."

@app.route("/token", methods=["GET"])
def tokenfunc():
	if not (user_id := request.args.get("uid")):
		return jsonify({"status": 400, "message": "User ID not present."})

	try:
		decrypted = fernet.decrypt(user_id.encode()).decode()
	except InvalidToken:
		return jsonify({"status": 401, "message": "Malformed token."}), 401

	try:
		decrypted = int(decrypted)
		if (1420070400000 > decrypted):
			raise ValueError()
	except (TypeError, ValueError):
		return jsonify({"status": 400, "message": "Malformed user ID."}), 400

	now = datetime.now(timezone.utc)
	token = jwt.encode({
		"user_id": decrypted,
		"exp": now + timedelta(minutes=30),
		"iat": now
	}, token_secret, algorithm="HS256")

	return jsonify({"status": 200, "token": token}), 200

@socketio.on("connect")
def handle_connect():
	token = request.args.get("token")
	if not token:
		return False

	try:
		data = jwt.decode(token, token_secret, algorithms=["HS256"])
		user_sessions[data["user_id"]] = request.sid
		print("User connected:", data["user_id"])

		emit("connected", {"user_id": data["user_id"]}, to=request.sid)
	except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
		return False 

@socketio.on("disconnect")
def handle_disconnect():
    for user_id, sid in list(user_sessions.items()):
        if sid == request.sid:
            del user_sessions[user_id]
            print(f"User {user_id} disconnected")
            break

@app.route("/callback", methods=["GET"])
def callback():
	if not (code := request.args.get("code")) or not (state := request.args.get("state")):
		return jsonify({"status": 400, "message": "Code or state not present."}), 400

	try:
		data = jwt.decode(state, token_secret, algorithms=["HS256"])
	except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
		return jsonify({"status": 400, "message": "Malformed state. Please re-authenticate."}), 400 

	sid = user_sessions[data["user_id"]]
	if not sid:
		return jsonify({"status": 404, "message": "Session not found."}), 404 

	emit("callback", {"code": code, "user_id": data["user_id"]}, to=sid)
	return render_template("./templates/authorized.html")

if __name__ == "__main__":
	socketio.run(app)