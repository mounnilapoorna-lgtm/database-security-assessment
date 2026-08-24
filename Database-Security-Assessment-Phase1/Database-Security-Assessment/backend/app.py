from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

app.config["SECRET_KEY"] = "change-this-secret-key"

@app.route("/")
def home():
    return {
        "status": "success",
        "message": "Database Security Assessment Platform API is running"
    }

@app.route("/api/health")
def health():
    return {
        "status": "healthy",
        "application": "Database Security Assessment Platform"
    }

if __name__ == "__main__":
    app.run(debug=True)
