from flask import Flask

app = Flask(__name__)

@app.route("/health")
def health():
    return {"status": "ok"}

@app.route("/data")
def data():
    return {"data": [1, 2, 3]}

@app.route("/admin")
def admin():
    return {"admin": "panel", "password": "12345"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
