from flask import Flask, render_template, jsonify
import detectors

app = Flask(__name__)

@app.route("/")

def dashboard():
    return render_template("dash.html")

@app.route("/api/alerts")

def api_alert():
    with detectors.alert_lock:
        return jsonify(list(detectors.alerts))

if __name__ == "__main__":
    detectors.start_background()
    app.run(debug=True, use_reloader=False)