# dashboard/app.py

from flask import Flask, render_template
import pandas as pd
import os

app = Flask(__name__)

@app.route('/')
def index():
    if os.path.exists('alerts/anomalies.csv'):
        df = pd.read_csv('alerts/anomalies.csv')
        alerts = df.to_dict(orient='records')
    else:
        alerts = []
    return render_template('index.html', alerts=alerts)

if __name__ == '__main__':
    app.run(debug=True)
