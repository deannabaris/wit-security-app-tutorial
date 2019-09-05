from flask import Flask, render_template, request
import requests
import os

app = Flask(__name__)

@app.route('/')
def hello_world(data=None):
    return render_template('index.html', data=data)

@app.route('/', methods=['POST'])
def virus_total_form_post():
    text = request.form['text']
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': os.environ['VIRUS_TOTAL_API_KEY'], 'resource': text.upper()}
    response = requests.get(url, params=params)

    total_found = response.json()['positives']
    engines_tested=response.json()['total']

    # Show all the metadata
    safe_url = text.replace('.', '{.}')
    return hello_world(data=f"{safe_url}: found {total_found} positive results on {engines_tested} engines")
