from flask import Flask, render_template, request
import requests
import os

app = Flask(__name__)

@app.route('/')
def dashboard(data=None):
    return render_template('index.html', data=data)

@app.route('/', methods=['POST'])
def virus_total_form_post():
    text = request.form['text']
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': os.environ['VIRUS_TOTAL_API_KEY'], 'resource': text.upper()}
    response = requests.get(url, params=params)

    # Validate API returned 200 status
    if response.status_code != 200:
        return dashboard(data=f"API returned error code: {response.status_code}")

    # If no data was found for the provided resource, the "positives" and "total" fields will not
    # be available. Instead, print the "verbose_msg" field
    content = response.json()
    if 'positives' not in content.keys() or 'total' not in content.keys():
        return dashboard(data=f"{text}: {content['verbose_msg']}")

    total_found = response.json()['positives']
    engines_tested=response.json()['total']
    safe_url = text.replace('.', '{.}')
    return dashboard(data=f"{safe_url}: found {total_found} positive results on {engines_tested} engines")
