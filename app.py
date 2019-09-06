from flask import Flask, render_template, request
import requests
import os

app = Flask(__name__)

VIRUS_TOTAL_API_KEY = os.environ['VIRUS_TOTAL_API_KEY']

@app.route('/')
def dashboard(url_data=None, url_color="#ffffff", file_data=None, file_color="#ffffff"):
    return render_template('index.html', url_data=url_data, url_color=url_color, file_data=file_data, file_color=file_color)

def result_color(positive_results, total_results):
    if positive_results == 0:
        return "#2fa350"
    elif positive_results < 3:
        return "#f5ea95"
    else:
        return "#a61b0c"

@app.route('/virustotal/url', methods=['POST'])
def virus_total_url():
    text = request.form['text']
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': VIRUS_TOTAL_API_KEY, 'resource': text.upper()}
    response = requests.get(url, params=params)

    # Validate API returned 200 status
    if response.status_code != 200:
        return dashboard(url_data=f'API returned error code: {response.status_code}')

    # If no data was found for the provided resource, the "positives" and "total" fields will not
    # be available. Instead, print the "verbose_msg" field
    content = response.json()
    if 'positives' not in content.keys() or 'total' not in content.keys():
        return dashboard(url_data=f"{text}: {content['verbose_msg']}")

    total_found = response.json()['positives']
    engines_tested=response.json()['total']
    safe_url = text.replace('.', '{.}')

    url_data = f'{safe_url}: found {total_found} positive results on {engines_tested} engines'
    return dashboard(url_data=url_data, url_color=result_color(total_found, engines_tested))

@app.route('/virustotal/file', methods=['POST'])
def virus_total_file():
    file_hash = request.form['text']
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    assert VIRUS_TOTAL_API_KEY is not None
    params = {'apikey': VIRUS_TOTAL_API_KEY, 'resource': file_hash}
    response = requests.get(url, params=params)

    # Validate API returned 200 status
    if response.status_code != 200:
        return dashboard(file_data=f'API returned error code: {response.status_code}')

    # If no data was found for the provided resource, the "positives" and "total" fields will not
    # be available. Instead, print the "verbose_msg" field
    content = response.json()
    if 'positives' not in content.keys() or 'total' not in content.keys():
        return dashboard(url_data=f"{text}: {content['verbose_msg']}")

    total_found = response.json()['positives']
    engines_tested=response.json()['total']

    file_data = f'{file_hash}: found {total_found} positive results on {engines_tested} engines'
    return dashboard(file_data=file_data, file_color=result_color(total_found, engines_tested))
