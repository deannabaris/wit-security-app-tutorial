Security Dashboard
==================

This is a tutorial for a dashboard of security utilities built using Python's Flask webserver framework. It uses the VirusTotal API as the basis for a single security resource page. 

### Installing Python3 & Flask

#### Python3

Windows Installation Instructions: https://docs.python.org/3/using/windows.html

OS X (Mac) Installation Instructions: https://docs.python-guide.org/starting/install3/osx/

Alternatively, the latest version of Python3 is available for download here: https://www.python.org/downloads/

#### Flask

Flask is a Python library that can be installed using Python's built-in package manager, pip. Once Python3 is installed, Flask can be installed by running the following command:

```pip3 install flask```

### API Keys

An API key works as an authentication mechanism for querying external APIs. They are used to track API use and prevent malicious users from abusing APIs.

To get an API key with Virus Total, create a free account here: https://www.virustotal.com/gui/join-us. Once you have an account, log on and click your name in the top right corner of the screen to reveal a drop down menu, then select "API key". On the API Key page, copy the key to the clipboard. 

Including hardcoded API keys in your code is bad practice, so we're going to use environment variables to avoid unnecessary information disclosure. Open up Terminal/Command Prompt, and add the following line to the bottom of the file `~/.bash_profile`, substituting <API_KEY> with the value of the actual copied API key. 

```export VIRUS_TOTAL_API_KEY=<API_KEY>```

The `~/.bash_profile` file is loaded with each new Terminal session, so adding this line to the file will automatically set `VIRUS_TOTAL_API_KEY` as an environment variable for all future sessions.  To add the variable for your current session, run the following command: 

```source ~/.bash_profile```


### To Run the App
```
> cd wit-security-app-tutorial
> export FLASK_APP=app.py
> flask run
```

Open your browser to http://localhost:5000 to see the site HTML

Useful `flask run` options:

* Run over HTTP (make sure you use the HTTPS version of the url: https://localhost:5000): `flask run --cert <cert> --key <key>` 
  * Generate self-signed certificate: ```openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem```
* Run externally accessible application: `flask run --host 0.0.0.0`
* Use a port other than 5000: `flask run --port <port>`


### Additional Resources
* Presentation slide deck:
* Flask documentation: https://flask.palletsprojects.com/en/1.1.x/ 
