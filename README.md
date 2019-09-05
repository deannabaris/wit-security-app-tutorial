Security Dashboard
==================

Tufts WIT Conference 2019 Flask tutorial

### Virus Total API Key

An API key works as an authentication mechanism to query external APIs. To get an API key with Virus Total, create a free account here: https://www.virustotal.com/gui/join-us. Once you have an account, log on and click your name in the top right corner of the screen to reveal a drop down menu, then select "API key". On the API Key page, copy the key to the clipboard. 

Including hardcoded API keys in your code is bad practice, so we're going to use environment variables to avoid unnecessary information disclosure. Open up Terminal/Command Prompt, and add the following line to the bottom of your ~/.bash_profile, substituting <API_KEY> with your actual copied API key. 

```export VIRUS_TOTAL_API_KEY=<API_KEY```

The ~/.bash_profile file is loaded with each new Terminal session, so adding this line to the file will automatically set VIRUS_TOTAL_API_KEY as an environment variable for all future sessions.  To add the variable for your current session, run the following command: 

```source ~/.bash_profile```


### To Run the App
```
> cd wit-security-app-tutorial
> export FLASK_APP=app.py
> flask run
```

Open your browser to http://localhost:5000 to see the site HTML

### Additional Resources
* Presentation slide deck:
* Flask documentation: https://flask.palletsprojects.com/en/1.1.x/ 
