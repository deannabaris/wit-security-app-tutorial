Security Dashboard
==================

Source code for WIT Conference Flask tutorial. 

### Run the App
```$ cd security-app```

```$ export FLASK_APP=app.py```

```$ flask run```


### Virus Total API Key

An API key works as an authentication mechanism to query external APIs. To set up an API key with Virus Total, create a free account here: https://www.virustotal.com/gui/join-us. Once you have an account, log on and click your name in the top right corner of the screen to reveal a drop down menu. Select "API key". On the API Key page, copy the key to the clipboard. 

It's bad security practice to include API keys in code, so we're going to work a little magic with environment variables avoid hardcoding this information. Open up Terminal/Command Prompt, and add the following line to the bottom of your ~/.bash_profile, substituting <API_KEY> with your actual copied API key. 

```export VIRUS_TOTAL_API_KEY=<API_KEY```

The ~/.bash_profile file is reloaded with each new Terminal session, so adding this line to the file will automatically set the VIRUS_TOTAL_API_KEY as an environment variable for all future sessions.  To add the variable for your current session, run the following command: 

```source ~/.bash_profile```
