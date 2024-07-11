# Web Application Firewall Simulation 
## Overview
This project demonstrates a Web Application Firewall (WAF) simulation using Flask and a vulnerability checker for CVE-2017-5638. The WAF middleware blocks HTTP requests containing specific patterns, and the vulnerability checker tests for and exploits the Apache Struts 2 vulnerability (CVE-2017-5638).

## Components
server.py: This Flask-based web server includes a WAF middleware that blocks HTTP requests containing potentially malicious patterns.
vulnerable.py: This script checks for the CVE-2017-5638 vulnerability and can execute arbitrary commands if the target is vulnerable.
## server.py
The server.py script sets up a Flask web server with a WAF middleware that inspects incoming requests for specific malicious patterns. If a blocked pattern is detected, the request is denied with a 403 Forbidden response.

## Usage
Install Flask:
pip install flask
Run the server:
python server.py
Access the server at http://127.0.0.1:5000/.

## vulnerable.py
The vulnerable.py script checks if a given URL is vulnerable to CVE-2017-5638 and can execute commands on the vulnerable server.

## Usage
Install the required libraries:

pip install requests
Check if a URL is vulnerable:

python vulnerable.py --url http://example.com --check
Execute a command on a vulnerable URL:

python vulnerable.py --url http://example.com -c "whoami"

## Notes
The server.py script serves as a basic demonstration of a WAF using Flask. In a real-world scenario, more advanced techniques and patterns should be employed.
