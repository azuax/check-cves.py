# check_cves.py

Simple utility for searching in NIST database for vulnerabilities related to services.

## Installation
1. Clone the repository and access the folder's repository.

2. Create a virtual environment.
```bash
python3 -m venv .venv
```

3. Activate the virtual environment.
```bash
source .venv/bin/activate
```

4. Install dependencies
```bash
pip install -r requirements.txt
```

## Usage
```python
python check-cves.py -i <input_file.csv> [-o <output_folder>] [-v]
```

## Input Format
The input is a CSV like the example
```csv
ip,port,service
192.168.1.1,80,Apache 2.4.29
192.168.1.2,22,OpenSSH 7.4
192.168.1.3,443,nginx 1.14.0
```

## Output results
### Output folder
The results are stored as JSON in files inside a folder as:
out
|--192.168.1.1.json
|--192.168.1.2.json
|--192.168.1.3.json

### Output files
The JSON format is like:
```json
[
    {
        "ip": "192.168.1.1",
        "port": 80,
        "service": "Apache 2.4.29",
        "cve_id": "CVE-2017-15710",
        "description": "In Apache httpd 2.0.23 to 2.0.65, 2.2.0 to 2.2.34, and 2.4.0 to 2.4.29, mod_authnz_ldap, if configured with AuthLDAPCharsetConfig, uses the Accept-Language header value to lookup the right charset encoding when verifying the user's credentials. If the header value is not present in the charset conversion table, a fallback mechanism is used to truncate it to a two characters value to allow a quick retry (for example, 'en-US' is truncated to 'en'). A header value of less than two characters forces an out of bound write of one NUL byte to a memory location that is not part of the string. In the worst case, quite unlikely, the process would crash which could be used as a Denial of Service attack. In the more likely case, this memory is already reserved for future use and the issue has no effect at all."
    },
    {
        "ip": "192.168.1.1",
        "port": 80,
        "service": "Apache 2.4.29",
        "cve_id": "CVE-2017-15715",
        "description": "In Apache httpd 2.4.0 to 2.4.29, the expression specified in <FilesMatch> could match '$' to a newline character in a malicious filename, rather than matching only the end of the filename. This could be exploited in environments where uploads of some files are are externally blocked, but only by matching the trailing portion of the filename."
    },
    {
        "ip": "192.168.1.1",
        "port": 80,
        "service": "Apache 2.4.29",
        "cve_id": "CVE-2018-1283",
        "description": "In Apache httpd 2.4.0 to 2.4.29, when mod_session is configured to forward its session data to CGI applications (SessionEnv on, not the default), a remote user may influence their content by using a \"Session\" header. This comes from the \"HTTP_SESSION\" variable name used by mod_session to forward its data to CGIs, since the prefix \"HTTP_\" is also used by the Apache HTTP Server to pass HTTP header fields, per CGI specifications."
    },
    {
        "ip": "192.168.1.1",
        "port": 80,
        "service": "Apache 2.4.29",
        "cve_id": "CVE-2018-1312",
        "description": "In Apache httpd 2.2.0 to 2.4.29, when generating an HTTP Digest authentication challenge, the nonce sent to prevent reply attacks was not correctly generated using a pseudo-random seed. In a cluster of servers using a common Digest authentication configuration, HTTP requests could be replayed across servers by an attacker without detection."
    }
]
```