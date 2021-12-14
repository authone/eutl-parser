# eutl-parser

A python application to parse EUTL (European Trust Lists) and extract qualified and unqualified service identities (digital certificates).
In also creates an XML index file of trust service providers

# ETSI Standards:

# EU Regulation

- Document 52019XC0816(01): https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2019.276.01.0001.01.ENG

# Installation:

All application dependencies are freezed in requirements.txt. Do not forget to run

`pip install -r requirements.txt`

# Running

Application is intended to run with python3. Use your favorite python interpreter, but CPython is the one recommended.

You can run the application using command `python3 .` in the application directory.

Check application command line parameters with `python3 . -h`

# Changelog

v1.0.3
Added Service Information Extensions as an attribute sie in trust_services.xml

v1.1.0
Implemented service history: it represents the previous service status at a specified moment of time. This is an optional separate section in the trust list for each service

v1.1.1
Added Service Digital Identity, also exported in trust_services.xml The SDI can be of 4 types: X509Certificate, X509SubjectName, X509SKI (key identifier), KeyValue (public key value)
