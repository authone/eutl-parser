# eutl-parser

A python application to parse EUTL (European Trust Lists) and extract qualified and unqualified service identities (digital certificates).
In also creates an XML index file of trust service providers

When implementing a qualified signatures validation service, one of the requirements is to take into consideration trust anchors defined by ETSI 119 612.
This application has three main purposes:

1. To download, validate the trust lists
2. To extract from each trust list the trust anchors represented by X509Certificates and save them on disk
3. To introduce a layer of abstraction between EUTL format and validation service, such that to protect
   the implemented Validation Service from possible future changes in list format (e.g. v6)

The author encourages developer to participate in the implementation of this application, to add other necessary missing features.
the participation if free, for the benefit of everyone else.

# ETSI Standards:

ts_119612

# EU Regulation

- Document 52019XC0816(01): https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2019.276.01.0001.01.ENG

# Installation:

All application dependencies are freezed in requirements.txt. Do not forget to run

`pip install -r requirements.txt`

# Running

Application is intended to run with python3. Use your favorite python interpreter, but CPython is the one recommended.

You can run the application using command `python3 .` in the application directory.

Check application command line parameters with `python3 . -h`

# Build and run as a Docker container

Build the image:

`docker build -t eutl-parser .`

Run the container:

`docker run -v $PWD/certificates:/tmp/download eutl-parser --workingdir /tmp/download`

In order to have easy access to the downloaded digital certificates you have to map a local folder inside the container using `-v local_path:container_path`. ***Container_path*** is the path where eutl_parser application downloads all the certificates. This is specified using `--workdir` argument when you run the container.

# Changelog

v1.0.3
Added Service Information Extensions as an attribute sie in trust_services.xml

v1.1.0
Implemented service history: it represents the previous service status at a specified moment of time. This is an optional separate section in the trust list for each service

v1.1.1
Added Service Digital Identity, also exported in trust_services.xml The SDI can be of 4 types: X509Certificate, X509SubjectName, X509SKI (key identifier), KeyValue (public key value)

v1.1.2
Refactory

v1.1.3
Added isqualified attribute to service history
