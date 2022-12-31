FROM python:3.9.10-bullseye

COPY . /tmp/eutl-parser

WORKDIR /tmp/eutl-parser

RUN pip install -r requirements.txt

ENTRYPOINT [ "/usr/local/bin/python3", "__main__.py" ]
