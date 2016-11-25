FROM alpine
MAINTAINER Francesco Tornieri

RUN apk update && \
    apk add git python python-dev py-pip build-base tcpdump && \
    pip install pycrypto 
 
RUN git clone https://github.com/secdev/scapy/ && \
    cd scapy && \
    python setup.py install

COPY synscan.py /

CMD ["python","./synscan.py"]
