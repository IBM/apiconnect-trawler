FROM alpine:3.9
RUN apk update && apk add python3 py3-pip
COPY requirements.txt /tmp
RUN pip3 install -r /tmp/requirements.txt
COPY *.py /app/
COPY test-assets /app/test-assets
WORKDIR "/app"
CMD /app/trawler.py --config /app/config/config.yaml
