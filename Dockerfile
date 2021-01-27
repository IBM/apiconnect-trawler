FROM alpine:3.12
RUN apk update && apk add python3 py3-pip
COPY requirements.txt /tmp
RUN pip3 install -r /tmp/requirements.txt
COPY *.py /app/
COPY test-assets /app/test-assets
RUN adduser -D trawler -u 1000
USER 1000
WORKDIR "/app"
CMD /app/trawler.py --config /app/config/config.yaml
