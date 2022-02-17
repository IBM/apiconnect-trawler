FROM registry.access.redhat.com/ubi8/ubi-minimal
RUN microdnf install -y python3 python3-devel redhat-rpm-config gcc libffi-devel openssl-devel cargo 
WORKDIR /app
COPY ./requirements.txt ./app ./
RUN python3 -m pip install setuptools_rust
RUN python3 -m pip install -r /app/requirements.txt
COPY *.py /app/
COPY test-assets /app/test-assets
USER 1000
ENV APP_FILE=/app/trawler.py
CMD ["python3", "/app/trawler.py", "-c", "/app/config/config.yaml"]
