#FROM registry.access.redhat.com/ubi9/ubi-minimal
#RUN microdnf install -y python3 python3-devel redhat-rpm-config gcc libffi-devel openssl-devel cargo 
FROM docker.io/python:3.11-slim-bullseye 
WORKDIR /app
COPY ./requirements.txt /app/
RUN python3 -m pip install setuptools_rust
RUN python3 -m pip install -r /app/requirements.txt
RUN python3 -m pip uninstall pip -y
COPY *.py /app/
COPY test-assets /app/test-assets
# Create and set user
#RUN adduser -D trawler -u 1000
RUN adduser trawler -u 1000
RUN chown -R trawler:users /app
USER 1000
ENV APP_FILE=/app/trawler.py
CMD ["python3", "/app/trawler.py", "-c", "/app/config/config.yaml"]
