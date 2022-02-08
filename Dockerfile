FROM alpine:latest AS build
workdir /app
RUN apk update && apk add python3 python3-dev py3-pip libffi libffi-dev musl-dev gcc  openssl-dev cargo
# Install Pipenv
RUN pip3 install --ignore-installed distlib pipenv
# Create a virtual environment and activate it
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" VIRTUAL_ENV="/opt/venv"

# Install dependencies into the virtual environment with Pipenv
COPY Pipfile Pipfile.lock /app/
RUN pipenv install --deploy

# Create distribution container
FROM alpine:latest
WORKDIR /app
# Install Python and external runtime dependencies only
RUN apk add --no-cache python3 libffi
# Copy the virtual environment from the previous image
COPY --from=build /opt/venv /opt/venv
# Activate the virtual environment
ENV PATH="/opt/venv/bin:$PATH" VIRTUAL_ENV="/opt/venv"

# Copy trawler application
COPY *.py /app/
COPY test-assets /app/test-assets
# Create and set user
RUN adduser -D trawler -u 1000
RUN chown -R trawler:users /app
USER 1000
WORKDIR "/app"
CMD python3 /app/trawler.py --config /app/config/config.yaml
