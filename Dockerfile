# phishstory-service

FROM artifactory.secureserver.net:10014/docker-dcu-local/grpcio
MAINTAINER DCUENG <dcueng@godaddy.com>

# Best Practice - Creating a user instead of running as root
RUN addgroup -S dcu && adduser -H -S -G dcu dcu

# apt-get installs
RUN apk update && \
    apk add --no-cache build-base \
    ca-certificates \
    libffi-dev \
    linux-headers \
    openssl-dev \
    python-dev \
    py-pip

# Expose grpc port 50051
EXPOSE 50051

# Move files to new directory in docker container
COPY ./*.ini ./*.sh ./run.py ./*.yml ./*.py /app/
COPY . /tmp
RUN chown dcu:dcu -R /app

# pip install from our private pips staged by our Makefile
RUN for dep in blindAl dcdatabase; \
  do \
  pip install --compile "/tmp/private_deps/$dep"; \
done

RUN update-ca-certificates && pip install --compile /tmp && rm -rf /tmp/*

ENTRYPOINT ["/app/runserver.sh"]