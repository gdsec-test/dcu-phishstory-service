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

# Expose grpc port 5000
EXPOSE 5000

# Move files to new directory in docker container
COPY ./*.sh ./run.py ./*.yml /app/
COPY . /tmp
RUN chown dcu:dcu -R /app

# pip install from our private pips staged by our Makefile
RUN for dep in blindal dcdatabase; \
  do \
  pip install --compile "/tmp/private_deps/$dep"; \
done

COPY certs/* /usr/local/share/ca-certificates/
RUN update-ca-certificates && pip install --compile /tmp && rm -rf /tmp/*

ENTRYPOINT ["/app/runserver.sh"]