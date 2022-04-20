# phishstory-service

FROM python:3.7.10-slim
LABEL MAINTAINER=dcueng@godaddy.com

# Best Practice - Creating a user instead of running as root
RUN addgroup dcu && adduser --disabled-password --disabled-login --no-create-home --ingroup dcu --system dcu
# Expose grpc port 50051
EXPOSE 50051

# Move files to new directory in docker container
COPY ./*.ini ./*.sh ./run.py ./*.py /app/
COPY . /tmp
RUN chown dcu:dcu -R /app

# install custom root certificates
RUN mkdir -p /usr/local/share/ca-certificates/
RUN cp /tmp/certs/* /usr/local/share/ca-certificates/
RUN update-ca-certificates

RUN PIP_CONFIG_FILE=/tmp/pip_config/pip.conf pip install --compile /tmp && rm -rf /tmp/*

ENTRYPOINT ["/app/runserver.sh"]