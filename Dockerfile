# phishstory-service

FROM docker-dcu-local.artifactory.secureserver.net/dcu-python3.7:3.3
LABEL MAINTAINER=dcueng@godaddy.com

USER root
# Best Practice - Creating a user instead of running as root
# Expose grpc port 50051
EXPOSE 50051

# Move files to new directory in docker container
COPY ./*.ini ./*.sh ./run.py ./*.py /app/
COPY . /tmp
RUN chown dcu:dcu -R /app

RUN PIP_CONFIG_FILE=/tmp/pip_config/pip.conf pip install --compile /tmp && rm -rf /tmp/*

USER dcu
ENTRYPOINT ["/app/runserver.sh"]