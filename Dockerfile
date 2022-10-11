# phishstory-service

FROM docker-dcu-local.artifactory.secureserver.net/dcu-python3.7:3.3
LABEL MAINTAINER=dcueng@godaddy.com

USER root
# Best Practice - Creating a user instead of running as root
# Expose grpc port 50051
EXPOSE 50051

# Move files to new directory in docker container
RUN mkdir -p /tmp/build
COPY requirements.txt /tmp/build/
COPY pip_config /tmp/build/pip_config
RUN PIP_CONFIG_FILE=/tmp/build/pip_config/pip.conf pip install -r /tmp/build/requirements.txt

COPY *.py /tmp/build/
COPY test_requirements.txt /tmp/build/
COPY README.md /tmp/build/
COPY pb /tmp/build/pb
COPY service /tmp/build/service

# pip install private pips staged by Makefile
RUN PIP_CONFIG_FILE=/tmp/pip_config/pip.conf pip install --compile /tmp/build

COPY ./*.ini ./*.sh ./run.py ./*.py /app/
# cleanup
RUN rm -rf /tmp/build
RUN chown dcu:dcu -R /app

USER dcu
ENTRYPOINT ["/app/runserver.sh"]