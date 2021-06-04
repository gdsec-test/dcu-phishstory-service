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

RUN pip install --compile /tmp/private_pips/dcdatabase
RUN pip install --compile /tmp/private_pips/dcu-structured-logging-grpc/
RUN pip install --compile /tmp && rm -rf /tmp/*

ENTRYPOINT ["/app/runserver.sh"]