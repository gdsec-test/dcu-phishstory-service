# Phishstory Service

Phishstory Service is a gRPC service that provides CRUD functionality for Abuse Reports relating to phishing, malware, spam, and network abuse.

## Cloning
To clone the repository via SSH perform the following
```
git clone git@github.secureserver.net:digital-crimes/phishstory-service.git
```

It is recommended that you clone this project into a pyvirtualenv or equivalent virtual environment.

## Installing Dependencies
To install all dependencies for development and testing simply run `make`.

## Building
To compile the project run one of the make targets

```
make [dev, ote, prod]
```


## Deploying
Deploying the Docker image to Kubernetes can be achieved via
```
make [dev, ote, prod]-deploy
```
You must also ensure you have the proper push permissions to Artifactory or you may experience a `Forbidden` message.

## Testing
```
make test     # runs all unit tests
make testcov  # runs tests with coverage
```

## Style and Standards
All deploys must pass Flake8 linting and all unit tests which are baked into the [Makefile](Makfile).

There are a few commands that might be useful to ensure consistent Python style:

```
make flake8  # Runs the Flake8 linter
make isort   # Sorts all imports
make tools   # Runs both Flake8 and isort
```

## Built With
1. gRPC
2. RabbitMQ


## Running Locally
In order to run Phishstory Service locally you must specify the following environment variables
1. DB_PASS
2. SNOW_PASS
3. BROKER_PASS

You may then run Phishstory Service via `python run.py`


## Example Client Implementation
```
class PhishstoryServiceClient:
    def __init__(self, url):
        self._url = url

    def get_ticket(self, ticketId):
        channel = grpc.insecure_channel(self._url)
        ready_future = grpc.channel_ready_future(channel)
        stub = pb.phishstory_pb2_grpc.PhishstoryStub(channel)

        resp = None
        try:
            ready_future.result(timeout=5)
        except grpc.FutureTimeoutError:
            print "Unable to connect to server"
        else:
            try:
                resp = stub.GetTicket(pb.phishstory_pb2.GetTicketRequest(ticketId=ticketId), timeout=5)
            except Exception as e:
                print "Unable to perform GetTicket on ticket {}".format(e.message)
        finally:
            return resp


if __name__ == '__main__':
    client = PhishstoryServiceClient("localhost:50051")
    resp = client.get_ticket("DCU000289618")
    print "Response: {}".format(resp)
```
