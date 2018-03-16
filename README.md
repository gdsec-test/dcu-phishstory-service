# Phishstory Service

Phishstory Service is a gRPC service that provides CRUD functionality for Abuse Reports relating to phishing, malware, spam, and network abuse.

## Cloning
To clone the repository via SSH perform the following

```
git clone git@github.secureserver.net:ITSecurity/phishstory-service.git
```

It is recommended that you clone this project into a pyvirtualenv or equivalent virtual environment. 

## Installing Dependencies
You can install the required private dependencies via 
```
pip install -r private_pips.txt
```

Followed by install public dependencies via 
```
pip install -r requirements.txt
```

## Building
In order to build the project locally you can run the following commands

```
make [dev, ote, prod]
```


## Deploying
Deploying Phishstory Service to Kubernetes can be achieved by

```
make [dev, ote, prod]-deploy
```


## Testing
In order to run the tests you must first install the required dependencies via
```
pip install -r test_requirements.txt
```

Optionally, you may provide the flags --with-coverage --cover-package=service/ to nosetests to determine the test coverage of this project.

## Built With
1. gRPC
2. RabbitMQ


## Running Locally
In order to run Phishstory Service locally you must specify the following environment variables
1. DB_PASS
2. SNOW_PASS
3. BROKER_PASS

You may then run Phishstory Service via `python run.py`

## Rebuild gRPC Stub Files
Install grpcio-tools via
```
pip install grpcio-tools
```

Then regenerate the stub files using the following command
```
python -m grpc_tools.protoc -I./pb/ --python_out=./pb/ --grpc_python_out=./pb/ ./pb/phishstory.proto 
```


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
    client = PhishstoryServiceClient("localhost:5000")
    resp = client.get_ticket("DCU000289618")
    print "Response: {}".format(resp)
```
