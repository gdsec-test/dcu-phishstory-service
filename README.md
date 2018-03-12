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
To-Do

## Rebuild gRPC Stub Files
To-Do
