REPONAME=digital-crimes/phishstory-service
BUILDROOT=$(HOME)/dockerbuild/$(REPONAME)
DOCKERREPO=docker-dcu-local.artifactory.secureserver.net/phishstory-service
DATE=$(shell date)
COMMIT=
BUILD_BRANCH=origin/main
SHELL=/bin/bash

all: env

env:
	pip install -r test_requirements.txt
	pip install -r requirements.txt

.PHONY: flake8
flake8:
	@echo "----- Running linter -----"
	flake8 --config ./.flake8 .

.PHONY: isort
isort:
	@echo "----- Optimizing imports -----"
	isort --atomic --skip pb --skip .venv .

.PHONY: tools
tools: flake8 isort

.PHONY: test
test:
	@echo "----- Running tests -----"
	nosetests tests

.PHONY: testcov
testcov:
	@echo "----- Running tests with coverage -----"
	nosetests tests --with-coverage --cover-erase --cover-package=service --cover-xml


.PHONY: prep
prep: tools test
	@echo "----- preparing $(REPONAME) build -----"
	mkdir -p $(BUILDROOT)/
	cp -rp ./* $(BUILDROOT)
	cp -rp ~/.pip $(BUILDROOT)/pip_config

.PHONY: prod
prod: prep
	@echo "----- building $(REPONAME) prod -----"
	read -p "About to build production image from $(BUILD_BRANCH) branch. Are you sure? (Y/N): " response ; \
	if [[ $$response == 'N' || $$response == 'n' ]] ; then exit 1 ; fi
	if [[ `git status --porcelain | wc -l` -gt 0 ]] ; then echo "You must stash your changes before proceeding" ; exit 1 ; fi
	git fetch && git checkout $(BUILD_BRANCH)
	$(eval COMMIT:=$(shell git rev-parse --short HEAD))
	sed -ie 's/THIS_STRING_IS_REPLACED_DURING_BUILD/$(DATE)/' $(BUILDROOT)/k8s/prod/deployment.yaml
	sed -ie 's/REPLACE_WITH_GIT_COMMIT/$(COMMIT)/' $(BUILDROOT)/k8s/prod/deployment.yaml
	docker build -t $(DOCKERREPO):$(COMMIT) $(BUILDROOT)
	git checkout -

.PHONY: ote
ote: prep
	@echo "----- building $(REPONAME) ote -----"
	sed -ie 's/THIS_STRING_IS_REPLACED_DURING_BUILD/$(DATE)/g' $(BUILDROOT)/k8s/ote/deployment.yaml
	docker build -t $(DOCKERREPO):ote $(BUILDROOT)

.PHONY: dev
dev: prep
	@echo "----- building $(REPONAME) dev -----"
	sed -ie 's/THIS_STRING_IS_REPLACED_DURING_BUILD/$(DATE)/g' $(BUILDROOT)/k8s/dev/deployment.yaml
	docker build -t $(DOCKERREPO):dev $(BUILDROOT)

.PHONY: prod-deploy
prod-deploy: prod
	@echo "----- deploying $(REPONAME) prod -----"
	docker push $(DOCKERREPO):$(COMMIT)
	kubectl --context prod-dcu apply -f $(BUILDROOT)/k8s/prod/deployment.yaml --record

.PHONY: ote-deploy
ote-deploy: ote
	@echo "----- deploying $(REPONAME) ote -----"
	docker push $(DOCKERREPO):ote
	kubectl --context ote-dcu apply -f $(BUILDROOT)/k8s/ote/deployment.yaml --record

.PHONY: dev-deploy
dev-deploy: dev
	@echo "----- deploying $(REPONAME) dev -----"
	docker push $(DOCKERREPO):dev
	kubectl --context dev-dcu apply -f $(BUILDROOT)/k8s/dev/deployment.yaml --record

.PHONY: clean
clean:
	@echo "----- cleaning $(REPONAME) app -----"
	rm -rf $(BUILDROOT)
