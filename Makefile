REPONAME=digital-crimes/phishstory-service
BUILDROOT=$(HOME)/dockerbuild/$(REPONAME)
DOCKERREPO=docker-dcu-local.artifactory.secureserver.net/phishstory-service
DATE=$(shell date)
COMMIT=
BUILD_BRANCH=origin/main
SHELL=/bin/bash

define deploy_k8s
	docker push $(DOCKERREPO):$(2)
	cd k8s/$(1) && kustomize edit set image $$(docker inspect --format='{{index .RepoDigests 0}}' $(DOCKERREPO):$(2))
	kubectl --context $(1)-dcu apply -k k8s/$(1)
	cd k8s/$(1) && kustomize edit set image $(DOCKERREPO):$(1)
endef

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
	docker build -t $(DOCKERREPO):$(COMMIT) $(BUILDROOT)
	git checkout -

.PHONY: ote
ote: prep
	@echo "----- building $(REPONAME) ote -----"
	docker build -t $(DOCKERREPO):ote $(BUILDROOT)

.PHONY: test-env
test-env: prep
	@echo "----- building $(REPONAME) test -----"
	docker build -t $(DOCKERREPO):test $(BUILDROOT)

.PHONY: dev
dev: prep
	@echo "----- building $(REPONAME) dev -----"
	docker build -t $(DOCKERREPO):dev $(BUILDROOT)

.PHONY: prod-deploy
prod-deploy: prod
	@echo "----- deploying $(REPONAME) prod -----"
	$(call deploy_k8s,prod,$(COMMIT))

.PHONY: ote-deploy
ote-deploy: ote
	@echo "----- deploying $(REPONAME) ote -----"
	$(call deploy_k8s,ote,ote)

.PHONY: test-deploy
test-deploy: test-env
	@echo "----- deploying $(REPONAME) test -----"
	$(call deploy_k8s,test,test)

.PHONY: dev-deploy
dev-deploy: dev
	@echo "----- deploying $(REPONAME) test -----"
	$(call deploy_k8s,dev,dev)

.PHONY: clean
clean:
	@echo "----- cleaning $(REPONAME) app -----"
	rm -rf $(BUILDROOT)
