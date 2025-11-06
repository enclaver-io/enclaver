# Build and run the SPIFFE example. See README.md for what each step does.
#
# The enclave steps need an AWS Nitro Enclaves capable instance; everything up
# to and including "make spire-up" runs anywhere Docker does.

TRUST_DOMAIN    ?= example.org
SPIRE_VERSION   ?= 1.12.5
SPIRE_IMAGE     ?= spiffe-example-spire-server:latest
SPIRE_CONTAINER ?= spire-server
SPIRE_PORT      ?= 8081
ENCLAVER        ?= enclaver

OUT := spire/out

# The measurement of a built enclave, read back out of the build summary. This
# expands to a shell substitution rather than $(shell ...) on purpose: make
# expands a whole recipe before running any of it, so $(shell ...) would read
# the summary before the build in the same recipe had written it.
pcr0 = $$(python3 -c "import json;print(json.load(open('$(OUT)/$(1)-build.json'))['Measurements']['PCR0'])")

.PHONY: help
help:
	@echo "make ca             generate the throwaway root CA"
	@echo "make spire-image    build the SPIRE server image with the nitro_enclave plugin"
	@echo "make spire-up       run the SPIRE server on the host"
	@echo "make spire-down     stop the SPIRE server"
	@echo "make spire-logs     follow the SPIRE server logs"
	@echo "make apps           build the client and server app images"
	@echo "make enclaves       build both enclave images and record their PCR0"
	@echo "make register       register both enclaves with the SPIRE server"
	@echo "make run-server     run the server enclave"
	@echo "make run-client     run the client enclave"
	@echo "make clean          remove built artifacts, containers and the SPIRE datastore"

# --- SPIRE server (on the host) ---------------------------------------------

.PHONY: ca
ca: $(OUT)/ca/ca.crt

$(OUT)/ca/ca.crt:
	./spire/gen-ca.sh

.PHONY: spire-image
spire-image:
	docker build --build-arg SPIRE_VERSION=$(SPIRE_VERSION) -t $(SPIRE_IMAGE) spire/

.PHONY: spire-up
spire-up: ca spire-image
	docker run -d --name $(SPIRE_CONTAINER) \
		-p 127.0.0.1:$(SPIRE_PORT):8081 \
		-v spiffe-example-spire-data:/opt/spire/data \
		-v $(abspath $(OUT)/ca):/opt/spire/conf/ca:ro \
		$(SPIRE_IMAGE)

.PHONY: spire-down
spire-down:
	-docker rm -f $(SPIRE_CONTAINER)

.PHONY: spire-logs
spire-logs:
	docker logs -f $(SPIRE_CONTAINER)

# --- Apps and enclaves ------------------------------------------------------

.PHONY: apps
apps: ca
	docker build -f server/Dockerfile -t spiffe-server-app:latest .
	docker build -f client/Dockerfile -t spiffe-client-app:latest .

.PHONY: enclaves
enclaves: server-enclave client-enclave

.PHONY: server-enclave
server-enclave: apps
	@mkdir -p $(OUT)
	$(ENCLAVER) build -f server/enclaver.yaml > $(OUT)/server-build.json
	@echo "server PCR0: $(call pcr0,server)"

.PHONY: client-enclave
client-enclave: apps
	@mkdir -p $(OUT)
	$(ENCLAVER) build -f client/enclaver.yaml > $(OUT)/client-build.json
	@echo "client PCR0: $(call pcr0,client)"

# --- Registration -----------------------------------------------------------

.PHONY: register
register: register-server register-client

.PHONY: register-server
register-server:
	TRUST_DOMAIN=$(TRUST_DOMAIN) SPIRE_CONTAINER=$(SPIRE_CONTAINER) \
		./spire/register.sh $(call pcr0,server) server

.PHONY: register-client
register-client:
	TRUST_DOMAIN=$(TRUST_DOMAIN) SPIRE_CONTAINER=$(SPIRE_CONTAINER) \
		./spire/register.sh $(call pcr0,client) client

.PHONY: entries
entries:
	docker exec $(SPIRE_CONTAINER) /opt/spire/bin/spire-server entry show

# --- Running the enclaves ---------------------------------------------------
#
# --network host puts the enclave's supervisor in the host's network namespace,
# which is what makes Enclaver's "host" hostname resolve to the machine the
# SPIRE server and the other enclave are reachable on. It also publishes the
# server's ingress port directly, so no -p is needed.

DOCKER_RUN_ENCLAVE = docker run --rm -it --network host \
	--device /dev/nitro_enclaves:/dev/nitro_enclaves --privileged

.PHONY: run-server
run-server:
	$(DOCKER_RUN_ENCLAVE) --name spiffe-server-enclave spiffe-server-enclave:latest

.PHONY: run-client
run-client:
	$(DOCKER_RUN_ENCLAVE) --name spiffe-client-enclave spiffe-client-enclave:latest

# --- Cleanup ----------------------------------------------------------------

.PHONY: clean
clean: spire-down
	-docker volume rm spiffe-example-spire-data
	rm -rf $(OUT)
