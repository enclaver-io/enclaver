# The build context is examples/spiffe so that the client and the server can
# share one Go module:
#
#   docker build -f server/Dockerfile -t spiffe-server-app:latest .

FROM golang:1.25-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY internal ./internal
COPY server ./server

RUN CGO_ENABLED=0 go build -trimpath -o /out/server ./server

FROM alpine:3.22

# The root CA that the SPIRE server's own certificate chains up to. odyn reads
# this inside the enclave to authenticate the SPIRE server before it attests to
# it, so baking it into the app image means the trust anchor is covered by the
# enclave measurement (PCR0) rather than supplied at run time.
COPY spire/out/ca/ca.crt /etc/spire/ca.crt

# odyn writes this enclave's own SVID here; see svid_dir in enclaver.yaml.
RUN mkdir -p /var/run/spiffe

COPY --from=build /out/server /usr/local/bin/spiffe-server

ENTRYPOINT ["/usr/local/bin/spiffe-server"]
