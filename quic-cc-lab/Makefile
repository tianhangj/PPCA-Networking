.PHONY: build test bench vet fmt clean score

ALG ?= student
# Backward compatibility for old invocations like `make bench CC=student`.
ifeq ($(origin CC),command line)
ALG := $(CC)
override CC :=
endif

build:
	go build -buildvcs=false -o bin/bench        ./cmd/bench

vet:
	go vet ./...

fmt:
	gofmt -l -w internal cmd

# loopback sanity check (no netem): should print non-zero goodput
bench: build
	@./bin/bench -mode server -listen 127.0.0.1:4433 -cc $(ALG) & \
	SRV=$$!; sleep 0.5; \
	./bin/bench -mode client -server 127.0.0.1:4433 -cc $(ALG) -duration 5s; \
	kill $$SRV 2>/dev/null || true

clean:
	rm -rf bin testbed/results
