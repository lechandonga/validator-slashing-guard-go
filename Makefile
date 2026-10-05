.PHONY: test test-race demo fmt vet

test:
	go test -v ./...

test-race:
	CGO_ENABLED=1 go test -race -v ./...

demo:
	go run ./cmd/simdemo

fmt:
	gofmt -w .

vet:
	go vet ./...
