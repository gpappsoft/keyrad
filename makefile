# Go test targets

# Run the full unit + integration + smoke suite with coverage.
test:
	go test ./... -cover

# Same, but under the race detector (also runs the e2e UDP tests).
test-race:
	go test -race ./...

# Fast end-to-end run: start the real server on a local UDP port against a mocked
# Keycloak and exchange real RADIUS packets (see server_test.go).
smoke-test:
	go test -run 'TestIntegration_|TestSmoke_' -count=1 -v .

run-test:
	env GOOS=linux GOARCH=amd64 go build -o ./build/amd64/keyrad main.go
	docker build --platform linux/amd64 -t keyrad:dev -f ./tests/dockerfile-test .
	docker run -ti keyrad:dev /app/run.sh