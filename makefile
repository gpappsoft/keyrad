run-test:
	env GOOS=linux GOARCH=amd64 go build -o ./build/amd64/keyrad main.go
	docker build --platform linux/amd64 -t keyrad:dev -f ./tests/dockerfile-test .
	docker run -ti keyrad:dev /app/run.sh