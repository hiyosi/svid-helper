out_dir := out/bin

build:
	cd cmd && GOOS=linux GOARCH=amd64 go build -o ../$(out_dir)/pod-svid-helper

build-docker: build
	docker build -t hiyosi/pod-svid-helper .

experimental-push: build
	docker build -t hiyosi/pod-svid-helper:experimental .
	docker push hiyosi/pod-svid-helper:experimental

docker-push: build
	docker build -t hiyosi/pod-svid-helper:latest .
	docker push hiyosi/pod-svid-helper:latest

docker-push-tag: build
	docker build -t hiyosi/pod-svid-helper:$TAG .
	docker push hiyosi/pod-svid-helper:$TAG

test: vet
	go test ./...

vet:
	go vet ./...

clean:
	go clean ./...
	rm -rf out

.PHONY: all build test vet clean
