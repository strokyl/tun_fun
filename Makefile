build-with-docker:
	docker build . -t tun_fun

build-test-image:
	docker build . -f test.Dockerfile -t tun_fun_test

test: build-with-docker build-test-image
	docker run \
		--net=host \
		-v /var/run/docker.sock:/var/run/docker.sock \
		--rm \
		tun_fun_test
