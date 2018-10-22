#!/bin/bash -eu

integration_test() {
    docker_id=$(docker run \
           --device /dev/net/tun:/dev/net/tun \
           --cap-add=NET_ADMIN \
           --net=host \
           --rm \
           -d \
           tun_fun \
           -binding 192.168.42.42:80:8080 \
           -gardening-cidr 192.168.43.0/24 \
           -targeted-cidr 192.168.42.0/24)

    sleep 10
    [[ "$(nc -l -p 8080)" == "ping" ]] &
    echo "ping" | nc -q 0 192.168.42.42 80

    if wait %1; then
        docker kill $docker_id
        echo
        echo "Test OK"
        exit 0
    else
        docker kill $docker_id
        echo
        echo "Test NOK"
        exit 1
    fi
}

integration_test
