#!/bin/bash

set -ex

clean_up() {
    r=$?
    set +e
    ./clean-up.sh
    exit $r
}
trap clean_up EXIT

ip netns add titun-test-1
ip netns add titun-test-2
ip -n titun-test-1 link add eth1 type veth peer name eth2 netns titun-test-2

ip -n titun-test-1 link set lo up
ip -n titun-test-2 link set lo up

ip -n titun-test-1 link set eth1 up mtu 60000
ip -n titun-test-1 addr add 192.168.3.1/24 dev eth1
ip -n titun-test-2 link set eth2 up mtu 9000
ip -n titun-test-2 addr add 192.168.3.2/24 dev eth2

TITUN_INTEROPE_TEST=1 ip netns exec titun-test-1 ../target/debug/titun -f tun1 &
ip netns exec titun-test-2 ip link add tun2 type wireguard

while [ ! -e /var/run/wireguard/tun1.sock ]; do sleep 1; done

wg setconf tun1 tun1.conf
ip netns exec titun-test-2 wg setconf tun2 tun2.conf

ip -n titun-test-1 link set tun1 up mtu 59000
ip -n titun-test-1 addr add 192.168.77.1/24 dev tun1
ip -n titun-test-2 link set tun2 up mtu 1420
ip -n titun-test-2 addr add 192.168.77.2/24 dev tun2

ip netns exec titun-test-2 ping -W 10 -c 1 192.168.77.1
