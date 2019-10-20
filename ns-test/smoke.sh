#!/bin/bash

set -x

ip netns add titun-test-1
ip netns add titun-test-2
ip -n titun-test-1 link add eth1 type veth peer name eth2 netns titun-test-2

ip -n titun-test-1 link set lo up
ip -n titun-test-2 link set lo up

ip -n titun-test-1 link set eth1 up mtu 60000
ip -n titun-test-1 addr add 192.168.3.1/24 dev eth1
ip -n titun-test-2 link set eth2 up mtu 9000
ip -n titun-test-2 addr add 192.168.3.2/24 dev eth2

ip netns exec titun-test-1 kcov --verify --exclude-pattern=/usr/lib,/.cargo,patched/ring ../coverage/tun1 titun -fc tun1.conf tun1 &
ip netns exec titun-test-2 kcov --verify --exclude-pattern=/usr/lib,/.cargo,patched/ring ../coverage/tun2 titun -fc tun2.conf tun2 &

while [ ! -e /var/run/wireguard/tun1.sock ]; do sleep 2; done
while [ ! -e /var/run/wireguard/tun2.sock ]; do sleep 2; done

ip -n titun-test-1 link set tun1 up mtu 59000
ip -n titun-test-1 addr add 192.168.77.1/24 dev tun1
ip -n titun-test-2 link set tun2 up mtu 1420
ip -n titun-test-2 addr add 192.168.77.2/24 dev tun2

ip netns exec titun-test-2 ping -c 5 192.168.77.1
eval "./clean-up.sh; exit $?"
