#!/bin/bash

set -ex

clean_up() {
    set +e
    r=$?
    ./clean-up.sh
    git checkout -- tun1.conf tun2.conf
    exit $r
}
trap clean_up EXIT

KCOV_TITUN='kcov --verify --exclude-pattern=/usr/include,/lib,/usr/lib,/.cargo,patched/ring ../coverage/$(dd if=/dev/urandom of=/dev/stdout bs=6 count=1 2>/dev/null | base64 | tr / _) ../target/debug/titun'

# Setup.

ip netns add titun-test-1
ip netns add titun-test-2
ip -n titun-test-1 link add eth1 type veth peer name eth2 netns titun-test-2

ip -n titun-test-1 link set lo up
ip -n titun-test-2 link set lo up

ip -n titun-test-1 link set eth1 up mtu 60000
ip -n titun-test-1 addr add 192.168.3.1/24 dev eth1
ip -n titun-test-2 link set eth2 up mtu 9000
ip -n titun-test-2 addr add 192.168.3.2/24 dev eth2

mkdir -p ../coverage

eval ip netns exec titun-test-1 $KCOV_TITUN -fc tun1.conf tun1 &
eval ip netns exec titun-test-2 $KCOV_TITUN -f tun2 &

while [ ! -e /var/run/wireguard/tun1.sock ]; do sleep 2; done
while [ ! -e /var/run/wireguard/tun2.sock ]; do sleep 2; done

wg setconf tun2 tun2.conf

ip -n titun-test-1 link set tun1 up mtu 59000
ip -n titun-test-1 addr add 192.168.77.1/24 dev tun1
ip -n titun-test-2 link set tun2 up mtu 1420
ip -n titun-test-2 addr add 192.168.77.2/24 dev tun2

# Ping.
ip netns exec titun-test-2 ping -i 0.1 -c 5 192.168.77.1

# Show.
eval $KCOV_TITUN show

# Generate and add PSK to config files.
PSK=$(../target/debug/titun genpsk)
echo PresharedKey = $PSK >> tun1.conf
echo PresharedKey = $PSK >> tun2.conf

# Reload.
pkill -HUP titun
wg setconf tun2 tun2.conf
sleep 1

# Show again.
eval $KCOV_TITUN show tun1 tun2

# And ping again.
ip netns exec titun-test-2 ping -i 0.1 -c 5 192.168.77.1
