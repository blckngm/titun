#!/bin/bash

ip -n titun-test-1 link del eth1
rm /var/run/wireguard/tun1.sock || ip -n titun-test-1 link del tun1
rm /var/run/wireguard/tun2.sock || ip -n titun-test-2 link del tun2
ip netns del titun-test-1
ip netns del titun-test-2
pkill iperf3
