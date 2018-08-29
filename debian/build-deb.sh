#!/bin/bash

set -e

cargo build --release
mkdir -p package/usr/bin/
cp ../target/release/titun package/usr/bin/titun
trap "rm package/usr/bin/titun" 0
fakeroot dpkg-deb --build package titun.deb
