#!/bin/bash

set -e

cross build --release --target=x86_64-unknown-linux-musl
mkdir -p package/usr/bin/
cp ../target/x86_64-unknown-linux-musl/release/titun package/usr/bin/titun
trap "rm package/usr/bin/titun" 0
fakeroot dpkg-deb --build package titun.deb
