# TiTun

Simple and reasonably efficient, [WireGuard](https://www.wireguard.com/)
compatible IP tunnel written in Rust.

## WARNING

This project is experimental and still under development. Use at your own risk.

## Build

Install rust, and then

```
$ cargo build --release
```

Debian package can be built with `dpkg-deb`.

```
$ cd debian
$ ./build-deb.sh
```

## Platforms

Linux and Windows (with the tap-windows driver) are supported.

FreeBSD kind of works. Other BSD systems might work, but are untested.

## Usage

### Ad hoc:

```
$ sudo titun tun --dev tun0 &
$ sudo wg show tun0
$ sudo wg set tun0 ...
```

### Or with systemd:

```systemd
[Unit]
Description=TiTun instance %I

[Service]
Type=notify
Environment=RUST_LOG=warn
Environment=RUST_BACKTRACE=1

ExecStart=/usr/bin/titun tun --dev %I

ExecStartPost=/usr/bin/wg setconf %I /etc/titun/%I.conf
ExecStartPost=/bin/sh -c "if [ -x /etc/titun/%I.up.sh ]; then /etc/titun/%I.up.sh; fi"

ExecStopPost=/bin/sh -c "if [ -x /etc/titun/%I.down.sh ]; then /etc/titun/%I.down.sh; fi"

Restart=always

[Install]
WantedBy=multi-user.target
```

### Or use wg-quick.
