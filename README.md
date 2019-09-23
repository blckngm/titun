# TiTun

Simple and fast, [WireGuard](https://www.wireguard.com/) compatible IP tunnel
written in Rust.

## WARNING

This project is experimental and still under development. Use at your own risk.

## Build

Install rust, and then

```
$ cargo build --release
```

Debian package for amd64 can be built with `dpkg-deb`:

```
$ cd debian
$ ./build-deb.sh
```

## Operating Systems Support

### Linux and FreeBSD

Linux and FreeBSD are supported.

On linux and FreeBSD, the WireGuard [cross platform userspace
interface](https://www.wireguard.com/xplatform/) is implmeneted. Use `wg` (from
wireguard-tools) and `ip` (or `ifconfig`) to configure the interface. See
[quickstart](https://www.wireguard.com/quickstart/) (Use `titun tun0` instead of
`ip link add dev wg0 type wireguard`).

#### wg-quick

TiTun is compatible with `wg-quick`. Use the `WG_QUICK_USERSPACE_IMPLEMENTATION`
environment variable to specify `titun` as the userspace implementation.

```sh
$ sudo WG_QUICK_USERSPACE_IMPLEMENTATION=titun wg-quick ...
```

#### systemd

TiTun supports systemd. Here is an example template service definiation:

```systemd
[Unit]
Description=TiTun instance %I

[Service]
Type=notify
Environment=RUST_LOG=warn
Environment=RUST_BACKTRACE=1

ExecStart=/usr/bin/titun -f %I

ExecStartPost=/usr/bin/wg setconf %I /etc/titun/%I.conf
ExecStartPost=/bin/sh -c "if [ -x /etc/titun/%I.up.sh ]; then /etc/titun/%I.up.sh; fi"

ExecStopPost=/bin/sh -c "if [ -x /etc/titun/%I.down.sh ]; then /etc/titun/%I.down.sh; fi"

Restart=always

[Install]
WantedBy=multi-user.target
```

When an instance is started, e.g. `titun@tun3`, a `tun3` interface is created.
The configuration at `/etc/titun/tun3.conf` is applied and the script
`/etc/titun/tun3.up.sh` is run (if present). When the service is stopped, the
script at `/etc/titun/tun3.down.sh` is run (if present).
