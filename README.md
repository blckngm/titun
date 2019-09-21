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

## CLI and Configuration

Use

```sh
$ sudo titun -c tun0.toml -f tun0
```

to run TiTun and open the tun device `tun0`. Here `-f` tells the program to run in foreground, i.e., not daemonize. The `-c tun0.toml` option tells the program to load configuration from the file `tun0.toml`.

Configuration file is similar to what `wg` produces and expects, but in TOML format:

```toml
[Interface]
ListenPort = 7777
PrivateKey = "2BJtcgPUjHfKKN3yMvTiVQbJ/UgHj2tcZE6xU/4BdGM="
FwMark = 33

[[Peer]]
PublicKey = "Ck8P+fUguLIf17zmb3eWxxS7PqgN3+ciMFBlSwqRaw4="
PresharedKey = "w64eiHxoUHU8DcFexHWzqILOvbWx9U+dxxh8iQqJr+k="
AllowedIPs = ["192.168.77.0/24"]
Endpoint = "192.168.3.1:7777"
PersistentKeepalive = 17
```

A show subcommand is available to query device status (similar to `wg show`):

```
$ sudo titun show
```

After the program is running, use `ip` or `ifconfig` to configure IP addresses, routes, etc. And you are good to go!

You can send a `SIGHUP` signal to reload configuration.

### systemd

TiTun supports systemd. Here is an example template service definiation:

```systemd
[Unit]
Description=TiTun instance %I

[Service]
Type=notify
Environment=RUST_LOG=warn
Environment=RUST_BACKTRACE=1

ExecStart=/usr/bin/titun -f -c /etc/titun/%I.conf %I
ExecStartPost=/bin/sh -c "if [ -x /etc/titun/%I.up.sh ]; then /etc/titun/%I.up.sh; fi"
ExecStopPost=/bin/sh -c "if [ -x /etc/titun/%I.down.sh ]; then /etc/titun/%I.down.sh; fi"

ExecReload=/usr/bin/titun check /etc/titun/%I.conf
ExecReload=/bin/kill -HUP $MAINPID

Restart=always

[Install]
WantedBy=multi-user.target
```

### WireGuard cross platform user interface

On unix-like operating systems, the WireGuard [cross platform userspace
interface](https://www.wireguard.com/xplatform/) is implmeneted. Use `wg` (from
wireguard-tools) and `ip` (or `ifconfig`) to configure the interface. See
[quickstart](https://www.wireguard.com/quickstart/) (Use `titun tun0` instead of
`ip link add dev wg0 type wireguard`).

TiTun is compatible with `wg-quick`. Use the `WG_QUICK_USERSPACE_IMPLEMENTATION`
environment variable to specify `titun` as the userspace implementation.

```sh
$ sudo WG_QUICK_USERSPACE_IMPLEMENTATION=titun wg-quick ...
```

## Operating Systems Support

### Linux and FreeBSD

Linux and FreeBSD are supported.
