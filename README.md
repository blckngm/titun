# TiTun

 [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Bors enabled](https://bors.tech/images/badge_small.svg)](https://app.bors.tech/repositories/21087)
[![CI](https://github.com/sopium/titun/actions/workflows/ci.yml/badge.svg)](https://github.com/sopium/titun/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/sopium/titun/branch/master/graph/badge.svg)](https://codecov.io/gh/sopium/titun)

Simple, fast, and cross-platform IP tunnel written in Rust. [WireGuard](https://www.wireguard.com/) compatible.

## Installation

Download binaries or installers from github releases.

Or build from source:

```
$ cargo build --release
```

## CLI and Configuration

Use

```sh
$ sudo titun -fc tun0.toml
```

to run TiTun and open the tun interface `tun0`. Here `-f` tells the program to
run in foreground, i.e., not daemonize. The `-c tun0.toml` option tells the
program to load configuration from the file `tun0.toml`.

Use `titun show` to show interface status. (It's similar to `wg show`.) Use
`titun help` to discover more CLI options.

It is recommended to use the TOML format, but the format used by `wg` is also
accepted.

```toml
# All optional. NOT applied when reloading.
[General]
# Set logging. Override by the `--log` option or the `RUST_LOG` environment variable.
Log = "info"
# Switch to user after initialization to drop privilege. Override by `--user`.
#
# If you use this option, and want to reload configuration, the configuration file
# must be readable by this user.
User = "nobody"
# Switch to group.
Group = "nogroup"
# --foreground
Foreground = true
# Number of worker threads. Override by `--threads` or `TITUN_THREADS`.
# Default is `min(2, number of cores)`.
Threads = 2

[Interface]
# Optiona. Alias: Port.
ListenPort = 7777
# Alias: Key.
PrivateKey = "2BJtcgPUjHfKKN3yMvTiVQbJ/UgHj2tcZE6xU/4BdGM="
# Alias: Mark.
FwMark = 33

# If an address is specified, TiTun will try to set the interface address, mtu, DNS servers and routes.
Address = "192.168.77.5"
Mtu = 1280
DNS = "192.168.77.0"

[[Peer]]
PublicKey = "Ck8P+fUguLIf17zmb3eWxxS7PqgN3+ciMFBlSwqRaw4="
# Optional. Alias: PSK.
PresharedKey = "w64eiHxoUHU8DcFexHWzqILOvbWx9U+dxxh8iQqJr+k="
# Optional. Alias: Routes.
AllowedIPs = ["192.168.0.0/16"]

# Optional. These routes will be excluded from the automatically added routes.
#
# Have no effect is `Interface.Address` is not specified.
ExcludeRoutes = ["192.168.20.0/24"]

# Optional.
#
# Host names can be used. If name resolution fails, a warning is emitted and
# the field is ignored.
Endpoint = "192.168.3.1:7777"
# Optional. Range: 1 - 65535. Alias: Keepalive.
PersistentKeepalive = 17
```

### systemd

On linux, this is the recommended way to run TiTun. Copy the `titun` binary to
`/usr/local/bin`, and put this service file `titun@.service` at
`/etc/systemd/system/`:

```systemd
[Unit]
Description=TiTun instance %I

[Service]
Type=notify
Environment=RUST_BACKTRACE=1

ExecStart=/usr/local/bin/titun -fc /etc/titun/%I.conf
ExecStartPost=/bin/sh -c "if [ -x /etc/titun/%I.up.sh ]; then /etc/titun/%I.up.sh; fi"
ExecStopPost=/bin/sh -c "if [ -x /etc/titun/%I.down.sh ]; then /etc/titun/%I.down.sh; fi"

ExecReload=/usr/local/bin/titun check /etc/titun/%I.conf
ExecReload=/bin/kill -HUP $MAINPID

Restart=always

[Install]
WantedBy=multi-user.target
```

Now if you want to run a TiTun interface `tun0`, put its configuration at
`/etc/titun/tun0.conf` and use `systemctl (start|stop|reload|restart|status)
titun@tun0` to manage the service. If you have more complicated DNS/routing
configurations, you can manage them with custom scripts at
`/etc/titun/tun0.up.sh` and `/etc/titun/tun0.down.sh`.

### Use with WireGuard tools

On unix-like operating systems, the WireGuard [cross platform userspace
interface](https://www.wireguard.com/xplatform/) is implemented. So you can use
`wg` and `wg-quick` to configure TiTun interfaces.

To use `wg-quick`, specify the `WG_QUICK_USERSPACE_IMPLEMENTATION` environment
variable to `titun`:

```sh
$ sudo WG_QUICK_USERSPACE_IMPLEMENTATION=titun wg-quick ...
```

## Operating Systems Support

### Linux

Linux is supported.

### FreeBSD

FreeBSD is supported.

### Windows

Windows is supported. (TODO: document driver, GUI, specific configuration, etc.)

## MacOS X

Mac OS X is supported. The interface name must be in the form of `utunN`, where `N` is a non-negative integer.
