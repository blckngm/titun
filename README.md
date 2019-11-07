# TiTun

 [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Bors enabled](https://bors.tech/images/badge_small.svg)](https://app.bors.tech/repositories/21087)
[![Dependabot enabled](https://badgen.net/dependabot/sopium/titun/?icon=dependabot)](https://dependabot.com)
[![azure-pipelines](https://dev.azure.com/sopium/titun/_apis/build/status/sopium.titun?branchName=staging)](https://dev.azure.com/sopium/titun/_build?definitionId=1)
[![codecov](https://codecov.io/gh/sopium/titun/branch/master/graph/badge.svg)](https://codecov.io/gh/sopium/titun)

Simple, fast, and cross-platform IP tunnel written in Rust. [WireGuard](https://www.wireguard.com/) compatible.

## WARNING

This project is experimental and still under development. Use at your own risk.

## Build

[Install rust](https://www.rust-lang.org/tools/install), and then

```
$ cargo build --release
```

to build a `titun` executable in `target/release`.

## CLI and Configuration

Use

```sh
$ sudo titun -c tun0.toml -f tun0
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
# Optional. Override by command line argument. NOT applied when reloading.
Name = "tun7"
# Optiona. Alias: Port.
ListenPort = 7777
# Alias: Key.
PrivateKey = "2BJtcgPUjHfKKN3yMvTiVQbJ/UgHj2tcZE6xU/4BdGM="
# Alias: Mark.
FwMark = 33

[[Peer]]
PublicKey = "Ck8P+fUguLIf17zmb3eWxxS7PqgN3+ciMFBlSwqRaw4="
# Optional. Alias: PSK.
PresharedKey = "w64eiHxoUHU8DcFexHWzqILOvbWx9U+dxxh8iQqJr+k="
# Optional. Alias: Routes.
AllowedIPs = ["192.168.77.0/24"]
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

ExecStart=/usr/local/bin/titun -f -c /etc/titun/%I.conf %I
ExecStartPost=/bin/sh -c "if [ -x /etc/titun/%I.up.sh ]; then /etc/titun/%I.up.sh; fi"
ExecStopPost=/bin/sh -c "if [ -x /etc/titun/%I.down.sh ]; then /etc/titun/%I.down.sh; fi"

ExecReload=/usr/local/bin/titun check /etc/titun/%I.conf
ExecReload=/bin/kill -HUP $MAINPID

Restart=always

[Install]
WantedBy=multi-user.target
```

Now if you want to run a TiTun interface `tun0`, put its configuration at
`/etc/titun/tun0.conf`, write a script `/etc/titun/tun0.up.sh` to configure IP
address, routes, DNS etc., write a script `/etc/titun/tun0.down.sh` to reverse
those changes, and use `systemctl (start|stop|reload|restart|status) titun@tun0`
to manage the service.

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

Windows is semi-supported. (TODO: document driver, GUI, specific configuration,
etc.)
