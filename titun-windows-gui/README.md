# TiTun Windows GUI

This is a basic Windows (C#/WPF) GUI for [TiTun](https://gitlab.com/sopium/titun).

## Build

* Build `titun.exe` and copy it here. (Rename it to `titun-32.exe` for 32 bit systems.)

* Build the GUI with Visual Studio or msbuild.

* Run Inno Setup to get a installer.

See also `..\.appveyor.yml`.

## Usage

Click Run and choose a configuration file.

Sample configuration file:

```yaml
# Name of the virtual interface.
dev_name: Local Area Network 2
# Whether to automatically config network.
# Default is true.
auto_config: true
network:
  # IP address of the virtual interface.
  address: "10.132.179.4"
  # Prefix length of the virtual network.
  prefix: 24
  # MTU of the virtual interface. Optional.
  mtu: 1280
  # Metric of the virtual interface. Optional.
  metric: 1
  # DNS servers of the virtual interface. Optional.
  dns:
    - "1.1.1.1"
  # Whether to block other interfaces' DNS servers.
  # Default is true.
  prevent_dns_leak: true
  # Next hop for new routes.
  # Tap-windows interfaces are not point to point,
  # so a next hop address must be specified for routes to work.
  next_hop: "10.132.179.1"
# Our private key. Base64 encoding.
key: KFo4y6lGauz+8v7nKkGHqe1pUcBHcCV6mYcyQZl0gEA=
peers:
    # Peer public key. Base64 encoding.
  - public_key: WUiH70+nDM1Lw7KFlSVigpJ9Q8izDUAWBK3cMMrUVjk=
    # Preshared key, base64 32-byte, optional.
    psk: ...
    # Endpoint. Optional.
    endpoint: "213.210.53.9:32973"
    # Allowed IPs.
    allowed_ips:
      - 0.0.0.0/1
      - 128.0.0.0/1
```

## How Auto Configuration Works

The GUI will automatically configure address, mask, MTU, metric, dns servers and
routes of the virtual interface if `auto_config` is true. Powershell is used
under the hood. Some commands used may not be supported on older versions of
Windows (e.g., Windows 7), so auto configuration might work there.

Address, mask, MTU and metric are configured with the `Set-NetIpInterface` and
`New-NetIPAddress` commands.

DNS servers are configured with the `Set-DnsClientServerAddress` command.

DNS leak is prevented by adding Windows Firewall rules (`New-NetFirewallRule`) to
block other interfaces' DNS servers.

A route to peer's endpoint will be added if the address is in the allowed IPs.
So, for example, if you have a peer like this:

```yaml
peers:
    - public_key: ...
      endpoint: "213.210.53.9:32973"
      allowed_ips:
        - "0.0.0.0/1"
        - "128.0.0.0/1"
```

And your original route to `213.210.53.9` is the default route, via
`192.168.1.1`, then a new route will be added to specifically route
`213.210.53.9/32` via `192.168.1.1`.

Routes to allowed IPs will be added if they are not entirely in the virtual
interfaces network (`network.address/network.prefix`). If all internet traffic
should be routed to this peer, it recommended that `0.0.0.0/1` and `128.0.0.0/1`
be used instead of `0.0.0.0/0`, so the original default route will not be
affected.

When you stop the tunnel or when you exit the program, routes and firewall rules
will be removed.
