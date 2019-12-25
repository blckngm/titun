import { Number, String, Array, Record, Static, Boolean, Null } from 'runtypes';

export const RtPeerState = Record({
    publicKey: String,
    presharedKey: Boolean,
    txBytes: Number,
    rxBytes: Number,
    persistentKeepaliveInterval: Number,
    allowedIps: Array(String),
    lastHandshakeTimeSec: Number.Or(Null),
    endpoint: String.Or(Null),
});

export const RtInterfaceState = Record({
    name: String,
    publicKey: String,
    listenPort: Number,
    fwmark: Number,
    peers: Array(RtPeerState),
});

export type PeerState = Static<typeof RtPeerState>;
export type InterfaceState = Static<typeof RtInterfaceState>;
