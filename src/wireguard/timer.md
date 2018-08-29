# Timer State Machine

## Per Peer:

* Handshake resend:

  + Dropped when handshake succeeds.

  + Dropped on stop handshake.

  + Dropped on clear.

* Stop handshake:

  + `De-activated` when handshake succeeds.

  + `Adjust and activated if not activated` on handshake init.

  + `Adjust and activate` on queueing packet.

* Rekey no recv:

  + De-activated on recv.

  + `Adjust and activate if not activated` on sending a non-keep-alive.

  + De-activated on clear.

* Keep alive:

  + `Adjust and activate if not activated` on receiving a non-keep-alive.

  + `Adjust (to 1 second later) and activated` on handshake successful as initiator. (For key confirmation.)

  + De-activated on send.

  + De-activated on clear.

* Persistent keep alive:

  + `Adjust and activate` on set to `Some`, or send anything.

  + `De-activated` when interval is set to `None`.

* Clear:

  + `Adjust and activate if not activated` on handshake init.

  + `Adjust and activate` on handshake success.

  + `De-activated` on clear.
