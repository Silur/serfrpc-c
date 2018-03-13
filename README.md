# Simple C RPC for [hashicorp serf](https://www.serf.io/docs/agent/rpc.html)

Missing calls:
* Stats - you better debug the daemon in a separate flow

Return types are mostly intuitive, callbacks expect an `msgpack_unpacked` argument.
See `rpc.h` for usage.
