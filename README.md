# tiny_dns

This is a barebones DNS server written in C++.

Features:

* Supports DNS lookups over UDP.
* Supports a handful of DNS record types (`A`, `AAAA`, `CNAME`, others).
* Supports additional administrative functions (e.g. manual record insertion) via a side gRPC channel.
* DNS records are stored in a simple in-memory database.
* Supports secondary lookups. E.g. if a given qname is unknown, can forward the request to a fallback server, and cache for future lookups.

TODO:

* Recursive resolve.
* LRU cache for in-memory db.
* WAL or other simple disk-based storage for recovery / consistency across program executions.

Dependencies:

* Built on Linux, may work on other platforms with small modifications.
* Built using Bazel.
* Admin server uses gRPC.
* `absl` & `googletest` libraries.
