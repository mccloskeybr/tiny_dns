# tiny_dns

This is a very barebones DNS server written in C++.

Features:

* Supports the DNS protocol.
* Supports a handful of DNS record types (`A`, `AAAA`, `CNAME`, others).

Dependencies:

* Built using Bazel.
* `absl` & `googletest` libraries.
