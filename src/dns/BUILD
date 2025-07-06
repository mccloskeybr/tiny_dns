load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:cc_binary.bzl", "cc_binary")

package(default_visibility = ["//visibility:public"])
cc_library(
  name = "dns_packet",
  srcs = ["dns_packet.cc"],
  hdrs = ["dns_packet.h"],
  deps = [
    "//src/common:status_macros",
    "@abseil-cpp//absl/container:btree",
    "@abseil-cpp//absl/log:check",
    "@abseil-cpp//absl/log:log",
    "@abseil-cpp//absl/status:status",
    "@abseil-cpp//absl/status:statusor",
    "@abseil-cpp//absl/strings:strings",
  ],
)

cc_test(
  name = "dns_packet_test",
  srcs = ["dns_packet_test.cc"],
  deps = [
    ":dns_packet",
    "@abseil-cpp//absl/status:status_matchers",
    "@googletest//:gtest",
    "@googletest//:gtest_main",
  ],
)

cc_library(
  name = "record_store",
  srcs = ["record_store.cc"],
  hdrs = ["record_store.h"],
  deps = [
    "//src/dns:dns_packet",
    "@abseil-cpp//absl/log:log",
    "@abseil-cpp//absl/strings:strings",
  ],
)

cc_library(
  name = "client",
  hdrs = ["client.h"],
  deps = [
    "@abseil-cpp//absl/log:log",
    "@abseil-cpp//absl/status:status",
    "@abseil-cpp//absl/status:statusor",
    "@abseil-cpp//absl/strings:strings",
  ],
)

cc_library(
  name = "dns_server",
  srcs = ["dns_server.cc"],
  hdrs = ["dns_server.h"],
  deps = [
    ":client",
    ":dns_packet",
    ":record_store",
    "//src/common:status_macros",
    "@abseil-cpp//absl/log:check",
    "@abseil-cpp//absl/log:log",
    "@abseil-cpp//absl/status:status",
    "@abseil-cpp//absl/status:statusor",
    "@abseil-cpp//absl/strings:strings",
  ],
)
