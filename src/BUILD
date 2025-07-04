load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:cc_binary.bzl", "cc_binary")

package(default_visibility = ["//visibility:public"])

cc_library(
  name = "status_macros",
  hdrs = ["status_macros.h"],
)

cc_library(
  name = "dns_packet",
  srcs = ["dns_packet.cc"],
  hdrs = ["dns_packet.h"],
  deps = [
    ":status_macros",
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

cc_binary(
  name = "main",
  srcs = ["main.cc"],
  args = [
    "--stderrthreshold=0",
  ],
  deps = [
    ":dns_packet",
    "@abseil-cpp//absl/flags:parse",
    "@abseil-cpp//absl/log:check",
    "@abseil-cpp//absl/log:flags",
    "@abseil-cpp//absl/log:initialize",
    "@abseil-cpp//absl/log:log",
  ],
)
