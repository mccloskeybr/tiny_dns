load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:cc_binary.bzl", "cc_binary")

package(default_visibility = ["//visibility:public"])

cc_library(
  name = "status_macros",
  hdrs = ["status_macros.h"],
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
