load("@rules_cc//cc:cc_binary.bzl", "cc_binary")

package(default_visibility = ["//visibility:public"])

cc_binary(
  name = "main",
  srcs = ["main.cc"],
  args = [
    "--stderrthreshold=0",
  ],
  deps = [
    "//src/admin:dns_admin_service_impl",
    "//src/common:record_store",
    "//src/dns:dns_packet",
    "//src/dns:dns_server",
    "//src/dns:client",
    "@abseil-cpp//absl/flags:flag",
    "@abseil-cpp//absl/flags:parse",
    "@abseil-cpp//absl/log:check",
    "@abseil-cpp//absl/log:flags",
    "@abseil-cpp//absl/log:initialize",
    "@abseil-cpp//absl/log:log",
    "@grpc//:grpc++",
    "@grpc//:grpc++_reflection",
  ],
)
