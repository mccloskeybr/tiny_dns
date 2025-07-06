load("@com_google_protobuf//bazel:cc_proto_library.bzl", "cc_proto_library")
load("@grpc//bazel:cc_grpc_library.bzl", "cc_grpc_library")
load("@rules_cc//cc:cc_library.bzl", "cc_library")

package(default_visibility = ["//visibility:public"])

proto_library(
  name = "dns_admin_service_proto",
  srcs = ["dns_admin_service.proto"],
)

cc_proto_library(
  name = "dns_admin_service_cc_proto",
  deps = ["dns_admin_service_proto"],
)

cc_grpc_library(
  name = "dns_admin_service_cc_grpc",
  srcs = [":dns_admin_service_proto"],
  grpc_only = True,
  deps = [":dns_admin_service_cc_proto"],
)

cc_library(
  name = "dns_admin_service_impl",
  srcs = ["dns_admin_service_impl.cc"],
  hdrs = ["dns_admin_service_impl.h"],
  deps = [
    ":dns_admin_service_cc_grpc",
    "//src/common:record_store",
    "//src/dns:dns_packet",
    "@abseil-cpp//absl/strings:strings",
    "@grpc//:grpc++",
  ],
)

cc_library(
  name = "dns_admin_service_client",
  srcs = ["dns_admin_service_client.cc"],
  hdrs = ["dns_admin_service_client.h"],
  deps = [
    ":dns_admin_service_cc_grpc",
    "@abseil-cpp//absl/log:log",
    "@grpc//:grpc++",
  ],
)
