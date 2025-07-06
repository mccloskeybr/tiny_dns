#include <iostream>
#include <cstring>
#include <thread>
#include <utility>
#include <time.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/log/check.h"
#include "grpcpp/grpcpp.h"
#include "grpcpp/ext/proto_server_reflection_plugin.h"
#include "src/dns/record_store.h"
#include "src/dns/client.h"
#include "src/dns/dns_server.h"
#include "src/admin/dns_admin_service_impl.h"

ABSL_FLAG(std::string, addr, "0.0.0.0",
          "Address to serve from.");
ABSL_FLAG(int32_t, dns_port, 4000,
          "Port to serve UDP DNS lookups.");
ABSL_FLAG(int32_t, admin_port, 4001,
          "Port to serve gRPC Admin functions from.");
ABSL_FLAG(std::string, fallback_dns_addr, "8.8.8.8",
          "If not empty, will forward failed resolution requests to this server.");
ABSL_FLAG(int32_t, fallback_dns_port, 53,
          "fallback DNS server port.");

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  srand(time(nullptr));

  auto record_store = std::make_shared<RecordStore>();

  LOG(INFO) << "Starting DNS UDP server: "
    << absl::GetFlag(FLAGS_addr) << ":" << absl::GetFlag(FLAGS_dns_port);
  std::shared_ptr<Client> fallback_dns = nullptr;
  if (!absl::GetFlag(FLAGS_fallback_dns_addr).empty()) {
    LOG(INFO) << "Initiating fallback DNS lookup server connection: "
      << absl::GetFlag(FLAGS_fallback_dns_addr) << ":"
      << absl::GetFlag(FLAGS_fallback_dns_port);
    absl::StatusOr<std::shared_ptr<Client>> temp_fallback_dns =
      Client::Create(
          absl::GetFlag(FLAGS_addr),
          absl::GetFlag(FLAGS_fallback_dns_addr),
          absl::GetFlag(FLAGS_fallback_dns_port));
    if (!temp_fallback_dns.ok()) {
      LOG(ERROR) << "Error initiating fallback DNS connection: "
        << temp_fallback_dns.status();
      fallback_dns = nullptr;
    } else {
      fallback_dns = std::move(*temp_fallback_dns);
    }
  }
  absl::StatusOr<std::shared_ptr<DnsServer>> dns_server =
    DnsServer::Create(
        absl::GetFlag(FLAGS_addr),
        absl::GetFlag(FLAGS_dns_port),
        std::move(fallback_dns), record_store);
  CHECK_OK(dns_server);
  auto dns_thread = std::thread([&]{ (*dns_server)->Wait(); });

  LOG(INFO) << "Starting DNS Admin gRPC server: "
    << absl::GetFlag(FLAGS_addr) << ":" << absl::GetFlag(FLAGS_admin_port);
  absl::StatusOr<std::shared_ptr<Client>> dns_server_client = Client::Create(
      absl::GetFlag(FLAGS_addr),
      absl::GetFlag(FLAGS_addr),
      absl::GetFlag(FLAGS_dns_port));
  if (!dns_server_client.ok()) {
    LOG(ERROR) << "Unable to create client connection to local server: "
      << dns_server_client.status();
    exit(1);
  }
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();
  grpc::ServerBuilder builder;
  DnsAdminServiceImpl admin_service(record_store, std::move(*dns_server_client));
  builder.RegisterService(&admin_service);
  std::string admin_address = absl::StrCat(
      absl::GetFlag(FLAGS_addr), ":", absl::GetFlag(FLAGS_admin_port));
  builder.AddListeningPort(admin_address, grpc::InsecureServerCredentials());
  std::unique_ptr<grpc::Server> admin_server(builder.BuildAndStart());
  auto admin_thread = std::thread([&]{ admin_server->Wait(); });

  LOG(INFO) << "Initialization complete.";
  dns_thread.join();
  admin_thread.join();

  return 0;
}
