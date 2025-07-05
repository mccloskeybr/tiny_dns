#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/log/check.h"
#include "src/client.h"
#include "src/dns_server.h"

ABSL_FLAG(std::string, dns_addr, "localhost",
          "Address to serve UDP DNS lookups.");
ABSL_FLAG(int32_t, dns_port, 4000,
          "Port to serve UDP DNS lookups.");
ABSL_FLAG(std::string, fallback_dns_addr, "8.8.8.8",
          "If not empty, will forward failed resolution requests to this server.");
ABSL_FLAG(int32_t, fallback_dns_port, 53,
          "fallback DNS server port.");

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  std::shared_ptr<Client> fallback_dns = nullptr;
  if (!absl::GetFlag(FLAGS_fallback_dns_addr).empty()) {
    absl::StatusOr<std::shared_ptr<Client>> temp_fallback_dns = Client::Create(
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

  absl::StatusOr<std::shared_ptr<DnsServer>> dns_server = DnsServer::Create(
      absl::GetFlag(FLAGS_dns_addr), absl::GetFlag(FLAGS_dns_port),
      std::move(fallback_dns));
  CHECK_OK(dns_server);
  (*dns_server)->Wait();

  return 0;
}
