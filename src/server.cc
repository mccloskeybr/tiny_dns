#include "src/server.h"

#include <array>
#include <cstdint>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <utility>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/strings/str_cat.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "src/client.h"
#include "src/dns_packet.h"
#include "src/status_macros.h"

absl::StatusOr<std::shared_ptr<Server>>
Server::Create(int32_t server_port, std::string dns_addr, int32_t dns_port) {
  int32_t socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (socket_fd < 0) {
    return absl::FailedPreconditionError(
        absl::StrCat("Unable to open socket: ", socket_fd));
  }

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(server_port);
  inet_pton(AF_INET, "localhost", &server_addr.sin_addr);
  if (int32_t status = bind(socket_fd, (struct sockaddr*) &server_addr,
        sizeof(server_addr)); status < 0) {
    close(socket_fd);
    return absl::FailedPreconditionError(
        absl::StrCat("Unable to bind to localhost."));
  }

  ASSIGN_OR_RETURN(
      std::shared_ptr<Client> dns_client,
      Client::Create(dns_addr, dns_port));

  return std::make_shared<Server>(socket_fd, std::move(dns_client));
}

bool Server::Serve() {
  while (true) {
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    std::array<uint8_t, 512> request_raw = {};
    if (recvfrom(socket_fd_, request_raw.data(), sizeof(request_raw), MSG_WAITALL,
          (struct sockaddr*) &client_addr, &client_addr_len) < 0) {
      LOG(ERROR) << "Error receiving request.";
      continue;
    }

    LOG(INFO) << "Serving request for: " << ntohs(client_addr.sin_port);

    absl::StatusOr<DnsPacket> request = DnsPacket::FromBytes(request_raw);
    if (!request.ok()) {
      LOG(ERROR) << "Error translating request: " << request.status();
      continue;
    }

    absl::StatusOr<DnsPacket> response = Lookup(*request);
    if (!response.ok()) {
      LOG(ERROR) << "Error forwarding request: " << response.status();
      continue;
    }

    absl::StatusOr<std::array<uint8_t, 512>> response_raw = response->ToBytes();
    if (!response_raw.ok()) {
      LOG(ERROR) << "Error translating response: " << response_raw.status();
      continue;
    }

    if (sendto(socket_fd_, response_raw->data(), sizeof(*response_raw), 0,
          (const struct sockaddr*) &client_addr, sizeof(client_addr)) < 0) {
      LOG(ERROR) << "Error sending response.";
      continue;
    }
  }
}

absl::StatusOr<DnsPacket> Server::Lookup(DnsPacket& request) {
  LOG(INFO) << "Forwarding packet: " << request.DebugString();
  ASSIGN_OR_RETURN(auto request_raw, request.ToBytes());
  std::array<uint8_t, 512> response_raw = {};
  RETURN_IF_ERROR(dns_client_->Call(request_raw, response_raw));
  ASSIGN_OR_RETURN(DnsPacket response, DnsPacket::FromBytes(response_raw));
  LOG(INFO) << "Received response: " << response.DebugString();
  return response;
}
