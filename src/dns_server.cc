#include "src/dns_server.h"

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

absl::StatusOr<std::shared_ptr<DnsServer>>
DnsServer::Create(std::string server_addr, int32_t server_port,
                  std::shared_ptr<Client> fallback_dns) {
  int32_t socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (socket_fd < 0) {
    return absl::FailedPreconditionError(
        absl::StrCat("Unable to open socket: ", socket_fd));
  }

  struct sockaddr_in src_addr;
  memset(&src_addr, 0, sizeof(src_addr));
  src_addr.sin_family = AF_INET;
  src_addr.sin_port = htons(server_port);
  inet_pton(AF_INET, server_addr.c_str(), &src_addr.sin_addr);
  if (int32_t status = bind(socket_fd, (struct sockaddr*) &src_addr,
        sizeof(src_addr)); status < 0) {
    close(socket_fd);
    return absl::FailedPreconditionError(
        absl::StrCat("Unable to bind to localhost."));
  }
  return std::make_shared<DnsServer>(socket_fd, std::move(fallback_dns));
}

void DnsServer::Wait() {
  while (true) {
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    std::array<uint8_t, 512> request_raw = {};
    if (recvfrom(socket_fd_, request_raw.data(), sizeof(request_raw), MSG_WAITALL,
          (struct sockaddr*) &client_addr, &client_addr_len) < 0) {
      LOG(ERROR) << "Error receiving request.";
      continue;
    }

    // TODO: delegate to separate thread.
    LOG(INFO) << "Serving request for: " << inet_ntoa(client_addr.sin_addr);
    absl::StatusOr<std::array<uint8_t, 512>> response_raw = HandleRequest(request_raw);
    if (!response_raw.ok()) {
      LOG(ERROR) << "Error serving request: " << response_raw.status();
      continue;
    }
    if (sendto(socket_fd_, response_raw->data(), sizeof(*response_raw), 0,
          (const struct sockaddr*) &client_addr, sizeof(client_addr)) < 0) {
      LOG(ERROR) << "Unable to send response back to the client.";
      continue;
    }
  }
}

absl::StatusOr<std::array<uint8_t, 512>> DnsServer::HandleRequest(
    std::array<uint8_t, 512>& request_raw) {
  ASSIGN_OR_RETURN(DnsPacket request, DnsPacket::FromBytes(request_raw));
  absl::StatusOr<DnsPacket> response;
  response = Lookup(request);
  if (!response.ok() && request.header.recursion_desired) {
    LOG(ERROR) << "Error retrieving results locally: " << response.status();
    response = Forward(request);
  }
  if (!response.ok()) {
    LOG(ERROR) << "Returning SERV_FAIL response.";
    DnsPacket err_response = {};
    err_response.header.id = request.header.id;
    err_response.header.query_response = true;
    err_response.header.response_code = ResponseCode::SERV_FAIL;
    return err_response.ToBytes();
  }
  return response->ToBytes();
}

absl::StatusOr<DnsPacket> DnsServer::Lookup(DnsPacket& request) {
  return absl::UnimplementedError("error");
}

absl::StatusOr<DnsPacket> DnsServer::Forward(DnsPacket& request) {
  if (fallback_dns_ == nullptr) {
    return absl::UnavailableError("Fallback DNS is not configured.");
  }
  LOG(INFO) << "Forwarding request to fallback DNS server.";
  ASSIGN_OR_RETURN(auto request_raw, request.ToBytes());
  std::array<uint8_t, 512> response_raw = {};
  RETURN_IF_ERROR(fallback_dns_->Call(request_raw, response_raw));
  return DnsPacket::FromBytes(response_raw);
}
