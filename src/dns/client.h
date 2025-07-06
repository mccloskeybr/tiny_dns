#ifndef SRC_DNS_CLIENT_H_
#define SRC_DNS_CLIENT_H_

#include <cstdint>
#include <memory>
#include <utility>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "absl/log/log.h"
#include "absl/strings/str_cat.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"

// Represents a UDP connection with an external server.
// Not thread safe; intended to be owned by a single thread.
class Client {
 public:
  Client(int32_t socket_fd, struct sockaddr_in dest_addr)
    : socket_fd_(socket_fd), dest_addr_(dest_addr) {}
  ~Client() { close(socket_fd_); }

  static absl::StatusOr<std::shared_ptr<Client>> Create(
      std::string local_address, std::string client_address, int32_t client_port) {
    int32_t socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
      return absl::FailedPreconditionError(
          absl::StrCat("Unable to open socket: ", socket_fd));
    }

    struct sockaddr_in src_addr;
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.sin_family = AF_INET;
    src_addr.sin_port = htons(0);
    if (inet_pton(AF_INET, local_address.c_str(), &src_addr.sin_addr) <= 0) {
      return absl::FailedPreconditionError(
          absl::StrCat("Unable to translate address: ", local_address));
    }
    if (int32_t status = bind(
        socket_fd, (struct sockaddr*) &src_addr, sizeof(src_addr)); status < 0) {
      close(socket_fd);
      return absl::FailedPreconditionError(
          absl::StrCat("Unable to bind to: ", local_address));
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(client_port);
    if (inet_pton(AF_INET, client_address.c_str(), &dest_addr.sin_addr) <= 0) {
      close(socket_fd);
      return absl::FailedPreconditionError(
          absl::StrCat("Unable to translate address: ", client_address));
    }

    return std::make_shared<Client>(socket_fd, dest_addr);
  }

  template<size_t N, size_t M>
  absl::Status Call(const std::array<uint8_t, N>& request, std::array<uint8_t, M>& response) {
    if (sendto(socket_fd_, request.data(), sizeof(request), 0,
          (const struct sockaddr*) &dest_addr_, sizeof(dest_addr_)) < 0) {
      return absl::FailedPreconditionError(
          absl::StrCat("Error sending data to client server."));
    }

    socklen_t addr_len = sizeof(dest_addr_);
    if (recvfrom(socket_fd_, response.data(), sizeof(response), MSG_WAITALL,
          (struct sockaddr*) &dest_addr_, &addr_len) < 0) {
      return absl::FailedPreconditionError(
          absl::StrCat("Error receiving data from client server."));
    }
    return absl::OkStatus();
  }

 private:
  const int32_t socket_fd_;
  const struct sockaddr_in dest_addr_;
};

#endif // SRC_DNS_CLIENT_H_
