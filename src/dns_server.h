#ifndef SRC_SERVER_H_
#define SRC_SERVER_H_

#include <cstdint>
#include <memory>
#include <utility>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "src/client.h"
#include "src/dns_packet.h"

// Triages and serves incoming UDP requests.
class DnsServer {
 public:
  DnsServer(int32_t socket_fd, std::shared_ptr<Client> fallback_dns)
    : socket_fd_(socket_fd), fallback_dns_(std::move(fallback_dns)) {};
  ~DnsServer() { close(socket_fd_); }
  static absl::StatusOr<std::shared_ptr<DnsServer>> Create(
      std::string server_addr, int32_t server_port,
      std::shared_ptr<Client> fallback_dns);

  void Wait();

 private:
  absl::StatusOr<std::array<uint8_t, 512>> HandleRequest(
      std::array<uint8_t, 512>& request_raw);
  absl::StatusOr<DnsPacket> Lookup(DnsPacket& request);
  absl::StatusOr<DnsPacket> Forward(DnsPacket& request);

  int32_t socket_fd_;
  struct sockaddr_in src_addr_;
  std::shared_ptr<Client> fallback_dns_;
};

#endif // SRC_SERVER_H_
