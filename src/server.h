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

// Triages and serves incoming requests.
class Server {
 public:
  Server(int32_t socket_fd, std::shared_ptr<Client> dns_client)
    : socket_fd_(socket_fd), dns_client_(std::move(dns_client)) {};
  ~Server() { close(socket_fd_); }

  static absl::StatusOr<std::shared_ptr<Server>> Create(
      int32_t server_port, std::string dns_addr, int32_t dns_port);

  bool Serve();

 private:
  absl::StatusOr<DnsPacket> Lookup(DnsPacket& request);

  int32_t socket_fd_;
  struct sockaddr_in src_addr_;
  std::shared_ptr<Client> dns_client_;
};

#endif // SRC_SERVER_H_
