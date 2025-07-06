#ifndef SRC_DNS_SERVER_H_
#define SRC_DNS_SERVER_H_

#include <cstdint>
#include <memory>
#include <utility>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "src/dns/client.h"
#include "src/dns/dns_packet.h"
#include "src/dns/record_store.h"

namespace tiny_dns {

// Triages and serves incoming UDP requests.
class DnsServer {
 public:
  DnsServer(
      int32_t socket_fd, std::shared_ptr<Client> fallback_dns,
      std::shared_ptr<RecordStore> record_store) :
    socket_fd_(socket_fd), fallback_dns_(std::move(fallback_dns)),
    record_store_(record_store) {};
  ~DnsServer() { close(socket_fd_); }
  static absl::StatusOr<std::shared_ptr<DnsServer>> Create(
      std::string server_addr, int32_t server_port,
      std::shared_ptr<Client> fallback_dns,
      std::shared_ptr<RecordStore> record_store);

  void Wait();

 private:
  absl::StatusOr<std::array<uint8_t, 512>> HandleRequest(
      std::array<uint8_t, 512>& request_raw);
  absl::StatusOr<DnsPacket> Lookup(const DnsPacket& request);
  absl::StatusOr<DnsPacket> Forward(const DnsPacket& request);

  DnsPacket CreateResponseTemplate(uint16_t id, ResponseCode response_code);

  int32_t socket_fd_;
  std::shared_ptr<Client> fallback_dns_;
  std::shared_ptr<RecordStore> record_store_;

  friend void ServeRequest(DnsServer*, std::array<uint8_t, 512>, struct sockaddr_in);
};

} // tiny_dns

#endif // SRC_DNS_SERVER_H_
