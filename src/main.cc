#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "absl/flags/parse.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/log/check.h"
#include "src/dns_packet.h"

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  // NOTE: create socket
  int sock_fd;
  if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    LOG(ERROR) << "Unable to create socket.";
    exit(1);
  }

  // NOTE: connect to server
  struct sockaddr_in dest_addr;
  memset(&dest_addr, 0, sizeof(dest_addr));
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(53);
  if (inet_pton(AF_INET, "8.8.8.8", &dest_addr.sin_addr) <= 0) {
    LOG(ERROR) << "Invalid address";
    close(sock_fd);
    exit(1);
  }

  // NOTE: send to server
  DnsPacket request = {};
  request.header.id = 6666;
  request.header.question_count = 1;
  request.header.recursion_desired = true;
  request.questions.push_back(Question {
        .qname = {"google", "com"},
        .qtype = QueryType::A,
      });
  LOG(INFO) << "Sending packet: " << request.DebugString();
  absl::StatusOr<std::array<uint8_t, 512>> request_raw = request.ToBytes();
  CHECK_OK(request_raw);
  if (sendto(sock_fd, request_raw->data(), 512, 0,
        (const struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
    LOG(ERROR) << "sendto failed";
    close(sock_fd);
    exit(1);
  }

  // NOTE: receive from server
  socklen_t addr_len = sizeof(dest_addr);
  std::array<uint8_t, 512> response_raw = {0};
  if (recvfrom(sock_fd, response_raw.data(), 512, 0,
        (struct sockaddr*)&dest_addr, &addr_len) < 0) {
    LOG(ERROR) << "recvfrom failed";
    close(sock_fd);
    exit(1);
  }
  absl::StatusOr<DnsPacket> response = DnsPacket::FromBytes(response_raw);
  CHECK_OK(response);
  LOG(INFO) << "Received packet: " << response->DebugString();

  close(sock_fd);
  return 0;
}
