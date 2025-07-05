#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "absl/flags/parse.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/log/check.h"
#include "src/client.h"
#include "src/server.h"

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  /*
  absl::StatusOr<std::shared_ptr<Client>> client_status_or =
    Client::Create("8.8.8.8", 53);
  CHECK_OK(client_status_or);
  auto client = std::move(*client_status_or);

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

  std::array<uint8_t, 512> response_raw = {0};
  absl::Status call_status = client->Call(*request_raw, response_raw);
  CHECK_OK(call_status);

  absl::StatusOr<DnsPacket> response = DnsPacket::FromBytes(response_raw);
  CHECK_OK(response);
  LOG(INFO) << "Received packet: " << response->DebugString();
  */

  absl::StatusOr<std::shared_ptr<Server>> server_status_or = Server::Create(4000, "8.8.8.8", 53);
  CHECK_OK(server_status_or);
  auto server = std::move(*server_status_or);
  server->Serve();

  return 0;
}
