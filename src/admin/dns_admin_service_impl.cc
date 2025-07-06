#include "src/admin/dns_admin_service_impl.h"

#include <cstdint>
#include <memory>

#include "absl/strings/numbers.h"
#include "absl/strings/str_split.h"
#include "grpcpp/grpcpp.h"
#include "src/admin/dns_admin_service.grpc.pb.h"
#include "src/common/record_store.h"
#include "src/dns/dns_packet.h"

grpc::Status DnsAdminServiceImpl::InsertOrUpdate(
    grpc::ServerContext* context,
    const proto::InsertOrUpdateRequest* request,
    proto::InsertOrUpdateResponse* response) {
  const proto::Record& proto_record = request->record();

  Record record = {};
  record.qname = proto_record.qname();
  record.qtype = QueryTypeFromShort((uint16_t) proto_record.qtype());
  record.dns_class = 1;
  record.ttl = (uint16_t) proto_record.ttl();
  switch (proto_record.data_case()) {
    case proto::Record::kA: {
      const std::vector<std::string> addr =
        absl::StrSplit(proto_record.a().addr(), ".");
      if (addr.size() != 4) {
        return grpc::Status(
            grpc::StatusCode::INVALID_ARGUMENT,
            "Data type A requires exactly 4 elements.");
      }
      Record::A data = {};
      for (size_t i = 0; i < 4; i++) {
        int32_t part = 0;
        if (!absl::SimpleAtoi(addr[i], &part)) {
          return grpc::Status(
              grpc::StatusCode::INVALID_ARGUMENT,
              absl::StrCat("Unable to parse IPv4 address from: ", proto_record.a().addr()));
        }
        if (part > std::numeric_limits<uint8_t>::max()) {
          return grpc::Status(
              grpc::StatusCode::INVALID_ARGUMENT,
              absl::StrCat("IPv4 part is greater than uint8 max: ", part));
        }
        data.ip_address[i] = (uint8_t) part;
      }
      record.data = data;
    } break;
    default: {
      return grpc::Status(
          grpc::StatusCode::INVALID_ARGUMENT,
          "Unrecognized record data type provided.");
    } break;
  }
  record_store_->InsertOrUpdate(std::move(record));
  return grpc::Status::OK;
}
