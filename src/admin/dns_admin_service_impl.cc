#include "src/admin/dns_admin_service_impl.h"

#include <cstdint>
#include <memory>
#include <stdlib.h>

#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "grpcpp/grpcpp.h"
#include "src/admin/dns_admin_service.grpc.pb.h"
#include "src/dns/record_store.h"
#include "src/dns/dns_packet.h"

namespace {

grpc::Status ProtoRecordToRecord(
    const proto::Record& proto_record, Record& record) {
  record = {};
  record.qname = proto_record.qname();
  if (proto_record.qtype() > std::numeric_limits<uint16_t>::max()) {
    return grpc::Status(
        grpc::StatusCode::INVALID_ARGUMENT,
        absl::StrCat("Query type is greater than uint16 max: ", proto_record.qtype()));
  }
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
      record.data = std::move(data);
    } break;
    case proto::Record::kUri: {
      if (proto_record.uri().priority() > std::numeric_limits<uint16_t>::max()) {
        return grpc::Status(
            grpc::StatusCode::INVALID_ARGUMENT,
            absl::StrCat("Priority exceeds uint16 bounds: ", proto_record.uri().priority()));
      }
      if (proto_record.uri().weight() > std::numeric_limits<uint16_t>::max()) {
        return grpc::Status(
            grpc::StatusCode::INVALID_ARGUMENT,
            absl::StrCat("Weight exceeds uint16 bounds: ", proto_record.uri().weight()));
      }
      Record::URI data = {};
      data.priority = (uint16_t) proto_record.uri().priority();
      data.weight = (uint16_t) proto_record.uri().weight();
      data.target = proto_record.uri().target();
      record.data = std::move(data);
    } break;
    default: {
      return grpc::Status(
          grpc::StatusCode::INVALID_ARGUMENT,
          "Unrecognized record data type provided.");
    } break;
  }
  return grpc::Status::OK;
}

// NOTE: returns true if translation is supported, false otherwise.
bool RecordToProtoRecord(
    const Record& record, proto::Record& proto_record) {
  proto_record = {};
  *proto_record.mutable_qname() = record.qname;
  proto_record.set_ttl(record.ttl);
  switch (record.qtype) {
    case QueryType::A: {
      proto_record.set_qtype(proto::QueryType::QUERY_TYPE_A);
      const Record::A& a = std::get<Record::A>(record.data);
      const std::string addr = absl::StrCat(
          a.ip_address[0], ".", a.ip_address[1], ".", a.ip_address[2], ".", a.ip_address[3]);
      *proto_record.mutable_a()->mutable_addr() = addr;
    } break;
    case QueryType::URI: {
      proto_record.set_qtype(proto::QueryType::QUERY_TYPE_URI);
      const Record::URI& uri = std::get<Record::URI>(record.data);
      proto_record.mutable_uri()->set_priority(uri.priority);
      proto_record.mutable_uri()->set_weight(uri.weight);
      *proto_record.mutable_uri()->mutable_target() = uri.target;
    } break;
    default: { return false; }
  }
  return true;
}

grpc::Status ProtoQuestionToQuestion(
    const proto::Question& proto_question, Question& question) {
  question = {};
  question.qname = proto_question.qname();
  if (proto_question.qtype() > std::numeric_limits<uint16_t>::max()) {
    return grpc::Status(
        grpc::StatusCode::INVALID_ARGUMENT,
        absl::StrCat("Query type is greater than uint16 max: ", proto_question.qtype()));
  }
  question.qtype = QueryTypeFromShort((uint16_t) proto_question.qtype());
  question.dns_class = 1;
  return grpc::Status::OK;
}

} // namespace

grpc::Status DnsAdminServiceImpl::InsertOrUpdate(
    grpc::ServerContext* context,
    const proto::InsertOrUpdateRequest* request,
    proto::InsertOrUpdateResponse* response) {
  Record record = {};
  grpc::Status status = ProtoRecordToRecord(request->record(), record);
  if (!status.ok()) {
    LOG(ERROR) << "Error translating proto record to internal record: "
      << status.error_code() << " - " << status.error_message();
    return status;
  }
  record_store_->InsertOrUpdate(std::move(record));
  return grpc::Status::OK;
}

grpc::Status DnsAdminServiceImpl::Lookup(
    grpc::ServerContext* context,
    const proto::LookupRequest* request,
    proto::LookupResponse* response) {
  DnsPacket dns_request = {};
  {
    dns_request.header.id = rand() % std::numeric_limits<uint16_t>::max();
    dns_request.header.recursion_desired = request->recursion_desired();
    Question question = {};
    const grpc::Status status = ProtoQuestionToQuestion(request->question(), question);
    if (!status.ok()) {
      LOG(ERROR) << "Error translating proto question to internal question: "
        << status.error_code() << " - " << status.error_message();
      return status;
    }
    dns_request.questions.push_back(std::move(question));
  }
  const absl::StatusOr<std::array<uint8_t, 512>> dns_request_raw = dns_request.ToBytes();
  if (!dns_request_raw.ok()) {
    return grpc::Status(
        grpc::StatusCode::INTERNAL,
        absl::StrCat("Error generating request packet to forward to DNS server: ", dns_request_raw.status()));
  }
  std::array<uint8_t, 512> dns_response_raw = {};
  const absl::Status forward_status = dns_server_->Call(*dns_request_raw, dns_response_raw);
  if (!forward_status.ok()) {
    return grpc::Status(
        grpc::StatusCode::UNAVAILABLE,
        absl::StrCat("Error forwarding the packet to the DNS server: ", forward_status));
  }
  const absl::StatusOr<DnsPacket> dns_response = DnsPacket::FromBytes(dns_response_raw);
  if (!dns_response.ok()) {
    return grpc::Status(
        grpc::StatusCode::INTERNAL,
        absl::StrCat("Error translating packet from the DNS server: ", dns_response.status()));
  }
  if (dns_response->header.response_code != ResponseCode::NO_ERROR) {
    return grpc::Status(
        grpc::StatusCode::INTERNAL,
        absl::StrCat("Error returned from DNS server: ", ResponseCodeToString(dns_response->header.response_code)));
  }
  for (const Record& answer : dns_response->answers) {
    proto::Record proto_answer;
    if (RecordToProtoRecord(answer, proto_answer)) { *response->mutable_answers()->Add() = proto_answer; }
    else { LOG(WARNING) << "Translation for record is not supported: " << answer.DebugString(); }
  }
  return grpc::Status::OK;
}
