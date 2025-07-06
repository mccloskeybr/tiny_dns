#include "src/dns/dns_packet.h"

#include <array>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>
#include <utility>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/str_join.h"
#include "src/common/status_macros.h"

absl::StatusOr<uint8_t> BufferReader::ReadU8() {
  if (cursor_ > &bytes_.back()) {
    return absl::InvalidArgumentError(
        "Malformed packet detected! Attempting to read beyond buffer limit.");
  }
  uint8_t result = ((uint8_t) *cursor_);
  cursor_ += 1;
  return result;
}

absl::StatusOr<uint16_t> BufferReader::ReadU16() {
  uint16_t result = 0;
  uint8_t chunk = 0;

  ASSIGN_OR_RETURN(chunk, ReadU8());
  result |= chunk;
  result <<= 8;

  ASSIGN_OR_RETURN(chunk, ReadU8());
  result |= chunk;
  return result;
}

absl::StatusOr<uint32_t> BufferReader::ReadU32() {
  uint32_t result = 0;
  uint8_t chunk = 0;

  ASSIGN_OR_RETURN(chunk, ReadU8());
  result |= chunk;
  result <<= 8;

  ASSIGN_OR_RETURN(chunk, ReadU8());
  result |= chunk;
  result <<= 8;

  ASSIGN_OR_RETURN(chunk, ReadU8());
  result |= chunk;
  result <<= 8;

  ASSIGN_OR_RETURN(chunk, ReadU8());
  result |= chunk;
  return result;
}

absl::StatusOr<std::string>
BufferReader::ReadQName(size_t num_jumps) {
  static const size_t kMaxJumps = 5;
  if (num_jumps > kMaxJumps) {
    return absl::InvalidArgumentError(
        "Attempting to exceed jump protection limit!");
  }

  std::vector<std::string> labels;
  while (true) {
    ASSIGN_OR_RETURN(uint8_t chunk, ReadU8());

    // NOTE: jump, get rest of labels from offset.
    if ((chunk & 0xc0) == 0xc0) {
      const uint8_t a = chunk;
      ASSIGN_OR_RETURN(const uint8_t b, ReadU8());
      const uint16_t offset = (((((uint16_t) a) << 8) | b) ^ 0xc000);

      BufferReader reader(bytes_, offset);
      ASSIGN_OR_RETURN(auto jumped_labels, reader.ReadQName(num_jumps + 1));
      labels.push_back(jumped_labels);
      return absl::StrJoin(labels, ".");
    }

    // NOTE: last byte in label list.
    else if (chunk == 0) { break; }

    // NOTE: read from stream directly.
    else {
      std::string label;
      const uint8_t label_len = chunk;
      label.reserve(label_len);
      // SPEEDUP: read whole string.
      for (uint8_t i = 0; i < label_len; i++) {
        ASSIGN_OR_RETURN(const uint8_t c, ReadU8());
        label += c;
      }
      labels.push_back(label);
    }
  }
  return absl::StrJoin(labels, ".");
}

absl::Status BufferWriter::WriteU8(const uint8_t x) {
  if (cursor_ > &bytes_.back()) {
    return absl::InternalError("Attempting to write beyond buffer limit!");
  }
  *cursor_ = x;
  cursor_++;
  return absl::OkStatus();
}

absl::Status BufferWriter::WriteU16(const uint16_t x) {
  RETURN_IF_ERROR(WriteU8(x >> 8));
  RETURN_IF_ERROR(WriteU8(x >> 0));
  return absl::OkStatus();
}

absl::Status BufferWriter::WriteU32(const uint32_t x) {
  RETURN_IF_ERROR(WriteU8(x >> 24));
  RETURN_IF_ERROR(WriteU8(x >> 16));
  RETURN_IF_ERROR(WriteU8(x >> 8));
  RETURN_IF_ERROR(WriteU8(x >> 0));
  return absl::OkStatus();
}

absl::StatusOr<uint16_t> BufferWriter::WriteQName(const std::string& qname) {
  uint16_t length = 0;
  bool jumped = false;
  std::vector<std::string> labels = absl::StrSplit(qname, ".");
  for (size_t i = 0; i < labels.size(); i++) {
    std::string merged_label = absl::StrJoin(labels.begin() + i, labels.end(), ".");
    if (auto it = label_map_.find(merged_label); it != label_map_.end()) {
      uint16_t jump = 0xc000 | it->second;
      RETURN_IF_ERROR(WriteU16(jump));
      length++;
      jumped = true;
      break;
    }
    label_map_[merged_label] = (uint16_t) (cursor_ - bytes_.begin());
    RETURN_IF_ERROR(WriteU8(labels[i].size()));
    for (uint8_t c : labels[i]) {
      RETURN_IF_ERROR(WriteU8(c));
    }
    length += labels[i].size() + 1;
  }
  if (!jumped) {
    RETURN_IF_ERROR(WriteU8(0));
    length++;
  }
  return length;
}

ResponseCode ResponseCodeFromByte(const uint8_t byte) {
  if (byte > 5) { return ResponseCode::NO_ERROR; }
  return static_cast<ResponseCode>(byte);
}

uint8_t ResponseCodeToByte(const ResponseCode code) {
  return static_cast<uint8_t>(code);
}

std::string ResponseCodeToString(const ResponseCode code) {
  using enum ResponseCode;
  switch (code) {
    case NO_ERROR: return "NO_ERROR";
    case FORM_ERROR: return "FORM_ERROR";
    case SERV_FAIL: return "SERV_FAIL";
    case NX_DOMAIN: return "NX_DOMAIN";
    case NO_TIMP: return "NO_TIMP";
    case REFUSED: return "REFUSED";
    default: CHECK(false); return "";
  }
}

QueryType QueryTypeFromShort(const uint16_t x) {
  using enum QueryType;
  switch (x) {
    case 1: return A;
    case 2: return NS;
    case 5: return CNAME;
    case 15: return MX;
    case 28: return AAAA;
    default: {
      LOG(WARNING) << "Observed unknown QueryType: " << x;
      return UNKNOWN;
    }
  }
}

uint16_t QueryTypeToShort(const QueryType type) {
  return static_cast<uint16_t>(type);
}

std::string QueryTypeToString(const QueryType type) {
  using enum QueryType;
  switch (type) {
    case UNKNOWN: return "UNKNOWN";
    case A: return "A";
    case NS: return "NS";
    case CNAME: return "CNAME";
    case MX: return "MX";
    case AAAA: return "AAAA";
    default: CHECK(false); return "";
  }
}

absl::StatusOr<Header> Header::FromBytes(BufferReader& reader) {
  Header header = {};
  {
    ASSIGN_OR_RETURN(header.id, reader.ReadU16());
  }
  {
    ASSIGN_OR_RETURN(const uint8_t chunk, reader.ReadU8());
    header.recursion_desired = chunk >> 0 & 0b1;
    header.truncated_message = chunk >> 1 & 0b1;
    header.authoritative_answer = chunk >> 2 & 0b1;
    header.op_code = chunk >> 3 & 0b1111;
    header.query_response = chunk >> 7 & 0b1;
  }
  {
    ASSIGN_OR_RETURN(const uint8_t chunk, reader.ReadU8());
    header.response_code = ResponseCodeFromByte(chunk >> 0 & 0b1111);
    header.checking_disabled = chunk >> 4 & 0b1;
    header.authed_data = chunk >> 5 & 0b1;
    header.z = chunk >> 6 & 0b1;
    header.recursion_available = chunk >> 7 & 0b1;
  }
  {
    ASSIGN_OR_RETURN(header.question_count, reader.ReadU16());
    ASSIGN_OR_RETURN(header.answer_count, reader.ReadU16());
    ASSIGN_OR_RETURN(header.authority_count, reader.ReadU16());
    ASSIGN_OR_RETURN(header.additional_count, reader.ReadU16());
  }
  return header;
}

absl::Status Header::ToBytes(BufferWriter& writer) const {
  {
    RETURN_IF_ERROR(writer.WriteU16(id));
  }
  {
    uint8_t chunk = 0;
    chunk |= recursion_desired << 0;
    chunk |= truncated_message << 1;
    chunk |= authoritative_answer << 2;
    chunk |= op_code << 3;
    chunk |= query_response << 7;
    RETURN_IF_ERROR(writer.WriteU8(chunk));
  }
  {
    uint8_t chunk = 0;
    chunk |= ResponseCodeToByte(response_code);
    chunk |= checking_disabled << 4;
    chunk |= authed_data << 5;
    chunk |= z << 6;
    chunk |= recursion_available << 7;
    RETURN_IF_ERROR(writer.WriteU8(chunk));
  }
  {
    RETURN_IF_ERROR(writer.WriteU16(question_count));
    RETURN_IF_ERROR(writer.WriteU16(answer_count));
    RETURN_IF_ERROR(writer.WriteU16(authority_count));
    RETURN_IF_ERROR(writer.WriteU16(additional_count));
  }
  return absl::OkStatus();
}

std::string Header::DebugString() const {
  std::string result;
  result += "{ ";
  result += absl::StrCat("id: ", id, " ");
  result += absl::StrCat("recursion_desired: ", recursion_desired, " ");
  result += absl::StrCat("truncated_message: ", truncated_message, " ");
  result += absl::StrCat("authoritative_answer: ", authoritative_answer, " ");
  result += absl::StrCat("op_code: ", op_code, " ");
  result += absl::StrCat("query_response: ", query_response, " ");
  result += absl::StrCat("response_code: ", ResponseCodeToString(response_code), " ");
  result += absl::StrCat("checking_disabled: ", checking_disabled, " ");
  result += absl::StrCat("authed_data: ", authed_data, " ");
  result += absl::StrCat("z: ", z, " ");
  result += absl::StrCat("recursion_available: ", recursion_available, " ");
  result += absl::StrCat("question_count: ", question_count, " ");
  result += absl::StrCat("answer_count: ", answer_count, " ");
  result += absl::StrCat("authority_count: ", authority_count, " ");
  result += absl::StrCat("additional_count: ", additional_count, " ");
  result += "}";
  return result;
}

absl::StatusOr<Question> Question::FromBytes(BufferReader& reader) {
  Question question = {};
  {
    ASSIGN_OR_RETURN(question.qname, reader.ReadQName());
    ASSIGN_OR_RETURN(const uint16_t qtype_raw, reader.ReadU16());
    question.qtype = QueryTypeFromShort(qtype_raw);
    ASSIGN_OR_RETURN(question.dns_class, reader.ReadU16());
  }
  return question;
}

absl::Status Question::ToBytes(BufferWriter& writer) const {
  RETURN_IF_ERROR(writer.WriteQName(qname).status());
  RETURN_IF_ERROR(writer.WriteU16(QueryTypeToShort(qtype)));
  RETURN_IF_ERROR(writer.WriteU16(dns_class));
  return absl::OkStatus();
}

std::string Question::DebugString() const {
  std::string result;
  result += "{ ";
  result += absl::StrCat("qname: ", qname, " ");
  result += absl::StrCat("qtype: ", QueryTypeToString(qtype), " ");
  result += absl::StrCat("dns_class: ", dns_class, " ");
  result += "}";
  return result;
}

absl::StatusOr<Record> Record::FromBytes(BufferReader& reader) {
  Record answer = {};
  uint16_t length = 0;
  {
    ASSIGN_OR_RETURN(answer.qname, reader.ReadQName());
    ASSIGN_OR_RETURN(const uint16_t qtype_raw, reader.ReadU16());
    answer.qtype = QueryTypeFromShort(qtype_raw);
    ASSIGN_OR_RETURN(answer.dns_class, reader.ReadU16());
    ASSIGN_OR_RETURN(answer.ttl, reader.ReadU32());
    ASSIGN_OR_RETURN(length, reader.ReadU16());
  }
  switch (answer.qtype) {
    case QueryType::A: {
      if (length != 4) {
        LOG(WARNING) << "Unexpected length for type A. Expected 4, got: " << length;
      }
      Record::A a = {};
      ASSIGN_OR_RETURN(a.ip_address[0], reader.ReadU8());
      ASSIGN_OR_RETURN(a.ip_address[1], reader.ReadU8());
      ASSIGN_OR_RETURN(a.ip_address[2], reader.ReadU8());
      ASSIGN_OR_RETURN(a.ip_address[3], reader.ReadU8());
      answer.data = std::move(a);
    } break;
    case QueryType::NS: {
      Record::NS ns = {};
      ASSIGN_OR_RETURN(ns.host, reader.ReadQName());
      answer.data = std::move(ns);
    } break;
    case QueryType::CNAME: {
      Record::CNAME cname = {};
      ASSIGN_OR_RETURN(cname.host, reader.ReadQName());
      answer.data = std::move(cname);
    } break;
    case QueryType::MX: {
      Record::MX mx = {};
      ASSIGN_OR_RETURN(mx.priority, reader.ReadU16());
      ASSIGN_OR_RETURN(mx.host, reader.ReadQName());
      answer.data = std::move(mx);
    } break;
    case QueryType::AAAA: {
      if (length != 16) {
        LOG(WARNING) << "Unexpected length for type AAAA. Expected 16, got: " << length;
      }
      Record::AAAA aaaa = {};
      ASSIGN_OR_RETURN(aaaa.ip_address[0], reader.ReadU16());
      ASSIGN_OR_RETURN(aaaa.ip_address[1], reader.ReadU16());
      ASSIGN_OR_RETURN(aaaa.ip_address[2], reader.ReadU16());
      ASSIGN_OR_RETURN(aaaa.ip_address[3], reader.ReadU16());
      ASSIGN_OR_RETURN(aaaa.ip_address[4], reader.ReadU16());
      ASSIGN_OR_RETURN(aaaa.ip_address[5], reader.ReadU16());
      ASSIGN_OR_RETURN(aaaa.ip_address[6], reader.ReadU16());
      ASSIGN_OR_RETURN(aaaa.ip_address[7], reader.ReadU16());
      answer.data = aaaa;
    } break;
    case QueryType::UNKNOWN: {} break;
    default: { CHECK(false); } break;
  }
  return answer;
}

absl::Status Record::ToBytes(BufferWriter& writer) const {
  {
    RETURN_IF_ERROR(writer.WriteQName(qname).status());
    RETURN_IF_ERROR(writer.WriteU16(QueryTypeToShort(qtype)));
    RETURN_IF_ERROR(writer.WriteU16(dns_class));
    RETURN_IF_ERROR(writer.WriteU32(ttl));
  }
  switch (qtype) {
    case QueryType::A: {
      RETURN_IF_ERROR(writer.WriteU16(4));
      const Record::A& a = std::get<Record::A>(data);
      RETURN_IF_ERROR(writer.WriteU8(a.ip_address[0]));
      RETURN_IF_ERROR(writer.WriteU8(a.ip_address[1]));
      RETURN_IF_ERROR(writer.WriteU8(a.ip_address[2]));
      RETURN_IF_ERROR(writer.WriteU8(a.ip_address[3]));
    } break;
    case QueryType::NS: {
      const Record::NS& ns = std::get<Record::NS>(data);
      BufferWriter len_ptr = writer;
      RETURN_IF_ERROR(writer.WriteU16(0)); // NOTE: write length after label block size is known.
      ASSIGN_OR_RETURN(uint16_t len, writer.WriteQName(ns.host));
      RETURN_IF_ERROR(len_ptr.WriteU16(len));
    } break;
    case QueryType::CNAME: {
      const Record::CNAME& cname = std::get<Record::CNAME>(data);
      BufferWriter len_ptr = writer;
      RETURN_IF_ERROR(writer.WriteU16(0));
      ASSIGN_OR_RETURN(uint16_t len, writer.WriteQName(cname.host));
      RETURN_IF_ERROR(len_ptr.WriteU16(len));
    } break;
    case QueryType::MX: {
      const Record::MX& mx = std::get<Record::MX>(data);
      BufferWriter len_ptr = writer;
      RETURN_IF_ERROR(writer.WriteU16(0));
      RETURN_IF_ERROR(writer.WriteU16(mx.priority));
      ASSIGN_OR_RETURN(uint16_t len, writer.WriteQName(mx.host));
      RETURN_IF_ERROR(len_ptr.WriteU16(2 + len));
    } break;
    case QueryType::AAAA: {
      const Record::AAAA& aaaa = std::get<Record::AAAA>(data);
      RETURN_IF_ERROR(writer.WriteU16(16));
      RETURN_IF_ERROR(writer.WriteU16(aaaa.ip_address[0]));
      RETURN_IF_ERROR(writer.WriteU16(aaaa.ip_address[1]));
      RETURN_IF_ERROR(writer.WriteU16(aaaa.ip_address[2]));
      RETURN_IF_ERROR(writer.WriteU16(aaaa.ip_address[3]));
      RETURN_IF_ERROR(writer.WriteU16(aaaa.ip_address[4]));
      RETURN_IF_ERROR(writer.WriteU16(aaaa.ip_address[5]));
      RETURN_IF_ERROR(writer.WriteU16(aaaa.ip_address[6]));
      RETURN_IF_ERROR(writer.WriteU16(aaaa.ip_address[7]));
    } break;
    case QueryType::UNKNOWN: {} break;
    default: CHECK(false); break;
  }
  return absl::OkStatus();
}

std::string Record::DebugString() const {
  std::string result;
  result += "{ ";
  result += absl::StrCat("qname: ", qname, " ");
  result += absl::StrCat("qtype: ", QueryTypeToString(qtype), " ");
  result += absl::StrCat("dns_class: ", dns_class, " ");
  result += absl::StrCat("ttl: ", ttl, " ");
  switch (qtype) {
    case QueryType::A: {
      const std::array<uint8_t, 4>& addr = std::get<Record::A>(data).ip_address;
      result += absl::StrCat("IPv4: ", addr[0], ".", addr[1], ".", addr[2], ".", addr[3], " ");
    } break;
    case QueryType::NS: {
      result += absl::StrCat("NS host: ", std::get<Record::NS>(data).host, " ");
    } break;
    case QueryType::CNAME: {
      result += absl::StrCat("CNAME host: ", std::get<Record::CNAME>(data).host, " ");
    } break;
    case QueryType::MX: {
      result += absl::StrCat("MX priority: ", std::get<Record::MX>(data).priority, " ");
      result += absl::StrCat("MX host: ", std::get<Record::MX>(data).host, " ");
    } break;
    case QueryType::AAAA: {
      const std::array<uint16_t, 8>& addr = std::get<Record::AAAA>(data).ip_address;
      result += absl::StrFormat(
          "IPv6: %0x:%0x:%0x:%0x:%0x:%0x:%0x:%0x ",
          addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7]);
    } break;
    case QueryType::UNKNOWN: {} break;
    default: CHECK(false); break;
  }
  result += "}";
  return result;
}

absl::StatusOr<DnsPacket> DnsPacket::FromBytes(
    const std::array<uint8_t, 512>& bytes) {
  BufferReader reader(bytes);
  DnsPacket packet = {};

  ASSIGN_OR_RETURN(packet.header, Header::FromBytes(reader));
  packet.questions.reserve(packet.header.question_count);
  packet.answers.reserve(packet.header.answer_count);
  packet.authorities.reserve(packet.header.authority_count);
  packet.additional.reserve(packet.header.additional_count);

  for (size_t i = 0; i < packet.header.question_count; i++) {
    ASSIGN_OR_RETURN(Question question, Question::FromBytes(reader));
    packet.questions.push_back(std::move(question));
  }
  for (size_t i = 0; i < packet.header.answer_count; i++) {
    ASSIGN_OR_RETURN(Record record, Record::FromBytes(reader));
    packet.answers.push_back(std::move(record));
  }
  for (size_t i = 0; i < packet.header.authority_count; i++) {
    ASSIGN_OR_RETURN(Record record, Record::FromBytes(reader));
    packet.authorities.push_back(std::move(record));
  }
  for (size_t i = 0; i < packet.header.additional_count; i++) {
    ASSIGN_OR_RETURN(Record record, Record::FromBytes(reader));
    packet.additional.push_back(std::move(record));
  }

  return packet;
}

absl::StatusOr<std::array<uint8_t, 512>> DnsPacket::ToBytes() {
  std::array<uint8_t, 512> bytes = {};
  BufferWriter writer(bytes);

  header.question_count = questions.size();
  header.answer_count = answers.size();
  header.authority_count = authorities.size();
  header.additional_count = additional.size();
  RETURN_IF_ERROR(header.ToBytes(writer));

  for (const Question& question : questions) {
    RETURN_IF_ERROR(question.ToBytes(writer));
  }
  for (const Record& record : answers) {
    RETURN_IF_ERROR(record.ToBytes(writer));
  }
  for (const Record& record : authorities) {
    RETURN_IF_ERROR(record.ToBytes(writer));
  }
  for (const Record& record : additional) {
    RETURN_IF_ERROR(record.ToBytes(writer));
  }

  return bytes;
}

std::string DnsPacket::DebugString() const {
  std::string result;
  result += "{ ";

  result += "Header: ";
  result += header.DebugString() + " ";

  result += "Questions: [ ";
  for (const Question& question : questions) {
    result += question.DebugString() + " ";
  }
  result += " ] ";

  result += "Answers: [ ";
  for (const Record& record : answers) {
    result += record.DebugString() + " ";
  }
  result += " ] ";

  result += "Authorities: [ ";
  for (const Record& record : authorities) {
    result += record.DebugString() + " ";
  }
  result += " ] ";

  result += "Additional: [ ";
  for (const Record& record : additional) {
    result += record.DebugString() + " ";
  }
  result += " ] ";

  result += "}";
  return result;
}
