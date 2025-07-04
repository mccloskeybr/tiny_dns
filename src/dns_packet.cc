#include "src/dns_packet.h"

#include <cstdint>
#include <string>
#include <vector>
#include <utility>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "src/status_macros.h"

absl::StatusOr<uint8_t> BufferReader::ReadByte() {
  if (cursor_ > &bytes_.back()) {
    return absl::InvalidArgumentError(
        "Malformed packet detected! Attempting to read beyond buffer limit.");
  }
  uint8_t result = ((uint8_t) *cursor_);
  cursor_ += 1;
  return result;
}

absl::StatusOr<uint16_t> BufferReader::Read2Bytes() {
  uint16_t result = 0;
  uint8_t chunk = 0;

  ASSIGN_OR_RETURN(chunk, ReadByte());
  result |= chunk;
  result <<= 8;

  ASSIGN_OR_RETURN(chunk, ReadByte());
  result |= chunk;

  return result;
}

absl::StatusOr<uint32_t> BufferReader::Read4Bytes() {
  uint32_t result = 0;
  uint8_t chunk = 0;

  ASSIGN_OR_RETURN(chunk, ReadByte());
  result |= chunk;
  result <<= 8;

  ASSIGN_OR_RETURN(chunk, ReadByte());
  result |= chunk;
  result <<= 8;

  ASSIGN_OR_RETURN(chunk, ReadByte());
  result |= chunk;
  result <<= 8;

  ASSIGN_OR_RETURN(chunk, ReadByte());
  result |= chunk;

  return result;
}

absl::StatusOr<std::vector<std::string>>
BufferReader::ReadLabels(size_t num_jumps) {
  static const size_t kMaxJumps = 5;
  if (num_jumps > kMaxJumps) {
    return absl::InvalidArgumentError(
        "Attempting to exceed jump protection limit!");
  }

  std::vector<std::string> labels;
  while (true) {
    ASSIGN_OR_RETURN(uint8_t chunk, ReadByte());

    // NOTE: jump, get rest of labels from offset.
    if ((chunk & 0xc0) == 0xc0) {
      uint8_t a = chunk;
      ASSIGN_OR_RETURN(uint8_t b, ReadByte());
      uint16_t offset = (((((uint16_t) a) << 8) | b) ^ 0xc000);

      BufferReader reader(bytes_, offset);
      ASSIGN_OR_RETURN(auto jumped_labels, reader.ReadLabels(num_jumps + 1));
      labels.insert(labels.end(), jumped_labels.begin(), jumped_labels.end());
      return labels;
    }

    // NOTE: last byte in label list.
    else if (chunk == 0) { return labels; }

    // NOTE: read from stream directly.
    else {
      std::string label;
      uint8_t label_len = chunk;
      label.reserve(label_len);
      // SPEEDUP: read whole string.
      for (uint8_t i = 0; i < label_len; i++) {
        ASSIGN_OR_RETURN(uint8_t c, ReadByte());
        label += c;
      }
      labels.push_back(label);
    }
  }
  return labels;
}

absl::Status BufferWriter::WriteByte(uint8_t x) {
  if (cursor_ > &bytes_.back()) {
    return absl::InternalError("Attempting to write beyond buffer limit!");
  }
  *cursor_ = x;
  cursor_++;
  return absl::OkStatus();
}

absl::Status BufferWriter::Write2Bytes(uint16_t x) {
  RETURN_IF_ERROR(WriteByte(x >> 8));
  RETURN_IF_ERROR(WriteByte(x >> 0));
  return absl::OkStatus();
}

absl::Status BufferWriter::Write4Bytes(uint32_t x) {
  RETURN_IF_ERROR(WriteByte(x >> 24));
  RETURN_IF_ERROR(WriteByte(x >> 16));
  RETURN_IF_ERROR(WriteByte(x >> 8));
  RETURN_IF_ERROR(WriteByte(x >> 0));
  return absl::OkStatus();
}

absl::StatusOr<uint16_t> BufferWriter::WriteLabels(const std::vector<std::string>& labels) {
  uint16_t length = 0;
  for (const std::string& label : labels) {
    if (label.size() > 0x3f) {
      return absl::InternalError("Label length is greater than 63!");
    }
    RETURN_IF_ERROR(WriteByte(label.size()));
    for (uint8_t c : label) {
      RETURN_IF_ERROR(WriteByte(c));
    }
    length += label.size() + 1;
  }
  RETURN_IF_ERROR(WriteByte(0));
  length++;
  return length;
}

std::array<uint8_t, 512> BufferWriter::GetBytes() {
  return bytes_;
}

ResponseCode ResponseCodeFromByte(uint8_t byte) {
  if (byte > 5) { return ResponseCode::NO_ERROR; }
  return static_cast<ResponseCode>(byte);
}

uint8_t ResponseCodeToByte(ResponseCode code) {
  return static_cast<uint8_t>(code);
}

std::string ResponseCodeToString(ResponseCode code) {
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

QueryType QueryTypeFromShort(uint16_t x) {
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

uint16_t QueryTypeToShort(QueryType type) {
  return static_cast<uint16_t>(type);
}

std::string QueryTypeToString(QueryType type) {
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

std::string QNameAssemble(const std::vector<std::string>& qname) {
  std::string result;
  for (size_t i = 0; i < qname.size(); i++) {
    result += qname[i];
    if (i < qname.size() - 1) { result += "."; }
  }
  return result;
}

absl::StatusOr<Header> Header::FromBytes(BufferReader& reader) {
  Header header = {};
  {
    ASSIGN_OR_RETURN(header.id, reader.Read2Bytes());
  }
  {
    ASSIGN_OR_RETURN(uint8_t chunk, reader.ReadByte());
    header.recursion_desired = chunk >> 0 & 0b1;
    header.truncated_message = chunk >> 1 & 0b1;
    header.authoritative_answer = chunk >> 2 & 0b1;
    header.op_code = chunk >> 3 & 0b1111;
    header.query_response = chunk >> 7 & 0b1;
  }
  {
    ASSIGN_OR_RETURN(uint8_t chunk, reader.ReadByte());
    header.response_code = ResponseCodeFromByte(chunk >> 0 & 0b1111);
    header.checking_disabled = chunk >> 4 & 0b1;
    header.authed_data = chunk >> 5 & 0b1;
    header.z = chunk >> 6 & 0b1;
    header.recursion_available = chunk >> 7 & 0b1;
  }
  {
    ASSIGN_OR_RETURN(header.question_count, reader.Read2Bytes());
    ASSIGN_OR_RETURN(header.answer_count, reader.Read2Bytes());
    ASSIGN_OR_RETURN(header.authority_count, reader.Read2Bytes());
    ASSIGN_OR_RETURN(header.additional_count, reader.Read2Bytes());
  }
  return header;
}

absl::Status Header::ToBytes(BufferWriter& writer) {
  {
    RETURN_IF_ERROR(writer.Write2Bytes(id));
  }
  {
    uint8_t chunk = 0;
    chunk |= recursion_desired << 0;
    chunk |= truncated_message << 1;
    chunk |= authoritative_answer << 2;
    chunk |= op_code << 3;
    chunk |= query_response << 7;
    RETURN_IF_ERROR(writer.WriteByte(chunk));
  }
  {
    uint8_t chunk = 0;
    chunk |= ResponseCodeToByte(response_code);
    chunk |= checking_disabled << 4;
    chunk |= authed_data << 5;
    chunk |= z << 6;
    chunk |= recursion_available << 7;
    RETURN_IF_ERROR(writer.WriteByte(chunk));
  }
  {
    RETURN_IF_ERROR(writer.Write2Bytes(question_count));
    RETURN_IF_ERROR(writer.Write2Bytes(answer_count));
    RETURN_IF_ERROR(writer.Write2Bytes(authority_count));
    RETURN_IF_ERROR(writer.Write2Bytes(additional_count));
  }
  return absl::OkStatus();
}

std::string Header::DebugString() {
  std::string result;
  result += absl::StrCat("id: ", id, "\n");
  result += absl::StrCat("recursion_desired: ", recursion_desired, "\n");
  result += absl::StrCat("truncated_message: ", truncated_message, "\n");
  result += absl::StrCat("authoritative_answer: ", authoritative_answer, "\n");
  result += absl::StrCat("op_code: ", op_code, "\n");
  result += absl::StrCat("query_response: ", query_response, "\n");
  result += absl::StrCat("response_code: ", ResponseCodeToString(response_code), "\n");
  result += absl::StrCat("checking_disabled: ", checking_disabled, "\n");
  result += absl::StrCat("authed_data: ", authed_data, "\n");
  result += absl::StrCat("z: ", z, "\n");
  result += absl::StrCat("recursion_available: ", recursion_available, "\n");
  result += absl::StrCat("question_count: ", question_count, "\n");
  result += absl::StrCat("answer_count: ", answer_count, "\n");
  result += absl::StrCat("authority_count: ", authority_count, "\n");
  result += absl::StrCat("additional_count: ", additional_count, "\n");
  return result;
}

absl::StatusOr<Question> Question::FromBytes(BufferReader& reader) {
  Question question = {};
  {
    ASSIGN_OR_RETURN(question.qname, reader.ReadLabels());
    ASSIGN_OR_RETURN(uint16_t qtype_raw, reader.Read2Bytes());
    question.qtype = QueryTypeFromShort(qtype_raw);
    ASSIGN_OR_RETURN(question.dns_class, reader.Read2Bytes());
  }
  return question;
}

absl::Status Question::ToBytes(BufferWriter& writer) {
  RETURN_IF_ERROR(writer.WriteLabels(qname).status());
  RETURN_IF_ERROR(writer.Write2Bytes(QueryTypeToShort(qtype)));
  RETURN_IF_ERROR(writer.Write2Bytes(dns_class));
  return absl::OkStatus();
}

std::string Question::DebugString() {
  std::string result;
  result += absl::StrCat("qname: ", QNameAssemble(qname), "\n");
  result += absl::StrCat("qtype: ", QueryTypeToString(qtype), "\n");
  result += absl::StrCat("dns_class: ", dns_class, "\n");
  return result;
}

absl::StatusOr<Record> Record::FromBytes(BufferReader& reader) {
  Record answer = {};
  uint16_t length = 0;
  {
    ASSIGN_OR_RETURN(answer.qname, reader.ReadLabels());
    ASSIGN_OR_RETURN(uint16_t qtype_raw, reader.Read2Bytes());
    answer.qtype = QueryTypeFromShort(qtype_raw);
    ASSIGN_OR_RETURN(answer.dns_class, reader.Read2Bytes());
    ASSIGN_OR_RETURN(answer.ttl, reader.Read4Bytes());
    ASSIGN_OR_RETURN(length, reader.Read2Bytes());
  }

  switch (answer.qtype) {
    case QueryType::A: {
      if (length != 4) {
        LOG(WARNING) << absl::StrCat("Unexpected length for type A. Expected 4, got: ", length);
      }
      Record::A a = {};
      ASSIGN_OR_RETURN(uint32_t raw, reader.Read4Bytes());
      a.ip_address[0] = (uint8_t) ((raw >> 24) & 0xff);
      a.ip_address[1] = (uint8_t) ((raw >> 16) & 0xff);
      a.ip_address[2] = (uint8_t) ((raw >> 8)  & 0xff);
      a.ip_address[3] = (uint8_t) ((raw >> 0)  & 0xff);
      answer.data = std::move(a);
    } break;
    case QueryType::NS: {
      Record::NS ns = {};
      ASSIGN_OR_RETURN(ns.host, reader.ReadLabels());
      answer.data = std::move(ns);
    } break;
    case QueryType::CNAME: {
      Record::CNAME cname = {};
      ASSIGN_OR_RETURN(cname.host, reader.ReadLabels());
      answer.data = std::move(cname);
    } break;
    case QueryType::MX: {
      Record::MX mx = {};
      ASSIGN_OR_RETURN(mx.priority, reader.Read2Bytes());
      ASSIGN_OR_RETURN(mx.host, reader.ReadLabels());
      answer.data = std::move(mx);
    } break;
    case QueryType::AAAA: {
      if (length != 16) {
        LOG(WARNING) << absl::StrCat("Unexpected length for type AAAA. Expected 16, got: ", length);
      }
      Record::AAAA aaaa = {};
      uint32_t chunk;
      ASSIGN_OR_RETURN(chunk, reader.Read2Bytes());
      aaaa.ip_address[0] = chunk;
      ASSIGN_OR_RETURN(chunk, reader.Read2Bytes());
      aaaa.ip_address[1] = chunk;
      ASSIGN_OR_RETURN(chunk, reader.Read2Bytes());
      aaaa.ip_address[2] = chunk;
      ASSIGN_OR_RETURN(chunk, reader.Read2Bytes());
      aaaa.ip_address[3] = chunk;
      ASSIGN_OR_RETURN(chunk, reader.Read2Bytes());
      aaaa.ip_address[4] = chunk;
      ASSIGN_OR_RETURN(chunk, reader.Read2Bytes());
      aaaa.ip_address[5] = chunk;
      ASSIGN_OR_RETURN(chunk, reader.Read2Bytes());
      aaaa.ip_address[6] = chunk;
      ASSIGN_OR_RETURN(chunk, reader.Read2Bytes());
      aaaa.ip_address[7] = chunk;
      answer.data = std::move(aaaa);
    } break;
    case QueryType::UNKNOWN: {} break;
    default: { CHECK(false); } break;
  }

  return answer;
}

absl::Status Record::ToBytes(BufferWriter& writer) {
  {
    RETURN_IF_ERROR(writer.WriteLabels(qname).status());
    RETURN_IF_ERROR(writer.Write2Bytes(QueryTypeToShort(qtype)));
    RETURN_IF_ERROR(writer.Write2Bytes(dns_class));
    RETURN_IF_ERROR(writer.Write4Bytes(ttl));
  }

  switch (qtype) {
    case QueryType::A: {
      RETURN_IF_ERROR(writer.Write2Bytes(4));
      uint32_t chunk = 0;
      chunk |= std::get<Record::A>(data).ip_address[0] << 24;
      chunk |= std::get<Record::A>(data).ip_address[1] << 16;
      chunk |= std::get<Record::A>(data).ip_address[2] << 8;
      chunk |= std::get<Record::A>(data).ip_address[3] << 0;
      RETURN_IF_ERROR(writer.Write4Bytes(chunk));
    } break;
    case QueryType::NS: {
      BufferWriter len_ptr = writer;
      RETURN_IF_ERROR(writer.Write2Bytes(0)); // NOTE: write length after label block size is known.
      ASSIGN_OR_RETURN(uint16_t len, writer.WriteLabels(std::get<Record::NS>(data).host));
      RETURN_IF_ERROR(len_ptr.Write2Bytes(len));
    } break;
    case QueryType::CNAME: {
      BufferWriter len_ptr = writer;
      RETURN_IF_ERROR(writer.Write2Bytes(0));
      ASSIGN_OR_RETURN(uint16_t len, writer.WriteLabels(std::get<Record::CNAME>(data).host));
      RETURN_IF_ERROR(len_ptr.Write2Bytes(len));
    } break;
    case QueryType::MX: {
      BufferWriter len_ptr = writer;
      RETURN_IF_ERROR(writer.Write2Bytes(0));
      RETURN_IF_ERROR(writer.Write2Bytes(std::get<Record::MX>(data).priority));
      ASSIGN_OR_RETURN(uint16_t len, writer.WriteLabels(std::get<Record::MX>(data).host));
      RETURN_IF_ERROR(len_ptr.Write2Bytes(2 + len));
    } break;
    case QueryType::AAAA: {
      RETURN_IF_ERROR(writer.Write2Bytes(16));
      RETURN_IF_ERROR(writer.Write2Bytes(std::get<Record::AAAA>(data).ip_address[0]));
      RETURN_IF_ERROR(writer.Write2Bytes(std::get<Record::AAAA>(data).ip_address[1]));
      RETURN_IF_ERROR(writer.Write2Bytes(std::get<Record::AAAA>(data).ip_address[2]));
      RETURN_IF_ERROR(writer.Write2Bytes(std::get<Record::AAAA>(data).ip_address[3]));
      RETURN_IF_ERROR(writer.Write2Bytes(std::get<Record::AAAA>(data).ip_address[4]));
      RETURN_IF_ERROR(writer.Write2Bytes(std::get<Record::AAAA>(data).ip_address[5]));
      RETURN_IF_ERROR(writer.Write2Bytes(std::get<Record::AAAA>(data).ip_address[6]));
      RETURN_IF_ERROR(writer.Write2Bytes(std::get<Record::AAAA>(data).ip_address[7]));
    } break;
    case QueryType::UNKNOWN: {} break;
    default: CHECK(false); break;
  }

  return absl::OkStatus();
}

std::string Record::DebugString() {
  std::string result;
  result += absl::StrCat("qname: ", QNameAssemble(qname), "\n");
  result += absl::StrCat("qtype: ", QueryTypeToString(qtype), "\n");
  result += absl::StrCat("dns_class: ", dns_class, "\n");
  result += absl::StrCat("ttl: ", ttl, "\n");

  switch (qtype) {
    case QueryType::A: {
      std::array<uint8_t, 4>& addr = std::get<Record::A>(data).ip_address;
      result += absl::StrCat("IPv4: ", addr[0], ".", addr[1], ".", addr[2], ".", addr[3], "\n");
    } break;
    case QueryType::NS: {
      result += absl::StrCat("NS host: ", QNameAssemble(std::get<Record::NS>(data).host), "\n");
    } break;
    case QueryType::CNAME: {
      result += absl::StrCat("CNAME host: ", QNameAssemble(std::get<Record::CNAME>(data).host), "\n");
    } break;
    case QueryType::MX: {
      result += absl::StrCat("MX priority: ", std::get<Record::MX>(data).priority, "\n");
      result += absl::StrCat("MX host: ", QNameAssemble(std::get<Record::MX>(data).host), "\n");
    } break;
    case QueryType::AAAA: {
      std::array<uint16_t, 8>& addr = std::get<Record::AAAA>(data).ip_address;
      result += absl::StrFormat(
          "IPv6: %0x:%0x:%0x:%0x:%0x:%0x:%0x:%0x\n",
          addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7]);
    } break;
    case QueryType::UNKNOWN: {} break;
    default: CHECK(false); break;
  }

  return result;
}

absl::StatusOr<DnsPacket> DnsPacket::FromBytes(std::array<uint8_t, 512>& bytes) {
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
  BufferWriter writer;

  CHECK_EQ(header.question_count, questions.size());
  CHECK_EQ(header.answer_count, answers.size());
  CHECK_EQ(header.authority_count, authorities.size());
  CHECK_EQ(header.additional_count, additional.size());

  RETURN_IF_ERROR(header.ToBytes(writer));
  for (Question& question : questions) {
    RETURN_IF_ERROR(question.ToBytes(writer));
  }
  for (Record& record : answers) {
    RETURN_IF_ERROR(record.ToBytes(writer));
  }
  for (Record& record : authorities) {
    RETURN_IF_ERROR(record.ToBytes(writer));
  }
  for (Record& record : additional) {
    RETURN_IF_ERROR(record.ToBytes(writer));
  }

  return writer.GetBytes();
}

std::string DnsPacket::DebugString() {
  std::string result;
  result += "{\n";

  result += "Header:\n";
  result += header.DebugString() + "\n";

  result += "Questions:\n";
  for (Question& question : questions) {
    result += question.DebugString() + "\n";
  }

  result += "Answers:\n";
  for (Record& record : answers) {
    result += record.DebugString() + "\n";
  }

  result += "Authorities:\n";
  for (Record& record : authorities) {
    result += record.DebugString() + "\n";
  }

  result += "Additional:\n";
  for (Record& record : additional) {
    result += record.DebugString() + "\n";
  }

  result += "}\n";
  return result;
}
