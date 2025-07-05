#ifndef SRC_DNS_PACKET_H_
#define SRC_DNS_PACKET_H_

#include <array>
#include <cstdint>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/container/btree_map.h"

class BufferReader {
 public:
  BufferReader(const std::array<uint8_t, 512>& bytes, size_t pos = 0)
    : bytes_(bytes), cursor_(bytes_.data() + pos) {}

  absl::StatusOr<uint8_t> ReadU8();
  absl::StatusOr<uint16_t> ReadU16();
  absl::StatusOr<uint32_t> ReadU32();
  absl::StatusOr<std::vector<std::string>> ReadLabels(size_t num_jumps = 0);

 private:
  const std::array<uint8_t, 512>& bytes_;
  const uint8_t* cursor_;
};

class BufferWriter {
 public:
  BufferWriter(std::array<uint8_t, 512>& bytes, size_t pos = 0)
    : bytes_(bytes), cursor_(bytes_.data() + pos), label_map_() {}

  absl::Status WriteU8(uint8_t x);
  absl::Status WriteU16(uint16_t x);
  absl::Status WriteU32(uint32_t x);
  absl::StatusOr<uint16_t> WriteLabels(const std::vector<std::string>& labels);

 private:
  std::array<uint8_t, 512>& bytes_;
  uint8_t* cursor_;
  absl::btree_map<std::string, uint16_t> label_map_;
};

enum class ResponseCode : uint8_t {
  NO_ERROR = 0,
  FORM_ERROR = 1,
  SERV_FAIL = 2,
  NX_DOMAIN = 3,
  NO_TIMP = 4,
  REFUSED = 5,
};
ResponseCode ResponseCodeFromByte(uint8_t byte);
uint8_t ResponseCodeToByte(ResponseCode code);
std::string ResponseCodeToString(ResponseCode code);

enum class QueryType : uint16_t {
  UNKNOWN = 0,
  A = 1,
  NS = 2,
  CNAME = 5,
  MX = 15,
  AAAA = 28,
};
QueryType QueryTypeFromShort(uint16_t x);
uint16_t QueryTypeToShort(QueryType type);
std::string QueryTypeToString(QueryType type);

std::string QNameAssemble(const std::vector<std::string>& qname);

struct Header {
  static absl::StatusOr<Header> FromBytes(BufferReader& reader);
  absl::Status ToBytes(BufferWriter& writer) const;
  std::string DebugString() const;

  uint16_t id;
  bool recursion_desired;
  bool truncated_message;
  bool authoritative_answer;
  uint8_t op_code;
  bool query_response;
  ResponseCode response_code;
  bool checking_disabled;
  bool authed_data;
  bool z;
  bool recursion_available;

  // NOTE: automatically updated when converting to bytes.
  // TODO: could probably hide this from the struct.
  uint16_t question_count;
  uint16_t answer_count;
  uint16_t authority_count;
  uint16_t additional_count;
};

struct Question {
  static absl::StatusOr<Question> FromBytes(BufferReader& reader);
  absl::Status ToBytes(BufferWriter& writer) const;
  std::string DebugString() const;

  std::vector<std::string> qname;
  QueryType qtype;
  uint16_t dns_class = 1;
};

struct Record {
  static absl::StatusOr<Record> FromBytes(BufferReader& reader);
  absl::Status ToBytes(BufferWriter& writer) const;
  std::string DebugString() const;

  std::vector<std::string> qname;
  QueryType qtype;
  uint16_t dns_class = 1;
  uint32_t ttl;
  time_t retrieval_time;

  struct A {
    std::array<uint8_t, 4> ip_address;
  };
  struct NS {
    std::vector<std::string> host;
  };
  struct CNAME {
    std::vector<std::string> host;
  };
  struct MX {
    uint16_t priority;
    std::vector<std::string> host;
  };
  struct AAAA {
    std::array<uint16_t, 8> ip_address;
  };
  std::variant<A, NS, CNAME, MX, AAAA> data;
};

struct DnsPacket {
  static absl::StatusOr<DnsPacket> FromBytes(
      const std::array<uint8_t, 512>& bytes);
  absl::StatusOr<std::array<uint8_t, 512>> ToBytes();
  std::string DebugString() const;

  Header header;
  std::vector<Question> questions;
  std::vector<Record> answers;
  std::vector<Record> authorities;
  std::vector<Record> additional;
};

#endif // SRC_DNS_PACKET_H_
