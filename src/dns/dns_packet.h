#ifndef SRC_DNS_DNS_PACKET_H_
#define SRC_DNS_DNS_PACKET_H_

#include <array>
#include <cstdint>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/container/btree_map.h"

// This file interfaces with the DNS protocol. E.g. encoding / decoding DNS packets.

class BufferReader {
 public:
  BufferReader(const std::array<uint8_t, 512>& bytes, size_t pos = 0)
    : bytes_(bytes), cursor_(bytes_.data() + pos) {}

  absl::StatusOr<uint8_t> ReadU8();
  absl::StatusOr<uint16_t> ReadU16();
  absl::StatusOr<uint32_t> ReadU32();
  absl::StatusOr<std::string> ReadQName(size_t num_jumps = 0);

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
  absl::StatusOr<uint16_t> WriteQName(const std::string& qname);

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

// NOTE: To support arbitrary query types that this server does not have explicit
// support for, raw types are static cast to QueryType. Therefore, expect that unknown
// cases may be forwarded / must be caught using default -- don't just rely on UNKNOWN.
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

struct Header {
  static absl::StatusOr<Header> FromBytes(
      BufferReader& reader,
      uint16_t& questions_count, uint16_t& answers_count,
      uint16_t& authorities_count, uint16_t& additional_count);
  absl::Status ToBytes(
      BufferWriter& writer,
      uint16_t questions_count, uint16_t answers_count,
      uint16_t authorities_count, uint16_t additional_count) const;
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
};

struct Question {
  static absl::StatusOr<Question> FromBytes(BufferReader& reader);
  absl::Status ToBytes(BufferWriter& writer) const;
  std::string DebugString() const;

  std::string qname;
  QueryType qtype;
  uint16_t dns_class = 1;
};

struct Record {
  static absl::StatusOr<Record> FromBytes(BufferReader& reader);
  absl::Status ToBytes(BufferWriter& writer) const;
  std::string DebugString() const;

  std::string qname;
  QueryType qtype;
  uint16_t dns_class = 1;
  uint32_t ttl;
  time_t retrieval_time;

  struct UNKNOWN {
    std::vector<uint8_t> bytes;
    bool operator==(const UNKNOWN& other) const {
      return bytes == other.bytes;
    }
  };
  struct A {
    std::array<uint8_t, 4> ip_address;
    bool operator==(const A& other) const {
      return ip_address == other.ip_address;
    }
  };
  struct NS {
    std::string host;
    bool operator==(const NS& other) const {
      return host == other.host;
    }
  };
  struct CNAME {
    std::string host;
    bool operator==(const CNAME& other) const {
      return host == other.host;
    }
  };
  struct MX {
    uint16_t priority;
    std::string host;
    bool operator==(const MX& other) const {
      return priority == other.priority && host == other.host;
    }
  };
  struct AAAA {
    std::array<uint16_t, 8> ip_address;
    bool operator==(const AAAA& other) const {
      return ip_address == other.ip_address;
    }
  };
  std::variant<UNKNOWN, A, NS, CNAME, MX, AAAA> data;
};

struct DnsPacket {
  static absl::StatusOr<DnsPacket> FromBytes(
      const std::array<uint8_t, 512>& bytes);
  static absl::StatusOr<uint16_t> FromBytesIdOnly(
      const std::array<uint8_t, 512>& bytes);
  absl::StatusOr<std::array<uint8_t, 512>> ToBytes() const;
  std::string DebugString() const;

  Header header;
  std::vector<Question> questions;
  std::vector<Record> answers;
  std::vector<Record> authorities;
  std::vector<Record> additional;
};

#endif // SRC_DNS_DNS_PACKET_H_
