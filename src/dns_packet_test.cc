#include "src/dns_packet.h"

#include <array>
#include <cstdint>
#include <utility>

#include "absl/status/status_matchers.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"

namespace {

using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::testing::ContainerEq;

TEST(PacketReaderTest, ReadLabelsNoJumpSuccess) {
  std::array<uint8_t, 512> bytes = {
    5, 'h', 'e', 'l', 'l', 'o',
    5, 'w', 'o', 'r', 'l', 'd',
    0 };
  BufferReader reader(bytes);
  absl::StatusOr<std::vector<std::string>> labels = reader.ReadLabels();
  std::vector<std::string> expected_labels = { "hello", "world" };
  EXPECT_THAT(labels, IsOkAndHolds(ContainerEq(expected_labels)));
}

TEST(PacketReaderTest, ReadLabelsJumpSuccess) {
  std::array<uint8_t, 512> bytes = {
    4, 'j', 'u', 'm', 'p', 0,
    5, 'h', 'e', 'l', 'l', 'o',
    0xc0, 0x00 };
  BufferReader reader(bytes, 6);
  absl::StatusOr<std::vector<std::string>> labels = reader.ReadLabels();
  std::vector<std::string> expected_labels = { "hello", "jump" };
  EXPECT_THAT(labels, IsOkAndHolds(ContainerEq(expected_labels)));
}

TEST(PacketReaderTest, ReadLabelsJumpLoopReturnsError) {
  std::array<uint8_t, 512> bytes = {0xc0, 0x00 };
  BufferReader reader(bytes);
  absl::StatusOr<std::vector<std::string>> labels = reader.ReadLabels();
  EXPECT_THAT(labels, StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(DnsPacketTest, FromBytesSuccess) {
  std::array<uint8_t, 512> bytes = {
    // Header
    0x86, 0x2a, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    // Question
    0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
    0x00, 0x01, 0x00, 0x01,
    // Answer
    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x25, 0x00, 0x04, 0xd8, 0x3a, 0xd3, 0x8e,
  };
  absl::StatusOr<DnsPacket> packet = DnsPacket::FromBytes(bytes);
  ASSERT_TRUE(packet.ok());

  {
    Header& header = packet->header;
    EXPECT_EQ(header.id, 0x862a);

    EXPECT_EQ(header.recursion_desired, true);
    EXPECT_EQ(header.truncated_message, false);
    EXPECT_EQ(header.authoritative_answer, false);
    EXPECT_EQ(header.op_code, 0);
    EXPECT_EQ(header.query_response, true);

    EXPECT_EQ(header.response_code, ResponseCode::NO_ERROR);
    EXPECT_EQ(header.checking_disabled, false);
    EXPECT_EQ(header.authed_data, false);
    EXPECT_EQ(header.z, false);
    EXPECT_EQ(header.recursion_available, true);

    EXPECT_EQ(header.question_count, 1);
    EXPECT_EQ(header.answer_count, 1);
    EXPECT_EQ(header.authority_count, 0);
    EXPECT_EQ(header.additional_count, 0);
  }
  {
    Question question = packet->questions[0];
    std::vector<std::string> expected_labels = { "google", "com" };
    EXPECT_THAT(question.qname, ContainerEq(expected_labels));
    EXPECT_EQ(question.qtype, QueryType::A);
    EXPECT_EQ(question.dns_class, 1);
  }
  {
    Record& answer = packet->answers[0];
    std::vector<std::string> expected_labels = { "google", "com" };
    EXPECT_THAT(answer.qname, ContainerEq(expected_labels));
    EXPECT_EQ(answer.qtype, QueryType::A);
    EXPECT_EQ(answer.dns_class, 1);
    EXPECT_EQ(answer.ttl, 293);
    std::array<uint8_t, 4> expected_ip_addr = {216, 58, 211, 142};
    EXPECT_THAT(std::get<Record::A>(answer.data).ip_address, ContainerEq(expected_ip_addr));
  }
}

TEST(DnsPacketTest, ToBytesSuccess) {
  DnsPacket packet = {};
  {
    Header header = {};
    header.id = 0x862a;
    header.recursion_desired = true;
    header.truncated_message = false;
    header.authoritative_answer = false;
    header.op_code = 0;
    header.query_response = true;
    header.response_code = ResponseCode::NO_ERROR;
    header.checking_disabled = false;
    header.authed_data = false;
    header.z = false;
    header.recursion_available = true;
    header.question_count = 1;
    header.answer_count = 1;
    header.authority_count = 0;
    header.additional_count = 0;
    packet.header = std::move(header);
  }
  {
    Question question = {};
    question.qname = { "google", "com" };
    question.qtype = QueryType::A;
    question.dns_class = 1;
    packet.questions.push_back(std::move(question));
  }
  {
    Record answer = {};
    answer.qname = { "google", "com" };
    answer.qtype = QueryType::A;
    answer.dns_class = 1;
    answer.ttl = 293;
    Record::A a = { .ip_address = {216, 58, 211, 142} };
    answer.data = a;
    packet.answers.push_back(std::move(answer));
  }

  absl::StatusOr<std::array<uint8_t, 512>> actual_bytes = packet.ToBytes();
  std::array<uint8_t, 512> expected_bytes = {
    // Header
    0x86, 0x2a, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    // Question
    0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
    0x00, 0x01, 0x00, 0x01,
    // Answer
    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x25, 0x00, 0x04, 0xd8, 0x3a, 0xd3, 0x8e,
  };
  /*
  for (size_t i = 0; i < 512; i++) {
    std::cerr << std::hex << std::setw(2) << std::setfill('0') << static_cast<uint32_t>((*actual_bytes)[i]);
    std::cerr << " : ";
    std::cerr << std::hex << std::setw(2) << std::setfill('0') << static_cast<uint32_t>(expected_bytes[i]);
    std::cerr << std::endl;
  }
  */
  EXPECT_THAT(actual_bytes, IsOkAndHolds(ContainerEq(expected_bytes)));
}

} // namespace
