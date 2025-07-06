#ifndef SRC_DNS_RECORD_STORE_H_
#define SRC_DNS_RECORD_STORE_H_

#include <ctime>
#include <mutex>
#include <vector>

#include "src/dns/dns_packet.h"

// This is a really simple in-memory lookup table for
// DNS records. Failed lookups get shunted and then cached here.
// Manual entries are placed here. That kind of thing.

// TODO: LRU cache to ensure shards don't become too large.
static constexpr size_t kShardCount = 32;

struct StoredRecord {
  time_t ttl_check;
  Record record;
};

class RecordStoreShard {
 public:
  RecordStoreShard() : stored_records_(), mutex_() {}

  bool InsertOrUpdate(Record record); // NOTE: true on update
  bool Remove(const Record& record);
  std::vector<Record> Query(const Question& question);

 private:
  std::vector<StoredRecord> stored_records_;
  std::mutex mutex_;
};

class RecordStore {
 public:
  RecordStore() : shards_(), hasher_() {}

  bool InsertOrUpdate(Record record); // NOTE: true on update
  bool Remove(const Record& record);
  std::vector<Record> Query(const Question& question);

 private:
  std::array<RecordStoreShard, kShardCount> shards_;
  std::hash<std::string> hasher_;
};

#endif // SRC_DNS_RECORD_STORE_H_
