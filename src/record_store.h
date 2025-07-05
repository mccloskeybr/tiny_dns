#ifndef SRC_RECORD_STORE_H_
#define SRC_RECORD_STORE_H_

#include <ctime>
#include <mutex>
#include <vector>

#include "src/dns_packet.h"

struct StoredRecord {
  time_t ttl_check;
  Record record;
};

class RecordStoreShard {
 public:
  RecordStoreShard() : stored_records_(), mutex_() {}

  void Insert(Record record);
  bool Remove(const Record& record);
  std::vector<Record> Query(const Question& question);

 private:
  std::vector<StoredRecord> stored_records_;
  std::mutex mutex_;
};

class RecordStore {
 public:
  RecordStore() : shards_(), hasher_() {}

  void Insert(Record record);
  bool Remove(const Record& record);
  std::vector<Record> Query(const Question& question);

 private:
  static constexpr size_t kShardCount = 10;
  std::array<RecordStoreShard, kShardCount> shards_;
  std::hash<std::string> hasher_;
};

#endif
