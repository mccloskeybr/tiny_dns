#include "src/record_store.h"

#include <chrono>
#include <ctime>
#include <thread>
#include <mutex>
#include <vector>

#include "absl/log/log.h"
#include "absl/strings/str_join.h"
#include "src/dns_packet.h"

void RemoveRecordAfterTtl(RecordStore* store, const Record record) {
  if (record.ttl == 0) {
    LOG(INFO) << "**Not** scheduling removal of: " << record.DebugString() << ", TTL is 0.";
    return;
  }
  LOG(INFO) << "Scheduling removal of: " << record.DebugString()
    << " in: " << record.ttl << "s.";
  std::this_thread::sleep_for(std::chrono::seconds(record.ttl));
  store->Remove(record);
}

void RecordStoreShard::Insert(Record to_insert) {
  std::scoped_lock lock(mutex_);
  StoredRecord record = {
    .ttl_check = time(nullptr),
    .record = to_insert,
  };
  stored_records_.push_back(record);
}

bool RecordStoreShard::Remove(const Record& to_remove) {
  std::scoped_lock lock(mutex_);
  for (size_t i = 0; i < stored_records_.size(); i++) {
    const Record& record = stored_records_[i].record;
    if (to_remove.qtype != record.qtype) { continue; }
    if (to_remove.qname.size() != record.qname.size()) { continue; }
    bool qnames_equal = true;
    for (size_t j = 0; j < to_remove.qname.size(); j++) {
      if (to_remove.qname[j] != record.qname[j]) { qnames_equal = false; break; }
    }
    if (!qnames_equal) { continue; }

    stored_records_[i] = stored_records_.back();
    stored_records_.pop_back();
    return true;
  }
  return false;
}

std::vector<Record> RecordStoreShard::Query(const Question& question) {
  std::scoped_lock lock(mutex_);
  std::vector<Record> hits;
  for (StoredRecord& stored_record : stored_records_) {
    Record& record = stored_record.record;
    if (question.qtype != record.qtype && record.qtype != QueryType::CNAME) { continue; }
    if (question.qname.size() != record.qname.size()) { continue; }
    // TODO: SPEEDUP - cache merged qnames.
    bool qnames_equal = true;
    for (size_t i = 0; i < question.qname.size(); i++) {
      if (question.qname[i] != record.qname[i]) { qnames_equal = false; break; }
    }
    if (!qnames_equal) { continue; }

    time_t current_time = time(nullptr);
    uint16_t ttl_delta = current_time - stored_record.ttl_check;
    stored_record.ttl_check = current_time;
    // NOTE: assume removal thread will take care of removal
    if (ttl_delta > record.ttl) { continue; }
    record.ttl -= ttl_delta;
    hits.push_back(record);
  }
  return hits;
}

void RecordStore::Insert(Record to_insert) {
  const size_t hash = hasher_(QNameAssemble(to_insert.qname));
  shards_[hash % kShardCount].Insert(to_insert);
  LOG(INFO) << "Inserted record :" << to_insert.DebugString();
  auto remove_after_ttl = std::thread(RemoveRecordAfterTtl, this, to_insert);
  remove_after_ttl.detach();
}

bool RecordStore::Remove(const Record& to_remove) {
  const size_t hash = hasher_(QNameAssemble(to_remove.qname));
  bool removed = shards_[hash % kShardCount].Remove(to_remove);
  LOG(INFO) << "Removed record: " << to_remove.DebugString();
  return removed;
}

std::vector<Record> RecordStore::Query(const Question& question) {
  const std::string assembled_qname = QNameAssemble(question.qname);
  const size_t hash = hasher_(assembled_qname);

  const std::vector<Record> hits = shards_[hash % kShardCount].Query(question);
  std::vector<std::string> hit_qnames;
  hit_qnames.reserve(hits.size());
  for (const Record& hit : hits) { hit_qnames.push_back(QNameAssemble(hit.qname)); }
  LOG(INFO) << "For question: " << question.DebugString()
    << ", record store contained: [ " << absl::StrJoin(hit_qnames, ", ") << " ].";

  return hits;
}
