#include "src/dns/record_store.h"

#include <chrono>
#include <ctime>
#include <thread>
#include <mutex>
#include <vector>

#include "absl/log/log.h"
#include "absl/strings/str_join.h"
#include "src/dns/dns_packet.h"

namespace tiny_dns {

void RemoveRecordAfterTtl(RecordStore* store, const Record record) {
  LOG(INFO) << "Scheduling removal of: " << record.DebugString()
    << " in: " << record.ttl << "s.";
  std::this_thread::sleep_for(std::chrono::seconds(record.ttl));
  store->Remove(record);
}

bool RecordStoreShard::InsertOrUpdate(Record to_insert) {
  std::scoped_lock lock(mutex_);
  for (size_t i = 0; i < stored_records_.size(); i++) {
    const Record& record = stored_records_[i].record;
    if (to_insert.qtype != record.qtype) { continue; }
    if (to_insert.qname != record.qname) { continue; }
    if (to_insert.data != record.data) { continue; }

    stored_records_[i].record = to_insert;
    return true;
  }
  stored_records_.push_back(StoredRecord {
      .ttl_check = time(nullptr),
      .record = to_insert,
      });
  return false;
}

bool RecordStoreShard::Remove(const Record& to_remove) {
  std::scoped_lock lock(mutex_);
  for (size_t i = 0; i < stored_records_.size(); i++) {
    const Record& record = stored_records_[i].record;
    if (to_remove.qtype != record.qtype) { continue; }
    if (to_remove.qname != record.qname) { continue; }
    if (to_remove.data != record.data) { continue; }

    stored_records_[i] = stored_records_.back();
    stored_records_.pop_back();
    return true;
  }
  return false;
}

std::vector<Record> RecordStoreShard::Query(const Question& question) {
  std::scoped_lock lock(mutex_);
  std::vector<Record> hits;
  time_t current_time = time(nullptr);
  for (StoredRecord& stored_record : stored_records_) {
    Record& record = stored_record.record;
    if (question.qtype != record.qtype && record.qtype != QueryType::CNAME) { continue; }
    if (question.qname != record.qname) { continue; }

    uint16_t ttl_delta = current_time - stored_record.ttl_check;
    stored_record.ttl_check = current_time;
    // NOTE: assume removal thread will take care of removal
    if (ttl_delta > record.ttl) { continue; }
    record.ttl -= ttl_delta;
    hits.push_back(record);
  }
  return hits;
}

bool RecordStore::InsertOrUpdate(Record to_insert) {
  const size_t hash = hasher_(to_insert.qname);
  bool updated = shards_[hash % kShardCount].InsertOrUpdate(to_insert);
  if (updated) { LOG(INFO) << "Updated record: " << to_insert.DebugString(); }
  else { LOG(INFO) << "Inserted record: " << to_insert.DebugString(); }
  // NOTE: update may lower the ttl, spawn another thread to attempt removal.
  // TODO: should probably update the live thread instead?
  auto remove_after_ttl = std::thread(RemoveRecordAfterTtl, this, to_insert);
  remove_after_ttl.detach();
  return updated;
}

bool RecordStore::Remove(const Record& to_remove) {
  const size_t hash = hasher_(to_remove.qname);
  bool removed = shards_[hash % kShardCount].Remove(to_remove);
  if (removed) { LOG(INFO) << "Removal succeeded for record: " << to_remove.DebugString(); }
  else { LOG(INFO) << "Removal failed (not found) for record: " << to_remove.DebugString(); }
  return removed;
}

std::vector<Record> RecordStore::Query(const Question& question) {
  const size_t hash = hasher_(question.qname);
  const std::vector<Record> hits = shards_[hash % kShardCount].Query(question);
  std::vector<std::string> hit_qnames;
  hit_qnames.reserve(hits.size());
  for (const Record& hit : hits) { hit_qnames.push_back(hit.qname); }
  LOG(INFO) << "For question: " << question.DebugString()
    << ", record store contained: [ " << absl::StrJoin(hit_qnames, ", ") << " ].";
  return hits;
}

} // tiny_dns
