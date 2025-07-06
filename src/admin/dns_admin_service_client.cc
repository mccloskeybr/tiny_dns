#include "src/admin/dns_admin_service_client.h"

#include <chrono>
#include <thread>
#include <vector>

#include "absl/log/log.h"

void RefreshTtl(DnsAdminServiceClient* client, proto::Record record) {
  LOG(INFO) << "Automatically refreshing record: " << record;
  while (!client->terminate_threads_) {
    std::this_thread::sleep_for(std::chrono::seconds(record.ttl()));

    grpc::ClientContext context;
    proto::InsertOrUpdateRequest request;
    *request.mutable_record() = record;
    proto::InsertOrUpdateResponse response;
    const grpc::Status status = client->stub_->InsertOrUpdate(&context, request, &response);
    if (!status.ok()) {
      LOG(ERROR) << "Attempt to refresh DNS record: " << record
        << " failed: " << status.error_code() << " - " << status.error_message();
    } else {
      LOG(INFO) << "Successfully refreshed DNS record: " << record;
    }
  }
}

DnsAdminServiceClient::~DnsAdminServiceClient() {
  terminate_threads_ = true;
  for (std::thread& thread : refresh_ttl_threads_) {
    thread.join();
  }
}

grpc::Status DnsAdminServiceClient::InsertOrUpdate(
    const proto::InsertOrUpdateRequest& request,
    proto::InsertOrUpdateResponse& response,
    bool auto_refresh_ttl) {
  proto::InsertOrUpdateRequest request_copy = request;
  if (request_copy.record().ttl() < kMinimumAllowedTtl) {
    LOG(WARNING) << "Request to forward DNS record with TTL below minimum "
      << "(" << kMinimumAllowedTtl << "): " << request_copy.record().ttl();
    request_copy.mutable_record()->set_ttl(kMinimumAllowedTtl);
  }
  grpc::ClientContext context;
  const grpc::Status status = stub_->InsertOrUpdate(&context, request_copy, &response);
  if (!status.ok()) {
    LOG(ERROR) << "Call to InsertOrUpdate failed: "
      << status.error_code() << " - " << status.error_message();
  }
  if (auto_refresh_ttl) {
    refresh_ttl_threads_.push_back(std::thread(RefreshTtl, this, request_copy.record()));
  }
  return grpc::Status::OK;
}
