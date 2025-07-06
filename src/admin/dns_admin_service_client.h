#ifndef SRC_ADMIN_DNS_ADMIN_SERVICE_CLIENT_H_
#define SRC_ADMIN_DNS_ADMIN_SERVICE_CLIENT_H_

#include <atomic>
#include <thread>
#include <vector>
#include <memory>

#include "grpcpp/grpcpp.h"
#include "src/admin/dns_admin_service.grpc.pb.h"

// NOTE: Any TTL below this will be overridden.
static const int32_t kMinimumAllowedTtl = 60;

// gRPC client for the DNS admin service. Intended to be used to refresh
// DNS record entries regularly.
class DnsAdminServiceClient {
 public:
  explicit DnsAdminServiceClient(std::shared_ptr<grpc::Channel> channel) :
    stub_(proto::DnsAdminService::NewStub(channel)), refresh_ttl_threads_(), terminate_threads_() {}
  ~DnsAdminServiceClient();

  // NOTE: if auto_refresh_ttl is true, upon successful connection, will
  // refresh the ttl based on the provided cadence.
  grpc::Status InsertOrUpdate(
      const proto::InsertOrUpdateRequest& request,
      proto::InsertOrUpdateResponse& response,
      bool auto_refresh_ttl = false);

  grpc::Status Lookup(
      const proto::LookupRequest& request,
      proto::LookupResponse& response);

 private:
  std::unique_ptr<proto::DnsAdminService::Stub> stub_;
  std::vector<std::thread> refresh_ttl_threads_;
  std::atomic<bool> terminate_threads_;

  friend void RefreshTtl(DnsAdminServiceClient*, proto::Record);
};

#endif // SRC_ADMIN_DNS_ADMIN_SERVICE_CLIENT_H_
