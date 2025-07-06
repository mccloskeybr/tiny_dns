#ifndef SRC_ADMIN_DNS_ADMIN_SERVICE_IMPL_H_
#define SRC_ADMIN_DNS_ADMIN_SERVICE_IMPL_H_

#include <memory>

#include "grpcpp/grpcpp.h"
#include "src/admin/dns_admin_service.grpc.pb.h"
#include "src/common/record_store.h"

// gRPC service exposing non-DNS lookup functionality. For example,
// registering DNS records manually from some other service.
class DnsAdminServiceImpl final : public proto::DnsAdminService::Service {
 public:
  DnsAdminServiceImpl(std::shared_ptr<RecordStore> record_store) :
    record_store_(std::move(record_store)) {}

 private:
  grpc::Status InsertOrUpdate(
      grpc::ServerContext* context,
      const proto::InsertOrUpdateRequest* request,
      proto::InsertOrUpdateResponse* response) override;

  std::shared_ptr<RecordStore> record_store_;
};

#endif // SRC_ADMIN_DNS_ADMIN_SERVICE_IMPL_H_
