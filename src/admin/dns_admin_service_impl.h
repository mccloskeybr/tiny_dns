#ifndef SRC_ADMIN_DNS_ADMIN_SERVICE_IMPL_H_
#define SRC_ADMIN_DNS_ADMIN_SERVICE_IMPL_H_

#include <memory>
#include <utility>

#include "grpcpp/grpcpp.h"
#include "src/admin/dns_admin_service.grpc.pb.h"
#include "src/dns/record_store.h"
#include "src/dns/client.h"

namespace tiny_dns {

// gRPC service exposing non-DNS lookup functionality. For example,
// registering DNS records manually from some other service.
class DnsAdminServiceImpl final : public proto::DnsAdminService::Service {
 public:
  DnsAdminServiceImpl(
      std::shared_ptr<RecordStore> record_store,
      std::shared_ptr<Client> dns_server) :
    record_store_(std::move(record_store)), dns_server_(std::move(dns_server)) {}

 private:
  grpc::Status InsertOrUpdate(
      grpc::ServerContext* context,
      const proto::InsertOrUpdateRequest* request,
      proto::InsertOrUpdateResponse* response) override;

  grpc::Status Lookup(
      grpc::ServerContext* context,
      const proto::LookupRequest* request,
      proto::LookupResponse* response) override;

  std::shared_ptr<RecordStore> record_store_;
  std::shared_ptr<Client> dns_server_;
};

} // tiny_dns

#endif // SRC_ADMIN_DNS_ADMIN_SERVICE_IMPL_H_
