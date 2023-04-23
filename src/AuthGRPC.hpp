#include <chrono>
#include <string_view>
#include <utility>

#include <fmt/format.h>
#include <userver/components/component.hpp>
#include <userver/components/component_list.hpp>
#include <AuthServ_service.usrv.pb.hpp>
#include <userver/components/loggable_component_base.hpp>
#include <userver/components/minimal_server_component_list.hpp>
#include <userver/server/handlers/http_handler_base.hpp>
#include <userver/storages/postgres/cluster.hpp>
#include <userver/storages/postgres/component.hpp>
#include <userver/ugrpc/client/client_factory_component.hpp>
#include <userver/ugrpc/server/server_component.hpp>
#include <userver/ugrpc/server/service_component_base.hpp>
#include <userver/utest/using_namespace_userver.hpp>
#include <userver/utils/daemon_run.hpp>
#include <userver/yaml_config/merge_schemas.hpp>
class AuthGrpcComponent final : public AuthAndRegistServiceBase::Component {
 public:
  static constexpr std::string_view kName = "AuthGrpcComponent";
  AuthGrpcComponent(const components::ComponentConfig& config,
                    const components::ComponentContext& context)
      : AuthAndRegistServiceBase::Component(config, context),
        pg_cluster_(
            context.FindComponent<components::Postgres>("AuthDatabase")
                .GetCluster()) {}

  void Authenticate(AuthenticateCall& call, AuthInput&& request) override;
  void TryRegistr(TryRegistrCall& call, RegistrationInput&& request) override;
  void TryVerifRegistr(TryVerifRegistrCall& call,
                       RegistrationVerificationInput&& request) override;
  void AuthFromPassword(
      AuthFromPasswordCall& call,
      ::PasswordAuthInput&& request) override;

 private:
  storages::postgres::ClusterPtr pg_cluster_;
};
void AppendAuthGrpc(userver::components::ComponentList& component_list);
