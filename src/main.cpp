#include <userver/clients/http/component.hpp>
#include <userver/ugrpc/client/client_factory_component.hpp>
#include <userver/ugrpc/server/server_component.hpp>
#include <userver/components/minimal_server_component_list.hpp>
#include <userver/server/handlers/ping.hpp>
#include <userver/server/handlers/tests_control.hpp>
#include <userver/testsuite/testsuite_support.hpp>
#include <userver/utils/daemon_run.hpp>
#include <userver/storages/secdist/component.hpp>
#include <userver/storages/secdist/provider_component.hpp>


#include "AuthGRPC.hpp"

int main(int argc, char* argv[]) {
  auto component_list = userver::components::MinimalServerComponentList()
                            .Append<userver::ugrpc::server::ServerComponent>()
                            .Append<userver::server::handlers::Ping>()
                            .Append<userver::components::TestsuiteSupport>()
                            .Append<userver::components::Secdist>()
                            .Append<userver::components::DefaultSecdistProvider>()
                            .Append<userver::components::HttpClient>()
                            .Append<userver::server::handlers::TestsControl>();

  AppendAuthGrpc(component_list);

  return userver::utils::DaemonMain(argc, argv, component_list);
}
