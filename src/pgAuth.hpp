#pragma once

#include "jwt.hpp"
#include "cryptCore.hpp"
#include <string>
#include <tuple>
#include <string_view>
#include <userver/storages/postgres/cluster.hpp>

namespace MyMicro{
    class PgAuthMaster{
        public:
            static std::string CreateTokenFromID(userver::storages::postgres::ClusterPtr cluster, const std::int64_t& uid);
            static std::tuple<std::int64_t, std::string> VerifyToken(userver::storages::postgres::ClusterPtr cluster,const std::string& jwt);
            static std::string TryRegistrateAndSend(userver::storages::postgres::ClusterPtr cluster, const std::string& email, const std::string& password);
            static std::string VerifyRegistration(userver::storages::postgres::ClusterPtr cluster, const std::string_view reg_token);
            static std::string AuthFromPassword(userver::storages::postgres::ClusterPtr cluster, const std::string& email, const std::string& password);
        private:
            static std::string TryRegistrate(userver::storages::postgres::ClusterPtr cluster, const std::string& email, const std::string& password);
            static void SendToEmail(const std::string& where, const std::string& data);
    };
}