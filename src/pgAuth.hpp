#pragma once

#include "jwt.hpp"
#include "cryptCore.hpp"
#include <string>
#include <tuple>
#include <userver/storages/postgres/cluster.hpp>

namespace MyMicro{
    class PgAuthMaster{
        private:
            static std::string CreateTokenFromID(userver::storages::postgres::ClusterPtr cluster, const std::int64_t& uid);
            static std::tuple<std::int64_t, std::string> VerifyToken(std)
    };
}