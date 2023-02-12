#include "pgAuth.hpp"
namespace MyMicro {
auto CreateTransactionRpRead(userver::storages::postgres::ClusterPtr& cluster) {
  namespace uPGN = userver::storages::postgres;
  constexpr auto isolationLevel = uPGN::IsolationLevel::kRepeatableRead;
  uPGN::TransactionOptions trO{isolationLevel};
  return cluster->Begin(trO);
}
std::string PgAuthMaster::CreateTokenFromID(
    userver::storages::postgres::ClusterPtr cluster, const std::int64_t& uid) {
  auto registrator = [&cluster](const std::int64_t& uid,
                                const std::string& publicKey,
                                const std::int64_t& t_c) {
    namespace uPGN = userver::storages::postgres;
    auto transactionR = CreateTransactionRpRead(cluster);
    const uPGN::Query tokenRegistrateQuery{
        "SELECT * from insert_token($1, $2, $3) ",
        uPGN::Query::Name{"tokenRegistator"},
    };
    auto transRes =
        transactionR.execute(tokenRegistrateQuery, uid, publicKey, t_c);
    transactionR.Commit();
    return transRes.AsSingleRow<std::int64_t>();
  };
  return MyMicro::JWT_Token_Master::CreateToken(regitsrator, uid);
}
std::tuple<std::int64_t, std::string> PgAuthMaster::VerifyToken(
    userver::storages::postgres::ClusterPtr cluster, const std::string& jwt) {
  std::int64_t uid = -1;
  auto dataGetter = [&cluster, &uid](const std::int64_t& token_id) {
    namespace uPGN = userver::storages::postgres;
    auto transactionR = CreateTransactionRpRead(cluster);
    const uPGN::Query tokenGetterQuery{
        "SELECT uid, open_key from users_tokens_info "
        "where tid = $1",
        uPGN::Query::Name{"tokenDataGetter"},
    };
    auto transRes = transactionR.execute(tokenGetterQuery, token_id);
    transactionR.Commit();
    if (!transRes.IsEmpty()) {
      auto row = transRes[0];  // there is single row
      uid = row["uid"].As<std::int64_t>();
      return row["open_key"].As<std::string>();
    };
    else{
        return "";
    }
  };
  auto resV = MyMicro::JWT_Token_Master::Verify(dataGetter, jwt);
  using state = MyMicro::JWT_Token_Master::GWTStates;
  switch (resV){
    case state::Ok:
        return std::make_tuple(uid, jwt);
    case state::GoodOld:
        return std::make_tuple(uid, PgAuthMaster::CreateTokenFromID(cluster, uid));
    case state::BadOld:
    case state::DontEq:
        return std::make_tuple(-1, "");

  }
}
}  // namespace MyMicro