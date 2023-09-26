#include <eosio/eosio.hpp>
#include <eosio/action.hpp>
#include <eosio/asset.hpp>
#include <eosio/singleton.hpp>
#include <eosio/crypto.hpp>
using namespace eosio;

// Define a struct for the transfer action data
struct transfer_data
{
    eosio::name from;
    eosio::name to;
    eosio::asset quantity;
    std::string memo;

    EOSLIB_SERIALIZE(transfer_data, (from)(to)(quantity)(memo))
};

class [[eosio::contract]] motivate : public eosio::contract
{
public:
    using eosio::contract::contract;
    motivate(name receiver, name code, datastream<const char *> ds) : contract(receiver, code, ds),
                                                                      singleton_instance(receiver, receiver.value) {}
    [[eosio::action]] void reveal(eosio::name username, std::string user_input)
    {
        // require_auth(get_self());
        print(" >In reveal ");
        action(permission_level{get_self(), "active"_n},
               get_self(), "getbalance"_n,
               std::make_tuple(username))
            .send();
        std::string message;
        uint64_t state;
        uint64_t secret = getSecret();
        if (checkCondition(user_input, secret))
        {
            state = 1;
            writeState(username, state);
            createSecret();
            message = "you win";
        }
        else
        {
            message = "you lose";
        }
        notify(username, message);
    }
    [[eosio::action]] void getbalance(eosio::name username)
    {
        require_auth(get_self());
        print(" >getbalance: ");
        uint64_t balance = readState(username);
        std::string message = std::to_string(balance);
        notify(username, message);
    }
    [[eosio::action]] void myreveal(eosio::name username, std::string user_input) {}

private:
    uint64_t getSecret()
    {
        if (!singleton_instance.exists())
            createSecret();
        uint64_t secret = singleton_instance.get().secondary_value;
        print(" >getSecret: ", secret);
        return secret;
    }
    void createSecret()
    {
        uint64_t seed = eosio::current_time_point().sec_since_epoch();
        eosio::checksum256 hash = sha256((char *)&seed, sizeof(seed));
        std::array<uint8_t, 32> hash_bytes = hash.extract_as_byte_array();
        uint64_t value = 0;
        for (int i = 0; i < 8; ++i)
        {
            value = (value << 8) | hash_bytes[i];
        }
        uint64_t secret = value % 10 + 1;
        auto entry_stored = singleton_instance.get_or_create(get_self(), secretrow);
        entry_stored.primary_value = get_self();
        entry_stored.secondary_value = secret;
        singleton_instance.set(entry_stored, get_self());
        print(" >createSecret: ", secret);
    }
    bool checkCondition(std::string user_input, uint64_t secret)
    {
        return std::stoi(user_input) > secret;
    }
    void writeState(eosio::name username, uint64_t state)
    {
        uint64_t balance = readState(username);
        uint64_t amount = balance + state;
        balance_index balances(get_self(), get_self().value);
        auto iterator = balances.find(username.value);
        if (iterator == balances.end())
        {
            balances.emplace(get_self(), [&](auto &row)
                             {
               row.key = username;
               row.amount = amount; });
        }
        else
        {
            balances.modify(
                iterator, get_self(),
                [&](auto &row)
                {
                    row.key = username;
                    row.amount = amount; });
        }
    }
    uint64_t readState(eosio::name username)
    {
        balance_index balances(get_self(), get_self().value);
        uint64_t amount = 0;
        auto iterator = balances.find(username.value);
        if (iterator != balances.end())
        {
            amount += iterator->amount;
        }
        return amount;
    }
    void notify(eosio::name username, std::string message)
    {
        print(" >notify: ", username, ": ", message);
        if (message == "you win")
        {
            uint8_t p = 4;
            uint8_t num = 1;
            action(
                permission_level{get_self(), "active"_n},
                "eosio.token"_n,
                "transfer"_n,
                std::make_tuple(get_self(),
                                username,
                                asset(num * pow(10, p), symbol("SYS", p)),
                                std::string("you win")))
                .send();
        }
        else if (message == "you lose")
        {
            uint8_t p = 4;
            uint8_t num = 1;
            action(
                permission_level{get_self(), "active"_n},
                "eosio.token"_n,
                "transfer"_n,
                std::make_tuple(get_self(),
                                username,
                                asset(num * pow(10, p), symbol("SYS", p)),
                                std::string("you lose")))
                .send();
        }
    }

    struct [[eosio::table]] balance
    {
        name key;
        uint64_t amount;
        uint64_t primary_key() const { return key.value; }
    };
    using balance_index = eosio::multi_index<"balances"_n, balance>;

    struct [[eosio::table]] secret
    {
        name primary_value;
        uint64_t secondary_value;
        uint64_t primary_key() const { return primary_value.value; }
    } secretrow;
    using singleton_type = eosio::singleton<"secret"_n, secret>;
    singleton_type singleton_instance;
};

void payToPlay(const transfer_data &transfer)
{
    if (transfer.to == "motivate"_n)
    {
        eosio::name contract_name = name("motivate");
        eosio::name action_name = name("myreveal");
        action(permission_level{"motivate"_n, "active"_n},
               contract_name, action_name,
               std::make_tuple(transfer.from, transfer.memo))
            .send();
    }
    else if (transfer.from == "motivate"_n)
    {
        print(transfer.from, " sent ", transfer.quantity.to_string(), " to ", transfer.to.to_string());
    }
}

extern "C" void apply(uint64_t receiver, uint64_t code, uint64_t action)
{
    if (code == receiver && action == name("myreveal").value)
        eosio::execute_action(eosio::name(receiver), eosio::name(code), &motivate::reveal);
    else if (action == name("getbalance").value)
        eosio::execute_action(eosio::name(receiver), eosio::name(code), &motivate::getbalance);
    else if (code == name("eosio.token").value && action == name("transfer").value)
        payToPlay(unpack_action_data<transfer_data>());
    else
        print("Unknown action", action);
}