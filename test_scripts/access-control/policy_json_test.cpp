#include "framework/UserAccessPolicyJSON.h"
#include <iostream>
#include <stdexcept>
using namespace OpenWifi::UserAccess;
int main() {
    unsigned checks = 0;
    auto check = [&](bool value) {
        if (!value) throw std::runtime_error("JSON policy check " + std::to_string(checks + 1));
        ++checks;
    };
    Policy policy;
    const std::string grant = R"({"scopeType":"venue","scopeId":"11111111-1111-4111-8111-111111111111","includeDescendants":false,"capabilities":["devices.read"]})";
    const std::string valid = "{\"version\":1,\"grants\":[" + grant + "]}";
    check(Parse(valid, policy));
    check(policy.grants.size() == 1);
    check(Allows(policy, Resource{{"venue", "11111111-1111-4111-8111-111111111111"}, {}, true}, "devices.read"));
    check(!Allows(policy, Resource{{"venue", "22222222-2222-4222-8222-222222222222"}, {}, true}, "devices.read"));
    for (const auto &invalid : {
         "", "null", "[]", "{}", "{\"version\":1}", "{\"version\":true,\"grants\":[]}",
         "{\"version\":1.0,\"grants\":[]}", "{\"version\":2,\"grants\":[]}",
         "{\"version\":1,\"grants\":null}", "{\"version\":1,\"grants\":{},\"admin\":true}",
         "{\"version\":1,\"grants\":[null]}", "{\"version\":1,\"grants\":[],\"admin\":true}"}) {
        check(!Parse(invalid, policy));
        check(!Allows(policy, Resource{{"venue", "11111111-1111-4111-8111-111111111111"}, {}, true}, "devices.read"));
    }
    check(!Parse(valid + " {}", policy));
    check(!Parse(valid + " garbage", policy));
    check(Parse("{\"version\":1,\"grants\":[]}", policy));
    check(policy.grants.empty());
    auto changed = valid;
    changed.replace(changed.find("false"), 5, "\"false\"");
    check(!Parse(changed, policy));
    changed = valid;
    changed.replace(changed.find("devices.read"), 12, "*");
    check(!Parse(changed, policy));
    changed = valid;
    changed.replace(changed.find("devices.read"), 12, "devices.read\",\"devices.read");
    check(!Parse(changed, policy));
    check(!Parse(std::string(65537, ' '), policy));
    std::cout << "PASS " << checks << " native JSON policy checks\n";
}
