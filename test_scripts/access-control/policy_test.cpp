#include "framework/UserAccessPolicy.h"
#include <iostream>
#include <stdexcept>

using namespace OpenWifi::UserAccess;
static unsigned checks = 0;
static void check(bool condition) {
    ++checks;
    if (!condition) throw std::runtime_error("failed check " + std::to_string(checks));
}

int main() {
    const Scope customerA{"entity", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"};
    const Scope customerB{"entity", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"};
    const Scope siteA{"venue", "11111111-1111-4111-8111-111111111111"};
    const Scope siteB{"venue", "22222222-2222-4222-8222-222222222222"};
    const Scope child{"venue", "33333333-3333-4333-8333-333333333333"};
    Resource a{siteA, {customerA}, true}, b{siteB, {customerB}, true};
    Policy mixed{1, {{siteA, false, Preset("viewer")}, {siteB, false, Preset("operator")}}};
    check(Valid(mixed));
    for (const auto &capability : Preset("viewer")) check(Allows(mixed, a, capability));
    for (const auto &capability : Capabilities()) {
        check(Allows(mixed, a, capability) ==
              (std::find(mixed.grants[0].capabilities.begin(), mixed.grants[0].capabilities.end(),
                         capability) != mixed.grants[0].capabilities.end()));
    }
    check(Allows(mixed, b, "configuration.push"));
    check(!Allows(mixed, a, "configuration.push"));
    for (const auto &capability : {"firmware.upgrade", "devices.console", "secrets.read", "users.manage"})
        check(!Allows(mixed, b, capability));
    check(!Allows(mixed, Resource{child, {siteA, customerA}, true}, "devices.read"));
    mixed.grants[0].descendants = true;
    check(Allows(mixed, Resource{child, {siteA, customerA}, true}, "devices.read"));
    check(!Allows(mixed, Resource{child, {siteB, customerB}, true}, "devices.console"));
    Policy entity{1, {{customerA, true, Preset("viewer")}}};
    check(Allows(entity, a, "clients.read"));
    check(!Allows(entity, b, "clients.read"));
    check(!Allows(Policy{}, a, "devices.read"));
    check(!Allows(mixed, a, "devices.read", false, true));
    check(Allows(Policy{99, {}}, Resource{}, "devices.read", true));
    check(!Allows(Policy{}, a, "devices.read", true, true));
    check(!Allows(mixed, a, "unknown", true));
    check(!Allows(mixed, Resource{siteA, {customerA}, false}, "devices.read"));
    check(!Allows(mixed, Resource{siteA, {siteA}, true}, "devices.read"));
    auto bad = mixed; bad.version = 2; check(!Allows(bad, a, "devices.read"));
    bad = mixed; bad.grants[0].capabilities.push_back("*"); check(!Valid(bad));
    bad = mixed; bad.grants[0].capabilities.push_back("devices.read"); check(!Valid(bad));
    bad = mixed; bad.grants[0].scope.id = "*"; check(!Valid(bad));
    bad = mixed; bad.grants[0].scope.type = "global"; check(!Valid(bad));
    bad = mixed; bad.grants[0].capabilities.push_back("firmware.publish"); check(!Valid(bad));
    bad = mixed; bad.grants[0].capabilities.push_back("controller.manage"); check(!Valid(bad));
    check(Allows(Policy{}, Resource{}, "firmware.publish", true));
    check(!Allows(mixed, b, "firmware.publish"));
    check(Preset("admin").empty());
    check(CanAssign(true, false, "root", "viewer"));
    check(!CanAssign(true, false, "root", "root"));
    check(!CanAssign(false, false, "operator", "viewer"));
    check(!CanAssign(true, true, "root", "viewer"));
    check(!CanAssign(true, false, "", "viewer"));
    check(CachedIdentityUsable(101, 100, false));
    check(!CachedIdentityUsable(100, 100, false));
    check(!CachedIdentityUsable(99, 100, false));
    check(!CachedIdentityUsable(101, 100, true));
    // A move must satisfy both old and new ownership. A read on A cannot
    // authorize moving it to B, nor can B's operator grant grant actions on A.
    check(!(Allows(mixed, a, "resources.move") && Allows(mixed, b, "resources.move")));
    const ParentLookup lookup = [&](const Scope &scope, Scope &parent) {
        if (scope == siteA) parent = customerA;
        else if (scope == customerA) parent = PlatformRoot;
        else if (scope == PlatformRoot) parent = {};
        else return false;
        return true;
    };
    check(Allows(entity, Resolve(siteA, lookup), "devices.read"));
    check(!Allows(entity, Resolve(siteB, lookup), "devices.read"));
    check(!Resolve(PlatformRoot, lookup).ownershipResolved);
    check(!Resolve(siteA, [](const Scope &, Scope &) { return false; }).ownershipResolved);
    check(!Resolve(siteA, [&](const Scope &, Scope &parent) { parent = siteA; return true; }).ownershipResolved);
    check(!Resolve(siteA, [](const Scope &, Scope &parent) { parent = {}; return true; }).ownershipResolved);
    std::cout << "PASS " << checks << " native policy checks\n";
}
