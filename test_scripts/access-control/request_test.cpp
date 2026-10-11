#include "framework/UserAccessRequest.h"
#include <iostream>
#include <stdexcept>
using namespace OpenWifi::UserAccess;
int main() {
    unsigned count = 0;
    auto check = [&](bool value) { if (!value) throw std::runtime_error("request check " + std::to_string(count)); ++count; };
    auto has = [](const RequestRule &rule, const std::string &cap) {
        return std::find(rule.capabilities.begin(), rule.capabilities.end(), cap) != rule.capabilities.end();
    };
    auto r = Classify("owprov", "GET", "/api/v1/inventory/ap-a", {});
    check(r.known && has(r, "devices.read"));
    r = Classify("owprov", "GET", "/api/v1/inventory/ap-a", {{"applyConfiguration", "true"}});
    check(r.known && has(r, "configuration.push") && !has(r, "devices.read"));
    r = Classify("owprov", "PUT", "/api/v1/venue/venue-a", {{"updateAllDevices", "true"}, {"rebootAllDevices", "true"}, {"upgradeAllDevices", "true"}});
    check(has(r, "configuration.push") && has(r, "devices.reboot") && has(r, "firmware.upgrade"));
    check(!Classify("owprov", "POST", "/api/v1/entity", {{"setTree", "true"}}).known);
    check(!Classify("owprov", "GET", "/api/v1/operator", {}).known);
    check(!Classify("owgw", "GET", "/api/v1/unknown", {}).known);
    check(!Classify("owgw", "GET", "/api/v1/device/ap-a/factory", {}).known);
    check(!Classify("owgw", "POST", "/api/v1/device/ap-a/script", {}).known);
    check(has(Classify("owgw", "GET", "/api/v1/device/ap-a/rtty", {}), "devices.console"));
    check(has(Classify("owgw", "POST", "/api/v1/device/ap-a/upgrade", {}), "firmware.upgrade"));
    check(has(Classify("owgw", "POST", "/api/v1/device/ap-a/reboot", {}), "devices.reboot"));
    check(!Classify("owgw", "GET", "/api/v1/devices", {{"connectionStatistics", "true"}}).known);
    check(Classify("owgw", "GET", "/api/v1/devices", {}).collection);
    check(!Classify("owfms", "POST", "/api/v1/firmware/firmware-a", {}).known);
    check(Classify("owfms", "GET", "/api/v1/firmwares", {}).catalog);
    check(!Classify("owprov", "GET", "/api/v1/configuration/id/other", {}).known);
    check(!Classify("owprov", "GET", "/api/v2/inventory/ap-a", {}).known);
    r = Classify("owprov", "GET", "/api/v1/inventory/cross", {{"orderSpec", "true"}});
    check(r.known && !r.catalog && r.id == "cross");
    check(!Classify("owprov", "GET", "/api/v1/inventory/cross", {{"orderSpec", "true"}, {"applyConfiguration", "true"}}).known);
    r = Classify("owprov", "GET", "/api/v1/configuration/cross", {{"orderSpec", "true"}});
    check(r.known && !r.catalog && r.id == "cross");
    check(Classify("owprov", "GET", "/api/v1/inventory", {{"orderSpec", "true"}}).catalog);
    check(!Classify("owprov", "GET", "/api/v1/inventory", {{"orderSpec", "true"}, {"countOnly", "true"}}).known);
    check(!Classify("owgw", "GET", "/api/v1/devices", {{"orderSpec", "true"}, {"select", "cross"}}).known);
    check(!Classify("owprov", "GET", "/api/v1/configuration", {{"orderSpec", "true"}}).known);
    check(!Classify("owprov", "GET", "/api/v1/entity", {{"orderSpec", "true"}}).known);
    std::cout << "PASS " << count << " actual route/action classification checks\n";
}
