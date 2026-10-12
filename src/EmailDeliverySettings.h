#pragma once
#include <Poco/JSON/Object.h>
#include <mutex>
#include <string>

namespace OpenWifi {
struct EmailDeliverySettings {
    bool configured=false, enabled=false;
    unsigned port=0;
    std::string host, tlsMode, sender, username, authMethod, password;
    Poco::JSON::Object PublicJSON() const;
    Poco::JSON::Object StoredJSON() const;
    static bool ParseUpdate(const Poco::JSON::Object &body, const EmailDeliverySettings &old,
                            EmailDeliverySettings &next);
};
class EmailSettingsStore {
public:
    static EmailSettingsStore &Instance() { static EmailSettingsStore store; return store; }
    void Load(const std::string &path);
    EmailDeliverySettings Snapshot();
    bool Available();
    enum class SaveResult { saved, invalid, unavailable };
    SaveResult Save(const Poco::JSON::Object &body);
private:
    std::mutex mutex_;
    EmailDeliverySettings settings_;
    std::string path_;
    bool available_=false;
};
}
