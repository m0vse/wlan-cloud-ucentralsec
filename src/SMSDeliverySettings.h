#pragma once
#include <Poco/JSON/Object.h>
#include <mutex>
#include <string>
namespace OpenWifi {
struct SMSDeliverySettings {
    bool configured=false, enabled=false;
    std::string accountSid, fromNumber, token;
    Poco::JSON::Object PublicJSON() const;
    Poco::JSON::Object StoredJSON() const;
    static bool ParseUpdate(const Poco::JSON::Object &, const SMSDeliverySettings &, SMSDeliverySettings &);
};
class SMSSettingsStore {
public:
    static SMSSettingsStore &Instance(){static SMSSettingsStore s;return s;}
    void Load(const std::string &);
    SMSDeliverySettings Snapshot();
    bool Available();
    enum class SaveResult { saved, invalid, unavailable };
    SaveResult Save(const Poco::JSON::Object &);
private:
    std::mutex mutex_;
    SMSDeliverySettings settings_;
    std::string path_;
    bool available_=false;
};
bool AlertPhoneNumber(const std::string &);
struct AlertDeliveryResult {
    bool accepted=false, retryable=false, ambiguous=false;
    unsigned status=502;
    std::string providerId;
    Poco::JSON::Object JSON() const;
};
AlertDeliveryResult SendTwilioAlert(const SMSDeliverySettings &, const std::string &, const std::string &);
AlertDeliveryResult ParseTwilioAlertResponse(unsigned, const std::string &);
}
