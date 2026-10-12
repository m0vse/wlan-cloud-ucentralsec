#include "RESTAPI_email_settings.h"
#include "EmailDeliverySettings.h"
#include "SMTPMailerService.h"
#include <regex>
#include "framework/ow_constants.h"
namespace OpenWifi {
void RESTAPI_email_settings::DoGet() {
    if(UserInfo_.userinfo.userRole!=SecurityObjects::ROOT)return ReturnStatus(Poco::Net::HTTPResponse::HTTP_FORBIDDEN);
    auto out=EmailSettingsStore::Instance().Snapshot().PublicJSON();ReturnObject(out);
}
void RESTAPI_email_settings::DoPut() {
    if(UserInfo_.userinfo.userRole!=SecurityObjects::ROOT)return ReturnStatus(Poco::Net::HTTPResponse::HTTP_FORBIDDEN);
    switch(EmailSettingsStore::Instance().Save(*ParsedBody_)) {
    case EmailSettingsStore::SaveResult::invalid:return BadRequest(RESTAPI::Errors::MissingOrInvalidParameters);
    case EmailSettingsStore::SaveResult::unavailable:return ReturnStatus(Poco::Net::HTTPResponse::HTTP_SERVICE_UNAVAILABLE);
    case EmailSettingsStore::SaveResult::saved:DoGet();
    }
}
void RESTAPI_email_settings::DoPost() {
    if(UserInfo_.userinfo.userRole!=SecurityObjects::ROOT)return ReturnStatus(Poco::Net::HTTPResponse::HTTP_FORBIDDEN);
    // Test only the saved configuration; never accept credentials or arbitrary mail content.
    if(!ParsedBody_ || ParsedBody_->size()!=1 || !ParsedBody_->has("recipient") ||
       !ParsedBody_->get("recipient").isString())return BadRequest(RESTAPI::Errors::MissingOrInvalidParameters);
    auto recipient=ParsedBody_->getValue<std::string>("recipient");
    static const std::regex address(R"(^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$)");
    if(recipient.size()>254 || !std::regex_match(recipient,address))return BadRequest(RESTAPI::Errors::MissingOrInvalidParameters);
    auto &store=EmailSettingsStore::Instance();
    auto settings=store.Snapshot();
    if(!store.Available() || !settings.configured || !settings.enabled)
        return ReturnStatus(Poco::Net::HTTPResponse::HTTP_SERVICE_UNAVAILABLE);
    SMTPMailerService::MessageEvent message;
    message.Attrs[RECIPIENT_EMAIL]=recipient;
    message.Attrs[SUBJECT]="OpenWiFi test email";
    message.Attrs[TEXT]="This is a test email from your OpenWiFi controller.";
    // Synchronous and never queued/retried: success means SMTP accepted the message.
    if(SMTPMailerService()->SendIt(message)!=MessageSendStatus::msg_sent)
        return ReturnStatus(Poco::Net::HTTPResponse::HTTP_SERVICE_UNAVAILABLE);
    Poco::JSON::Object out;out.set("accepted",true);ReturnObject(out);
}
}
