#include "RESTAPI_alert_delivery.h"
#include "SMSDeliverySettings.h"
#include "EmailDeliverySettings.h"
#include "SMTPMailerService.h"
#include "framework/ow_constants.h"
#include <regex>
namespace OpenWifi {
namespace {
bool address(const std::string &s){static const std::regex r(R"(^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$)");return s.size()<=254&&std::regex_match(s,r);}
}
void RESTAPI_sms_settings::DoGet(){if(UserInfo_.userinfo.userRole!=SecurityObjects::ROOT)return ReturnStatus(Poco::Net::HTTPResponse::HTTP_FORBIDDEN);auto o=SMSSettingsStore::Instance().Snapshot().PublicJSON();ReturnObject(o);}
void RESTAPI_sms_settings::DoPut(){if(UserInfo_.userinfo.userRole!=SecurityObjects::ROOT)return ReturnStatus(Poco::Net::HTTPResponse::HTTP_FORBIDDEN);if(!ParsedBody_)return BadRequest(RESTAPI::Errors::MissingOrInvalidParameters);switch(SMSSettingsStore::Instance().Save(*ParsedBody_)){case SMSSettingsStore::SaveResult::invalid:return BadRequest(RESTAPI::Errors::MissingOrInvalidParameters);case SMSSettingsStore::SaveResult::unavailable:return ReturnStatus(Poco::Net::HTTPResponse::HTTP_SERVICE_UNAVAILABLE);case SMSSettingsStore::SaveResult::saved:DoGet();}}
void RESTAPI_sms_settings::DoPost(){
 if(UserInfo_.userinfo.userRole!=SecurityObjects::ROOT)return ReturnStatus(Poco::Net::HTTPResponse::HTTP_FORBIDDEN);
 if(!ParsedBody_||ParsedBody_->size()!=1||!ParsedBody_->has("recipient")||!ParsedBody_->get("recipient").isString()||!AlertPhoneNumber(ParsedBody_->getValue<std::string>("recipient")))return BadRequest(RESTAPI::Errors::MissingOrInvalidParameters);
 auto &store=SMSSettingsStore::Instance();AlertDeliveryResult r;if(!store.Available()){r.status=503;r.retryable=true;}else r=SendTwilioAlert(store.Snapshot(),ParsedBody_->getValue<std::string>("recipient"),"This is a test SMS from your OpenWiFi controller.");auto o=r.JSON();Reply(o,r.status);
}
void RESTAPI_alert_delivery::DoPost(){
 // The common handler validates the existing internal service key. A browser token,
 // including ROOT, can never invoke arbitrary-content delivery.
 if(!Internal_||!Request->has("X-INTERNAL-NAME")||REST_Requester_.empty())return ReturnStatus(Poco::Net::HTTPResponse::HTTP_FORBIDDEN);
 if(!ParsedBody_||(ParsedBody_->size()!=5&&ParsedBody_->size()!=6))return BadRequest(RESTAPI::Errors::MissingOrInvalidParameters);
 for(const auto &kv:*ParsedBody_)if(kv.first!="channel"&&kv.first!="recipient"&&kv.first!="subject"&&kv.first!="text"&&kv.first!="eventId"&&kv.first!="html")return BadRequest(RESTAPI::Errors::MissingOrInvalidParameters);
 for(auto f:{"channel","recipient","subject","text","eventId"})if(!ParsedBody_->has(f)||!ParsedBody_->get(f).isString())return BadRequest(RESTAPI::Errors::MissingOrInvalidParameters);
 auto channel=ParsedBody_->getValue<std::string>("channel"),recipient=ParsedBody_->getValue<std::string>("recipient"),subject=ParsedBody_->getValue<std::string>("subject"),text=ParsedBody_->getValue<std::string>("text"),id=ParsedBody_->getValue<std::string>("eventId");
 if((channel!="email"&&channel!="sms")||id.empty()||id.size()>128||id.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:._-")!=std::string::npos||subject.empty()||subject.size()>255||subject.find_first_of("\r\n")!=std::string::npos||text.empty()||text.size()>16384||(channel=="sms"?(!AlertPhoneNumber(recipient)||text.size()>1600):!address(recipient)))return BadRequest(RESTAPI::Errors::MissingOrInvalidParameters);
 AlertDeliveryResult r;
 if(ParsedBody_->has("html")&&(channel!="email"||!ParsedBody_->get("html").isString()||ParsedBody_->getValue<std::string>("html").size()>32768))return BadRequest(RESTAPI::Errors::MissingOrInvalidParameters);
 if(channel=="sms"){auto &store=SMSSettingsStore::Instance();if(!store.Available()){r.status=503;r.retryable=true;}else r=SendTwilioAlert(store.Snapshot(),recipient,text);}
 else {auto &store=EmailSettingsStore::Instance();auto settings=store.Snapshot();if(!store.Available()||!settings.configured||!settings.enabled){r.status=503;r.retryable=true;}else {SMTPMailerService::MessageEvent message;message.PrivateAlert=true;message.Attrs[RECIPIENT_EMAIL]=recipient;message.Attrs[SUBJECT]=subject;message.Attrs[TEXT]=text;if(ParsedBody_->has("html"))message.Attrs[ALERT_HTML]=ParsedBody_->getValue<std::string>("html");if(SMTPMailerService()->SendIt(message)==MessageSendStatus::msg_sent){r.accepted=true;r.status=200;}else {r.status=504;r.ambiguous=true;}}}
 auto o=r.JSON();Reply(o,r.status);
}
}
