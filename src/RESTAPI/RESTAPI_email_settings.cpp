#include "RESTAPI_email_settings.h"
#include "EmailDeliverySettings.h"
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
}
