#pragma once
#include "framework/RESTAPI_Handler.h"
namespace OpenWifi {
class RESTAPI_sms_settings : public RESTAPIHandler {
public:
 RESTAPI_sms_settings(const BindingMap &b,Poco::Logger &l,RESTAPI_GenericServerAccounting &s,uint64_t t,bool i):RESTAPIHandler(b,l,{"GET","PUT","POST","OPTIONS"},s,t,i){}
 static auto PathName(){return std::list<std::string>{"/api/v1/smsSettings"};}
 void DoGet() final; void DoPut() final; void DoPost() final; void DoDelete() final {}
 void Reply(Poco::JSON::Object &o,unsigned status){PrepareResponse(static_cast<Poco::Net::HTTPResponse::HTTPStatus>(status));Poco::JSON::Stringifier::stringify(o,Response->send());}
};
class RESTAPI_alert_delivery : public RESTAPIHandler {
public:
 RESTAPI_alert_delivery(const BindingMap &b,Poco::Logger &l,RESTAPI_GenericServerAccounting &s,uint64_t t,bool i):RESTAPIHandler(b,l,{"POST","OPTIONS"},s,t,i){}
 static auto PathName(){return std::list<std::string>{"/api/v1/alertDelivery"};}
 void DoGet() final {} void DoPut() final {} void DoPost() final; void DoDelete() final {}
 void Reply(Poco::JSON::Object &o,unsigned status){PrepareResponse(static_cast<Poco::Net::HTTPResponse::HTTPStatus>(status));Poco::JSON::Stringifier::stringify(o,Response->send());}
};
}
