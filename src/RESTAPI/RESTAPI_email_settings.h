#pragma once
#include "framework/RESTAPI_Handler.h"
namespace OpenWifi {
class RESTAPI_email_settings : public RESTAPIHandler {
public:
    RESTAPI_email_settings(const BindingMap &bindings,Poco::Logger &log,
                          RESTAPI_GenericServerAccounting &server,uint64_t tid,bool internal)
        : RESTAPIHandler(bindings,log,{"GET","PUT","OPTIONS"},server,tid,internal) {}
    static auto PathName(){return std::list<std::string>{"/api/v1/emailSettings"};}
    void DoGet() final;
    void DoPut() final;
    void DoPost() final {}
    void DoDelete() final {}
};
}
