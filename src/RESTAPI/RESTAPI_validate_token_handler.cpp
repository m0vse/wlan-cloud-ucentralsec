//
// Created by stephane bourque on 2021-07-01.
//

#include "RESTAPI_validate_token_handler.h"
#include "AuthService.h"

namespace OpenWifi {
	void RESTAPI_validate_token_handler::DoGet() {
		Poco::URI URI(Request->getURI());
		auto Parameters = URI.getQueryParameters();
		for (auto const &i : Parameters) {
			if (i.first == "token") {
				//  can we find this token?
				SecurityObjects::UserInfoAndPolicy SecObj;
				bool Expired = false;
				if (AuthService()->IsValidToken(i.second, SecObj.webtoken, SecObj.userinfo,
												Expired)) {
					Poco::JSON::Object Obj;
					if (SecObj.userinfo.userRole != SecurityObjects::ROOT &&
						GetParameter("accessPolicyVersion") != "1")
						return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
					SecObj.userinfo.currentPassword.clear();
					SecObj.userinfo.lastPasswords.clear();
					SecObj.userinfo.userTypeProprietaryInfo.authenticatorSecret.clear();
					SecObj.to_json(Obj);
					return ReturnObject(Obj);
				}
			}
		}
		return NotFound();
	}
} // namespace OpenWifi
