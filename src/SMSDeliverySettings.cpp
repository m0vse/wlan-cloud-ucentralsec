#include "SMSDeliverySettings.h"
#include <Poco/JSON/Parser.h>
#include <Poco/Net/Context.h>
#include <Poco/Net/RejectCertificateHandler.h>
#include <Poco/Net/HTTPSClientSession.h>
#include <Poco/Net/HTTPBasicCredentials.h>
#include <Poco/Net/HTMLForm.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/URI.h>
#include <regex>
#include <sstream>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
namespace OpenWifi {
bool AlertPhoneNumber(const std::string &s){static const std::regex r(R"(^\+[1-9][0-9]{6,14}$)");return std::regex_match(s,r);}
static bool sid(const std::string &s,const std::string &prefix){return s.size()==34 && s.substr(0,2)==prefix && s.find_first_not_of("0123456789abcdefABCDEF",2)==std::string::npos;}
Poco::JSON::Object SMSDeliverySettings::PublicJSON() const {Poco::JSON::Object o;o.set("configured",configured);o.set("enabled",enabled);o.set("accountSid",accountSid);o.set("fromNumber",fromNumber);o.set("tokenSet",!token.empty());return o;}
Poco::JSON::Object SMSDeliverySettings::StoredJSON() const {auto o=PublicJSON();o.remove("tokenSet");o.set("token",token);return o;}
bool SMSDeliverySettings::ParseUpdate(const Poco::JSON::Object &b,const SMSDeliverySettings &old,SMSDeliverySettings &n){
 try {
  for(const auto &kv:b)if(kv.first!="enabled"&&kv.first!="accountSid"&&kv.first!="fromNumber"&&kv.first!="tokenAction"&&kv.first!="token")return false;
  if(!b.has("enabled")||b.get("enabled").type()!=typeid(bool))return false;
  for(auto f:{"accountSid","fromNumber","tokenAction"})if(!b.has(f)||!b.get(f).isString())return false;
  n=old;n.enabled=b.getValue<bool>("enabled");n.accountSid=b.getValue<std::string>("accountSid");n.fromNumber=b.getValue<std::string>("fromNumber");
  if((!n.accountSid.empty()&&!sid(n.accountSid,"AC"))||(!n.fromNumber.empty()&&!AlertPhoneNumber(n.fromNumber)))return false;
  auto action=b.getValue<std::string>("tokenAction");
  if(action=="set"){if(!b.has("token")||!b.get("token").isString())return false;n.token=b.getValue<std::string>("token");if(n.token.empty()||n.token.size()>4096||n.token.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")!=std::string::npos)return false;}
  else if(action=="clear"&&!b.has("token"))n.token.clear();
  else if(action!="retain"||b.has("token"))return false;
  if(n.enabled&&(!sid(n.accountSid,"AC")||!AlertPhoneNumber(n.fromNumber)||n.token.empty()))return false;
  n.configured=true;return true;
 }catch(...){return false;}
}
SMSDeliverySettings SMSSettingsStore::Snapshot(){std::lock_guard lock(mutex_);return settings_;}
bool SMSSettingsStore::Available(){std::lock_guard lock(mutex_);return available_;}
void SMSSettingsStore::Load(const std::string &path){
 std::lock_guard lock(mutex_);path_=path;settings_={};available_=true;
 int fd=open(path.c_str(),O_RDONLY|O_NOFOLLOW);if(fd<0){if(errno!=ENOENT)available_=false;return;}
 struct stat st{};if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid!=geteuid()||(st.st_mode&077)||st.st_size>32768){close(fd);available_=false;return;}
 std::string data;char buf[4096];ssize_t count;while((count=read(fd,buf,sizeof(buf)))>0)data.append(buf,count);close(fd);
 try{if(count<0)throw std::runtime_error("read");Poco::JSON::Parser p;auto b=p.parse(data).extract<Poco::JSON::Object::Ptr>();b->remove("configured");b->remove("tokenSet");auto token=b->optValue<std::string>("token","");if(token.empty()){b->remove("token");b->set("tokenAction","clear");}else b->set("tokenAction","set");SMSDeliverySettings n;if(!SMSDeliverySettings::ParseUpdate(*b,{},n))throw std::runtime_error("invalid");settings_=n;}catch(...){available_=false;}
}
SMSSettingsStore::SaveResult SMSSettingsStore::Save(const Poco::JSON::Object &b){
 std::lock_guard lock(mutex_);if(!available_||path_.empty())return SaveResult::unavailable;SMSDeliverySettings n;if(!SMSDeliverySettings::ParseUpdate(b,settings_,n))return SaveResult::invalid;
 std::ostringstream stream;n.StoredJSON().stringify(stream);auto data=stream.str(),tmp=path_+".XXXXXX";std::vector<char> name(tmp.begin(),tmp.end());name.push_back(0);int fd=mkstemp(name.data());if(fd<0)return SaveResult::unavailable;
 bool ok=fchmod(fd,0600)==0;std::size_t off=0;while(ok&&off<data.size()){auto written=write(fd,data.data()+off,data.size()-off);if(written<=0)ok=false;else off+=written;}if(ok)ok=fsync(fd)==0;if(close(fd))ok=false;if(ok)ok=rename(name.data(),path_.c_str())==0;if(!ok){unlink(name.data());return SaveResult::unavailable;}settings_=n;return SaveResult::saved;
}
Poco::JSON::Object AlertDeliveryResult::JSON() const {Poco::JSON::Object o;o.set("accepted",accepted);if(accepted){if(!providerId.empty())o.set("providerId",providerId);}else{o.set("retryable",retryable);o.set("ambiguous",ambiguous);}return o;}
AlertDeliveryResult ParseTwilioAlertResponse(unsigned status,const std::string &body){
 AlertDeliveryResult r;
 if(status==201){
  try{Poco::JSON::Parser p;auto o=p.parse(body).extract<Poco::JSON::Object::Ptr>();auto state=o->getValue<std::string>("status"),id=o->getValue<std::string>("sid");
   if(sid(id,"SM")&&(state=="queued"||state=="accepted"||state=="sending"||state=="sent")){r.accepted=true;r.status=200;r.providerId=id;return r;}
  }catch(...){}
  r.status=504;r.ambiguous=true;return r;
 }
 r.status=502;r.retryable=status==429||status>=500;return r;
}
AlertDeliveryResult SendTwilioAlert(const SMSDeliverySettings &s,const std::string &to,const std::string &text){
 AlertDeliveryResult r;if(!s.configured||!s.enabled){r.status=503;r.retryable=true;return r;}
 bool attempted=false;
 try{
  auto context=Poco::AutoPtr<Poco::Net::Context>(new Poco::Net::Context(Poco::Net::Context::TLS_CLIENT_USE,"","","",Poco::Net::Context::VERIFY_STRICT,9,true));
  context->setInvalidCertificateHandler(new Poco::Net::RejectCertificateHandler(false));
  Poco::Net::HTTPSClientSession session("api.twilio.com",443,context);session.setTimeout(Poco::Timespan(15,0));
  Poco::Net::HTTPRequest req("POST","/2010-04-01/Accounts/"+s.accountSid+"/Messages.json",Poco::Net::HTTPMessage::HTTP_1_1);
  Poco::Net::HTTPBasicCredentials(s.accountSid,s.token).authenticate(req);Poco::Net::HTMLForm form;form.add("To",to);form.add("From",s.fromNumber);form.add("Body",text);form.prepareSubmit(req);
  attempted=true;auto &out=session.sendRequest(req);form.write(out);Poco::Net::HTTPResponse response;auto &in=session.receiveResponse(response);
  std::string body;char buf[1024];while(in&&body.size()<=16384){in.read(buf,sizeof(buf));body.append(buf,in.gcount());}
  if(body.size()>16384){r.status=504;r.ambiguous=true;return r;}return ParseTwilioAlertResponse(response.getStatus(),body);
 }catch(...){r.status=attempted?504:503;r.ambiguous=attempted;r.retryable=!attempted;return r;}
}
}

