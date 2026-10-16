#include "SMSDeliverySettings.h"
#include <Poco/JSON/Parser.h>
#include <cassert>
#include <sys/stat.h>
#include <unistd.h>
using namespace OpenWifi;
int main(){
 SMSDeliverySettings empty,next;assert(!empty.enabled&&!empty.configured&&empty.token.empty());
 const std::string account="AC"+std::string(32,'1'),message="SM"+std::string(32,'1');
 Poco::JSON::Object b;b.set("enabled",true);b.set("accountSid",account);b.set("fromNumber","+441234567890");b.set("tokenAction","set");b.set("token","synthetic-secret");
 assert(SMSDeliverySettings::ParseUpdate(b,empty,next));assert(next.PublicJSON().getValue<bool>("tokenSet"));assert(!next.PublicJSON().has("token"));
 auto good=next;b.set("tokenAction","retain");b.remove("token");assert(SMSDeliverySettings::ParseUpdate(b,good,next)&&next.token==good.token);
 b.set("token","unexpected");assert(!SMSDeliverySettings::ParseUpdate(b,good,next));b.remove("token");
 for(auto number:{"1234","+0123456789","+44123\r\n", "+441234567890123456"}){b.set("fromNumber",number);assert(!SMSDeliverySettings::ParseUpdate(b,good,next));}
 b.set("fromNumber",good.fromNumber);b.set("tokenAction","clear");assert(!SMSDeliverySettings::ParseUpdate(b,good,next));b.set("enabled",false);assert(SMSDeliverySettings::ParseUpdate(b,good,next)&&next.token.empty());
 b.set("tokenAction","set");b.set("token","synthetic-secret");b.set("enabled",true);
 char path[]="/tmp/sms-settings-test.XXXXXX";int fd=mkstemp(path);assert(fd>=0);close(fd);unlink(path);auto &store=SMSSettingsStore::Instance();store.Load(path);assert(store.Available());assert(store.Save(b)==SMSSettingsStore::SaveResult::saved);struct stat st{};assert(!stat(path,&st)&&(st.st_mode&0777)==0600);store.Load(path);assert(store.Available()&&store.Snapshot().token=="synthetic-secret");chmod(path,0644);store.Load(path);assert(!store.Available());unlink(path);
 for(auto state:{"queued","accepted","sending","sent"}){auto r=ParseTwilioAlertResponse(201,std::string("{\"sid\":\"")+message+"\",\"status\":\""+state+"\"}");assert(r.accepted&&r.status==200&&!r.providerId.empty());}
 assert(!ParseTwilioAlertResponse(200,"{}").accepted);assert(ParseTwilioAlertResponse(201,"{}").ambiguous);assert(ParseTwilioAlertResponse(429,"private error").retryable);assert(!ParseTwilioAlertResponse(401,"private error").retryable);assert(ParseTwilioAlertResponse(503,"private error").retryable);assert(SendTwilioAlert({},"+441234567890","test").status==503);
}
