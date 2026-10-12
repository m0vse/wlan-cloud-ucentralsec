#include "EmailDeliverySettings.h"
#include <Poco/JSON/Parser.h>
#include <Poco/Dynamic/Var.h>
#include <algorithm>
#include <sstream>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

namespace OpenWifi {
namespace {
bool clean(const std::string &s, std::size_t max=255) {
    return s.size()<=max && std::none_of(s.begin(),s.end(),[](unsigned char c){return c<32 || c==127;});
}
bool email(const std::string &s) { return clean(s) && s.find('@')!=std::string::npos && s.find(' ')==std::string::npos; }
bool choice(const std::string &s,std::initializer_list<const char *> values) {
    return std::any_of(values.begin(),values.end(),[&](const char *v){return s==v;});
}
}
Poco::JSON::Object EmailDeliverySettings::PublicJSON() const {
    Poco::JSON::Object out;
    out.set("configured",configured); out.set("enabled",enabled); out.set("host",host);
    out.set("port",configured?Poco::Dynamic::Var(port):Poco::Dynamic::Var());
    out.set("tlsMode",tlsMode); out.set("sender",sender); out.set("username",username);
    out.set("authMethod",authMethod); out.set("passwordSet",!password.empty()); return out;
}
Poco::JSON::Object EmailDeliverySettings::StoredJSON() const {
    auto out=PublicJSON(); out.remove("passwordSet"); out.set("password",password); return out;
}
bool EmailDeliverySettings::ParseUpdate(const Poco::JSON::Object &body,const EmailDeliverySettings &old,EmailDeliverySettings &next) {
    try {
        for(const auto &kv:body) if(!choice(kv.first,{"enabled","host","port","tlsMode","sender","username","authMethod","passwordAction","password"})) return false;
        if(!body.has("enabled") || body.get("enabled").type()!=typeid(bool)) return false;
        next=old; next.enabled=body.getValue<bool>("enabled");
        for(auto field:{"host","tlsMode","sender","username","authMethod","passwordAction"})
            if(!body.has(field)||!body.get(field).isString()) return false;
        next.host=body.getValue<std::string>("host"); next.tlsMode=body.getValue<std::string>("tlsMode");
        next.sender=body.getValue<std::string>("sender"); next.username=body.getValue<std::string>("username");
        next.authMethod=body.getValue<std::string>("authMethod");
        if(!body.has("port") || !body.get("port").isInteger() || body.get("port").type()==typeid(bool)) return false;
        auto port=body.getValue<long long>("port"); if(port<1||port>65535) return false; next.port=port;
        if(next.host.empty()||!clean(next.host)||next.host.find_first_of(" /\\:@")!=std::string::npos ||
            !email(next.sender)||!clean(next.username)||!choice(next.tlsMode,{"none","starttls","implicit"})||
            !choice(next.authMethod,{"none","login","plain","cram-md5"})) return false;
        auto action=body.getValue<std::string>("passwordAction");
        if(action=="set") {
            if(!body.has("password")||!body.get("password").isString()) return false;
            next.password=body.getValue<std::string>("password");
            if(next.password.empty()||!clean(next.password,4096)) return false;
        } else if(action=="clear") { if(body.has("password")) return false; next.password.clear(); }
        else if(action=="retain") { if(body.has("password")) return false; }
        else return false;
        if(next.enabled && next.authMethod!="none" && (next.username.empty()||next.password.empty())) return false;
        next.configured=true; return true;
    } catch(...) { return false; }
}
EmailDeliverySettings EmailSettingsStore::Snapshot() { std::lock_guard lock(mutex_); return settings_; }
bool EmailSettingsStore::Available() { std::lock_guard lock(mutex_); return available_; }
void EmailSettingsStore::Load(const std::string &path) {
    std::lock_guard lock(mutex_); path_=path; settings_={}; available_=true;
    int fd=open(path.c_str(),O_RDONLY|O_NOFOLLOW);
    if(fd<0) { if(errno!=ENOENT) available_=false; return; }
    struct stat st{};
    if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid!=geteuid()||(st.st_mode&077)!=0||st.st_size>32768) {
        close(fd);available_=false;return;
    }
    std::string data;char buf[4096];ssize_t n;
    while((n=read(fd,buf,sizeof(buf)))>0)data.append(buf,n);
    close(fd);
    try {
        if(n<0)throw std::runtime_error("read");
        Poco::JSON::Parser parser; auto body=parser.parse(data).extract<Poco::JSON::Object::Ptr>();
        body->remove("configured");body->remove("passwordSet");
        auto password=body->optValue<std::string>("password","");
        if(password.empty()){body->remove("password");body->set("passwordAction","clear");}
        else body->set("passwordAction","set");
        EmailDeliverySettings next;
        if(!EmailDeliverySettings::ParseUpdate(*body,{},next))throw std::runtime_error("invalid");
        settings_=next;
    }catch(...){available_=false;}
}
EmailSettingsStore::SaveResult EmailSettingsStore::Save(const Poco::JSON::Object &body) {
    std::lock_guard lock(mutex_);
    if(!available_||path_.empty())return SaveResult::unavailable;
    EmailDeliverySettings next;
    if(!EmailDeliverySettings::ParseUpdate(body,settings_,next))return SaveResult::invalid;
    std::ostringstream stream;next.StoredJSON().stringify(stream);auto data=stream.str();
    auto tmp=path_+".XXXXXX";std::vector<char> filename(tmp.begin(),tmp.end());filename.push_back(0);
    int fd=mkstemp(filename.data());if(fd<0)return SaveResult::unavailable;
    bool ok=fchmod(fd,0600)==0;std::size_t offset=0;
    while(ok&&offset<data.size()){auto n=write(fd,data.data()+offset,data.size()-offset);if(n<=0)ok=false;else offset+=n;}
    if(ok)ok=fsync(fd)==0;
    if(close(fd))ok=false;
    if(ok)ok=rename(filename.data(),path_.c_str())==0;
    if(!ok){unlink(filename.data());return SaveResult::unavailable;}
    settings_=next;return SaveResult::saved;
}
}
