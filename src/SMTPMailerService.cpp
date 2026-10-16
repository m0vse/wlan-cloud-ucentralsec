//
// Created by stephane bourque on 2021-06-17.
//

#include "Poco/Exception.h"
#include "Poco/Net/Context.h"
#include "Poco/Net/MailMessage.h"
#include "Poco/Net/MailRecipient.h"
#include "Poco/Net/NetException.h"
#include "Poco/Net/SMTPClientSession.h"
#include "Poco/Net/SSLManager.h"
#include "Poco/Net/SecureSMTPClientSession.h"
#include "Poco/Net/SecureStreamSocket.h"
#include "Poco/Net/RejectCertificateHandler.h"
#include "Poco/Net/StringPartSource.h"

#include "AuthService.h"
#include "SMTPMailerService.h"
#include "SMSDeliverySettings.h"

#include "fmt/format.h"
#include "framework/MicroServiceFuncs.h"
#include "framework/utils.h"

namespace OpenWifi {
	namespace {
	// Alerts use bounded TCP connection setup without changing legacy mail/MFA.
	// Explicit hostname passed at STARTTLS keeps certificate validation on the
	// configured DNS name even though the initial connection was pre-established.
	class AlertSMTPSession : public Poco::Net::SMTPClientSession {
	public:
		explicit AlertSMTPSession(const Poco::Net::StreamSocket &socket)
			: Poco::Net::SMTPClientSession(socket) {}
		void StartTLS(Poco::Net::Context::Ptr context,const std::string &hostname) {
			socket().sendMessage("STARTTLS");
			std::string response;
			if(socket().receiveStatusMessage(response)!=220)
				throw Poco::Net::SMTPException("SMTP TLS required");
			socket()=Poco::Net::SecureStreamSocket::attach(socket(),hostname,context);
		}
	};
	}

	void SMTPMailerService::LoadMyConfig() {
		std::lock_guard lock(Mutex_);
		TemplateDir_ = MicroServiceConfigPath("mailer.templates", MicroServiceDataDirectory());
		Enabled_ = MicroServiceConfigGetBool("mailer.enabled", false);
		if (Enabled_) {
			MailHost_ = MicroServiceConfigGetString("mailer.hostname", "");
			SenderLoginUserName_ = MicroServiceConfigGetString("mailer.username", "");
			SenderLoginPassword_ = MicroServiceConfigGetString("mailer.password", "");
			Sender_ = MicroServiceConfigGetString("mailer.sender", "");
			LoginMethod_ = MicroServiceConfigGetString("mailer.loginmethod", "");
			MailHostPort_ = MicroServiceConfigGetInt("mailer.port", 587);
			TemplateDir_ = MicroServiceConfigPath("mailer.templates", MicroServiceDataDirectory());
			MailRetry_ = MicroServiceConfigGetInt("mailer.retry", 2 * 60);
			MailAbandon_ = MicroServiceConfigGetInt("mailer.abandon", 2 * 60 * 60);
			UseHTML_ = MicroServiceConfigGetBool("mailer.html", false);
			Enabled_ = (!MailHost_.empty() && !SenderLoginPassword_.empty() &&
						!SenderLoginUserName_.empty());
			LogoFilename = AuthService()->GetLogoAssetURI();
			SubLogoFilename = AuthService()->GetSubLogoAssetURI();
		}
	}

	void SMTPMailerService::AddUserVars(MessageAttributes &Attrs) {
		Attrs[USER_HELPER_EMAIL] = AuthService()->HelperEmail();
		Attrs[USER_SYSTEM_LOGIN] = AuthService()->SystemLoginSite();
		Attrs[USER_HELPER_SITE] = AuthService()->HelperSite();
		Attrs[GLOBAL_USER_HELPER_EMAIL] = AuthService()->GlobalHelperEmail();
		Attrs[USER_SIGNATURE] = AuthService()->UserSignature();
	}

	void SMTPMailerService::AddSubVars(MessageAttributes &Attrs) {
		Attrs[SUB_HELPER_EMAIL] = AuthService()->SubHelperEmail();
		Attrs[SUB_SYSTEM_LOGIN] = AuthService()->SubSystemLoginSite();
		Attrs[SUB_HELPER_SITE] = AuthService()->SubHelperSite();
		Attrs[GLOBAL_SUB_HELPER_EMAIL] = AuthService()->GlobalSubHelperEmail();
		Attrs[SUB_SIGNATURE] = AuthService()->SubSignature();
	}

	int SMTPMailerService::Start() {
		EmailSettingsStore::Instance().Load(MicroServiceDataDirectory()+"/email-settings.json");
		SMSSettingsStore::Instance().Load(MicroServiceDataDirectory()+"/sms-settings.json");
		LoadMyConfig();
		SenderThr_.start(*this);
		return 0;
	}

	void SMTPMailerService::Stop() {
		Running_ = false;
		SenderThr_.wakeUp();
		SenderThr_.join();
	}

	void SMTPMailerService::reinitialize([[maybe_unused]] Poco::Util::Application &self) {
		MicroServiceLoadConfigurationFile();
		poco_information(Logger(), "Reinitializing.");
		LoadMyConfig();
	}

	bool SMTPMailerService::SendMessage([[maybe_unused]] const std::string &Recipient,
										const std::string &Name, const MessageAttributes &Attrs,
										bool Subscriber) {
		if(!Enabled())return false;
		std::lock_guard G(Mutex_);
		PendingMessages_.push_back(MessageEvent{.Posted = OpenWifi::Now(),
												.LastTry = 0,
												.Sent = 0,
												.TemplateName = Name,
												.Attrs = Attrs,
												.Subscriber = Subscriber});
		return true;
	}

	void SMTPMailerService::run() {
		Running_ = true;
		Utils::SetThreadName("smtp-mailer");
		while (Running_) {

			Poco::Thread::trySleep(10000);
			if (!Running_)
				break;
			{
				std::lock_guard G(Mutex_);
				Messages_.splice(Messages_.end(), PendingMessages_);
			}

			for (auto i = Messages_.begin(); i != Messages_.end();) {
				if (!Running_)
					break;
				auto Recipient = i->Attrs.find(RECIPIENT_EMAIL)->second;
				uint64_t now = OpenWifi::Now();
				if ((i->LastTry == 0 || (now - i->LastTry) > MailRetry_)) {
					switch (SendIt(*i)) {
					case MessageSendStatus::msg_sent: {
						poco_information(
							Logger(),
							fmt::format("Attempting to deliver for mail '{}'.", Recipient));
						i = Messages_.erase(i);
					} break;
					case MessageSendStatus::msg_not_sent_but_resend: {
						poco_information(
							Logger(),
							fmt::format("Mail for '{}' was not. We will retry later.", Recipient));
						i->LastTry = now;
						++i;
					} break;
					case MessageSendStatus::msg_not_sent_but_do_not_resend: {
						poco_information(
							Logger(),
							fmt::format("Mail for '{}' will not be sent. Check email address",
										Recipient));
						i = Messages_.erase(i);
					} break;
					}
				} else if ((now - i->Posted) > MailAbandon_) {
					poco_information(
						Logger(), fmt::format("Mail for '{}' has timed out and will not be sent.",
											  Recipient));
					i = Messages_.erase(i);
				} else {
					++i;
				}
			}
		}
	}

	void FillVariables(const MessageAttributes &Attrs, Types::StringPairVec &R) {
		for (const auto &[Variable, Value] : Attrs) {
			R.push_back(std::make_pair(MessageAttributeToVar(Variable), Value));
		}
	}

	MessageSendStatus SMTPMailerService::SendIt(const MessageEvent &Msg) {

		std::string Recipient;

		try {
			if(!EmailSettingsStore::Instance().Available())return MessageSendStatus::msg_not_sent_but_do_not_resend;
			EmailDeliverySettings delivery;
			std::string templateDir;
			{
				std::lock_guard lock(Mutex_);
				delivery.host=MailHost_;delivery.port=MailHostPort_;delivery.sender=Sender_;
				delivery.username=SenderLoginUserName_;delivery.password=SenderLoginPassword_;
				delivery.authMethod=LoginMethod_;delivery.tlsMode="starttls";delivery.enabled=Enabled_;
				templateDir=TemplateDir_;
			}
			auto saved=EmailSettingsStore::Instance().Snapshot();if(saved.configured)delivery=saved;
			if(!delivery.enabled)return MessageSendStatus::msg_not_sent_but_do_not_resend;
			auto H1 = Msg.Attrs.find(SENDER);
			std::string TheSender;
			if (H1 != Msg.Attrs.end()) {
				TheSender = H1->second;
			} else {
				TheSender = delivery.sender;
			}

			auto Message = std::make_unique<Poco::Net::MailMessage>();

			Recipient = Msg.Attrs.find(RECIPIENT_EMAIL)->second;
			std::string From=TheSender;
			if(TheSender==delivery.sender && !delivery.senderName.empty()) {
				auto name=Poco::Net::MailMessage::encodeWord(delivery.senderName);
				if(name==delivery.senderName) {
					std::string quoted="\"";
					for(char c:name) { if(c=='\\' || c=='\"')quoted+='\\';quoted+=c; }
					name=quoted+'\"';
				}
				From=name+" <"+TheSender+">";
			}
			Message->setSender(From);
			Message->addRecipient(
				Poco::Net::MailRecipient(Poco::Net::MailRecipient::PRIMARY_RECIPIENT, Recipient));
			Message->setSubject(Msg.Attrs.find(SUBJECT)->second);
			Message->setContentType("multipart/alternative");

			if(!Msg.PrivateAlert) {
				poco_information(Logger(),fmt::format("Sending message to:{} from {}", Recipient, TheSender));
			}

			if (Msg.Attrs.find(TEXT) != Msg.Attrs.end()) {
				std::string Content = Msg.Attrs.find(TEXT)->second;
				Message->addContent(new Poco::Net::StringPartSource(Content,
					Msg.PrivateAlert ? "text/plain; charset=UTF-8" : "text/plain"));
				auto html=Msg.Attrs.find(ALERT_HTML);
				if(html!=Msg.Attrs.end())Message->addContent(new Poco::Net::StringPartSource(html->second,"text/html; charset=UTF-8"));
			} else {
				for (const auto &format : {"txt", "html"}) {
					std::string Content =
						Utils::LoadFile(templateDir + Msg.TemplateName + "." + format);
					Types::StringPairVec Variables;
					FillVariables(Msg.Attrs, Variables);
					Utils::ReplaceVariables(Content, Variables);
					Message->addContent(new Poco::Net::StringPartSource(
						Content, (strcmp(format, "html") == 0 ? "text/html" : "text/plain")));
				}
			}

			/*
			auto Logo = Msg.Attrs.find(LOGO);
			if(Logo!=Msg.Attrs.end()) {
				std::cout << "... >" << Logo->second << std::endl;
				try {
					Poco::File          LogoFile( Msg.Subscriber ?
			AuthService::GetSubLogoAssetFileName() :  AuthService::GetLogoAssetFileName ());
					std::ifstream       IF(LogoFile.path());
					std::ostringstream  OS;
					Poco::StreamCopier::copyStream(IF, OS);
					Message->addAttachment("logo", new Poco::Net::StringPartSource(OS.str(),
			"image/png")); } catch (...) { poco_warning(Logger(),fmt::format("Cannot add '{}' logo
			in email",AuthService::GetLogoAssetFileName()));
				}
			}
			*/

			// Dedicated verified SMTP context: never replace the global HTTPS client trust.
			auto context=Poco::AutoPtr<Poco::Net::Context>(new Poco::Net::Context(
				Poco::Net::Context::TLS_CLIENT_USE,"","","",Poco::Net::Context::VERIFY_STRICT,9,true));
			context->setInvalidCertificateHandler(new Poco::Net::RejectCertificateHandler(false));
			std::unique_ptr<Poco::Net::SMTPClientSession> session;
			if(Msg.PrivateAlert) {
				Poco::Net::StreamSocket socket;
				socket.connect(Poco::Net::SocketAddress(delivery.host,delivery.port),Poco::Timespan(15,0));
				socket.setReceiveTimeout(Poco::Timespan(15,0));
				socket.setSendTimeout(Poco::Timespan(15,0));
				if(delivery.tlsMode=="implicit") {
					auto secure=Poco::Net::SecureStreamSocket::attach(socket,delivery.host,context);
					session=std::make_unique<AlertSMTPSession>(secure);
				} else {
					auto alert=std::make_unique<AlertSMTPSession>(socket);
					alert->setTimeout(Poco::Timespan(15,0));
					if(delivery.tlsMode=="starttls") {alert->login();alert->StartTLS(context,delivery.host);}
					session=std::move(alert);
				}
			} else if(delivery.tlsMode=="implicit") {
				Poco::Net::SecureStreamSocket socket(Poco::Net::SocketAddress(delivery.host,delivery.port),delivery.host,context);
				session=std::make_unique<Poco::Net::SMTPClientSession>(socket);
			} else if(delivery.tlsMode=="starttls") {
				auto secure=std::make_unique<Poco::Net::SecureSMTPClientSession>(delivery.host,delivery.port);
				secure->setTimeout(Poco::Timespan(15,0));secure->login();
				if(!secure->startTLS(context))throw Poco::Net::SMTPException("SMTP TLS required");
				session=std::move(secure);
			} else session=std::make_unique<Poco::Net::SMTPClientSession>(delivery.host,delivery.port);
			session->setTimeout(Poco::Timespan(15,0));
			if(delivery.authMethod=="none")session->login();
			else {
				auto method=delivery.authMethod=="plain"?Poco::Net::SMTPClientSession::AUTH_PLAIN:
					delivery.authMethod=="cram-md5"?Poco::Net::SMTPClientSession::AUTH_CRAM_MD5:Poco::Net::SMTPClientSession::AUTH_LOGIN;
				session->login(delivery.host,method,delivery.username,delivery.password);
			}
			/*            std::ofstream
			   of(MicroServiceDataDirectory()+"/message.txt",std::ios_base::out|std::ios_base::trunc);
						Message->write(of);
						of.close();
			*/
			session->sendMessage(*Message);
			session->close();
			return MessageSendStatus::msg_sent;
		} catch (const Poco::Net::SMTPException &S) {
			poco_warning(Logger(),"SMTP delivery rejected; check saved delivery settings.");
			return MessageSendStatus::msg_not_sent_but_do_not_resend;
		} catch (const Poco::Exception &E) {
			poco_warning(Logger(),"SMTP delivery unavailable; retry pending.");
			return MessageSendStatus::msg_not_sent_but_resend;
		} catch (const std::exception &E) {
			poco_warning(Logger(),
						 "SMTP delivery failed.");
			return MessageSendStatus::msg_not_sent_but_do_not_resend;
		}
	}

} // namespace OpenWifi
