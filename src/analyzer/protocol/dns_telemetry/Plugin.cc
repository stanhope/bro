
#include "plugin/Plugin.h"

#include "DNS.h"
BRO_PLUGIN_BEGIN(Bro, DNS_TELEMETRY)
	BRO_PLUGIN_DESCRIPTION("DNS Telemetry analyzer");
	BRO_PLUGIN_ANALYZER("DNS_TELEMETRY", dns_telemetry::DNS_Telemetry_Analyzer);
	BRO_PLUGIN_SUPPORT_ANALYZER("Contents_DNS_Telemetry");
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
