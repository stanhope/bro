// See the file "COPYING" in the main distribution directory for copyright.

// TODOs
//
// 1) Implement per zone QNAME reporting. The current implementation will enable for ALL qnames. This is way to expensive.
//
//    A possible solution to this is to stop all use of the BRO logging framework and leverage the capability do high-volume
//    details logging.

#include "config.h"

#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unordered_map>

#include "NetVar.h"
#include "DNS.h"
#include "Sessions.h"
#include "Event.h"
#include "Hash.h"
#include "Dict.h"
#include "File.h"

#include "events.bif.h"

#include <unordered_map>
#include "hash_func.h"

using namespace analyzer::dns_telemetry;

struct CurCounts {
  uint request;
  uint rejected;
  uint reply;
  uint non_dns_request;
  uint ANY_RD;
  uint ANY;
  uint A;
  uint AAAA;
  uint NS;
  uint CNAME;
  uint PTR;
  uint SOA;
  uint MX;
  uint TXT;
  uint SRV;
  uint other;
  uint TCP;
  uint UDP;
  uint TSIG;
  uint EDNS;
  uint RD;
  uint DO;
  uint CD;
  uint V4;
  uint V6;
  uint OpQuery;
  uint OpIQuery;
  uint OpStatus;
  uint OpNotify;
  uint OpUpdate;
  uint OpUnassigned;
  uint rcode_noerror;
  uint rcode_format_err;
  uint rcode_server_fail;
  uint rcode_nxdomain;
  uint rcode_not_impl;
  uint rcode_refused;
  uint logged;
  uint qlen;
  uint rlen;
  uint clients;
  uint zones;
  uint MBsec;
};

struct AnyRDCounts {
  char ip[20];
  char query[128];
  int cnt;
};

struct ZoneInfo {
  char key[128];
  int zone_id;
  int owner_id;
  int log_id;
  int stat_id;
  int qname_id;
  bool details;
};

struct OwnerStats {
  uint id;
  uint cnt;
};

declare(PDict,OwnerStats);

PDict(OwnerStats) OWNER_INFO;

struct ZoneStats {
  char key[255];
  uint zone_id;
  uint owner_id;
  uint cnt;
  uint A;
  uint AAAA;
  uint CNAME;
  uint MX;
  uint SOA;
  uint TXT;
  uint PTR;
  uint SRV;
  uint NS;
  uint other;
  uint DO;
  uint RD;
  uint NOERROR;
  uint NXDOMAIN;
  uint REFUSED;
};

struct QnameStats {
  char query[255];
  uint zone_id;
  uint owner_id;
  int cnt;
  int A;
  int AAAA;
  int CNAME;
  int MX;
  int SOA;
  int TXT;
  int PTR;
  int SRV;
  int NS;
  int other;
};

declare(PDict,int);
declare(PDict,QnameStats);
declare(PDict,ZoneStats);
declare(PDict,ZoneInfo);

PDict(int) telemetry_anyrd_counts;
PDict(int) telemetry_client_stats;
PDict(QnameStats) telemetry_qname_stats;
PDict(ZoneStats) telemetry_zone_stats;
PDict(ZoneInfo) telemetry_zone_info;

#define UNORDERED_MAP
unordered_map<string, ZoneInfo*> zone_info;
// unordered_map<string, ZoneInfo*, SuperFastHashChar, StringKeyEq> zone_info;
// unordered_map<string, ZoneInfo*, JesteressHashChar, StringKeyEq> zone_info;
// unordered_map<string, ZoneInfo*, MurmorChar, StringKeyEq> zone_info;

struct ZoneMapInfo {
  char fname[512];
  time_t last_mod;
};

ZoneMapInfo ZONE_MAP_INFO;

class ZoneUpdater : public threading::MsgThread {
public:
  ZoneUpdater(char* _fname, double _interval = 60);
  virtual ~ZoneUpdater();
  virtual bool OnHeartbeat(double network_time, double current_time);
  virtual bool OnFinish(double network_time);
protected:
  double interval;
  double next;
  time_t last;
  char* fname;
};

ZoneUpdater::ZoneUpdater(char* _fname, double _interval) {
  SetName("ZoneUpdater");
  interval = _interval;
  fname = _fname;
  next = current_time() + interval;
  struct stat buf;
  stat(fname, &buf);
  int size = buf.st_size;
  last = buf.st_mtime;
}

ZoneUpdater::~ZoneUpdater() {
}

int __dns_telemetry_set_zones(const char* fname, const char* details_fname);

bool ZoneUpdater::OnHeartbeat(double network_time, double current_time) {
  if (current_time > next) {
    // See if the zonemap has changed
    struct stat buf;
    stat(ZONE_MAP_INFO.fname, &buf);
    if (buf.st_mtime != ZONE_MAP_INFO.last_mod) {
      static char old_timestr[256];
      strftime(old_timestr, sizeof(old_timestr), "%Y%m%dT%H%M%S", localtime(&ZONE_MAP_INFO.last_mod));
      static char new_timestr[256];
      strftime(new_timestr, sizeof(new_timestr), "%Y%m%dT%H%M%S", localtime(&buf.st_mtime));
      fprintf(stderr,"%f zonemap change detected old=%s new=%s\n", current_time, old_timestr, new_timestr);
      __dns_telemetry_set_zones(ZONE_MAP_INFO.fname, NULL);
    }
    next += interval;
  }
  return 1;
}

bool ZoneUpdater::OnFinish(double network_time) {
  return 1;
}

ZoneUpdater* ZONE_UPDATER = NULL;

bool do_counts = false;
bool do_totals = false;
bool do_zone_stats = true;
bool do_owner_stats = true;
bool do_qname_stats = true;
bool do_anyrd_stats = true;
bool do_client_stats = true;
bool do_details = true;

struct DetailLogInfo {
  double ts;
  int owner_id;
  int log_id;
  int zone_id;
  // uint cnt;
  bool enabled;
  PDict(int) zones;
  char* fname;
  BroFile* file;
};

declare(PDict,DetailLogInfo);
PDict(DetailLogInfo) DETAIL_LOGGER_INFO;
char DETAIL_DEFAULT_PATH[256];

// Tracks open loggers. Important for the MultiZone (logid=2) scenario.
PDict(DetailLogInfo) DETAIL_LOGGER_OPEN;

// Allow per zone stats telemetry
struct StatsLogInfo {
  char* fname;
  BroFile* file;
  int owner_id;
  bool enabled;
  CurCounts CNTS;
};
declare(PDict,StatsLogInfo);
PDict(StatsLogInfo) STATS_LOGGER_INFO;

// Allow per zone stats qname stats. Per Zone for Filter
struct QnameFilter {
  int owner_id;
  int zone_id;
  bool enabled;
};
declare(PDict,QnameFilter);
PDict(QnameFilter) QNAME_FILTERS;


CurCounts CNTS;
CurCounts TOTALS;

DNS_Telemetry_Interpreter::DNS_Telemetry_Interpreter(analyzer::Analyzer* arg_analyzer)
	{
	analyzer = arg_analyzer;
	}

int DNS_Telemetry_Interpreter::ParseMessage(const u_char* data, int len, int is_query)
	{
	int hdr_len = sizeof(DNS_RawMsgHdr);

	if ( len < hdr_len )
		{
		analyzer->Weird("DNS_truncated_len_lt_hdr_len");
		return 0;
		}

	DNS_Telemetry_MsgInfo msg((DNS_RawMsgHdr*) data, is_query);

	qlen = 0;
	rlen = 0;

	if (do_counts) {
	  if (is_query) {
	    CNTS.qlen += len;
	    TOTALS.qlen += len;
	    qlen = len;
	  } else {
	    CNTS.rlen += len;
	    TOTALS.rlen += len;
	    rlen = len;
	  }
	}

	if ( dns_telemetry_message )
		{
		val_list* vl = new val_list();
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(is_query, TYPE_BOOL));
		vl->append(msg.BuildHdrVal());
		vl->append(new Val(len, TYPE_COUNT));
		analyzer->ConnectionEvent(dns_telemetry_message, vl);
		}

	// There is a great deal of non-DNS traffic that runs on port 53.
	// This should weed out most of it.
	if ( dns_max_queries > 0 && msg.qdcount > dns_max_queries )
		{
		analyzer->ProtocolViolation("DNS_Conn_count_too_large");
		analyzer->Weird("DNS_Conn_count_too_large");
		EndMessage(&msg);
		return 0;
		}

	const u_char* msg_start = data;	// needed for interpreting compression

	// if (is_query) fprintf(stderr, "ParseMessage len=%d\n", len);

	data += hdr_len;
	len -= hdr_len;

	if ( ! ParseQuestions(&msg, data, len, msg_start, is_query) )
		{
		EndMessage(&msg);
		return 0;
		}

	/*

	if ( ! ParseAnswers(&msg, msg.ancount, DNS_ANSWER,
				data, len, msg_start) )
		{
		EndMessage(&msg);
		return 0;
		}

	*/

	analyzer->ProtocolConfirmation();

	/*
	AddrVal server(analyzer->Conn()->RespAddr());

	int skip_auth = dns_skip_all_auth;
	int skip_addl = dns_skip_all_addl;
	if ( msg.ancount > 0 )
		{ // We did an answer, so can potentially skip auth/addl.
		skip_auth = skip_auth || msg.nscount == 0 ||
				dns_skip_auth->Lookup(&server);
		skip_addl = skip_addl || msg.arcount == 0 ||
				dns_skip_addl->Lookup(&server);
		}

	if ( skip_auth && skip_addl )
		{
		// No point doing further work parsing the message.
		EndMessage(&msg);
		return 1;
		}

	msg.skip_event = skip_auth;
	if ( ! ParseAnswers(&msg, msg.nscount, DNS_AUTHORITY,
				data, len, msg_start) )
		{
		EndMessage(&msg);
		return 0;
		}

	if ( skip_addl )
		{
		// No point doing further work parsing the message.
		EndMessage(&msg);
		return 1;
		}

	msg.skip_event = skip_addl;
	if ( ! ParseAnswers(&msg, msg.arcount, DNS_ADDITIONAL,
				data, len, msg_start) )
		{
		EndMessage(&msg);
		return 0;
		}

	EndMessage(&msg);
	*/
	return 1;
	}

int DNS_Telemetry_Interpreter::EndMessage(DNS_Telemetry_MsgInfo* msg)
	{
	  fprintf(stderr, "EndMessage\n");
	  return 1;
	}

int DNS_Telemetry_Interpreter::ParseQuestions(DNS_Telemetry_MsgInfo* msg,
				const u_char*& data, int& len,
					      const u_char* msg_start, int is_query)
	{
	int n = msg->qdcount;

	if ( n == 0 )
		{
		// Generate event here because we won't go into ParseQuestion.
		EventHandlerPtr dns_event =
			msg->rcode == DNS_CODE_OK ?
				dns_telemetry_query_reply : dns_telemetry_rejected;
		BroString* question_name = new BroString("<no query>");
		SendReplyOrRejectEvent(msg, dns_event, data, len, question_name);
		return 1;
		}

	while ( n > 0 && ParseQuestion(msg, data, len, msg_start, is_query) )
		--n;
	return n == 0;
	}

int DNS_Telemetry_Interpreter::ParseAnswers(DNS_Telemetry_MsgInfo* msg, int n, DNS_AnswerType atype,
				const u_char*& data, int& len,
				const u_char* msg_start)
	{
	msg->answer_type = atype;
	while ( n > 0 && ParseAnswer(msg, data, len, msg_start) )
		--n;
	return n == 0;
	}

int DNS_Telemetry_Interpreter::ParseQuestion(DNS_Telemetry_MsgInfo* msg,
					     const u_char*& data, int& len,
					     const u_char* msg_start, int is_query)
{
  u_char name[513];
  int name_len = sizeof(name) - 1;

  // if (is_query) fprintf(stderr, "ParseQuestion len=%d\n", len);
  int hdr_len = sizeof(DNS_RawMsgHdr);
  int msg_len = len + hdr_len;

  char tlz [255];
  u_char* name_end;

  name_end = ExtractName(data, len, name, name_len, msg_start, tlz);

  if ( ! name_end )
    return 0;

  if ( len < int(sizeof(short)) * 2 )
    {
      analyzer->Weird("DNS_truncated_quest_too_short");
      return 0;
    }

  EventHandlerPtr dns_event = 0;
  ZoneStats* zv = 0;
  HashKey* zone_hash = new HashKey(tlz);
  ZoneInfo* zinfo = 0;
  OwnerStats* owner_stats = 0;
  bool do_zone_details = false;

  CurCounts* custom_stats= 0;

  bro_int_t owner_id = 0;

  if (do_zone_stats && dns_telemetry_zone_info) {

#ifdef UNORDERED_MAP
    unordered_map<string,ZoneInfo*>::const_iterator got = zone_info.find(tlz);
    zinfo = got == zone_info.end() ? NULL : got->second;
#else
    zinfo = telemetry_zone_info.Lookup(zone_hash);
#endif

    if (!zinfo) {
      // Get rid of the zoneid based specific hash and use the OTHER zone hash
      delete zone_hash;
      const char other[] = "OTHER";
      HashKey* other_hash = new HashKey(other);
      zv = telemetry_zone_stats.Lookup(other_hash);
      zone_hash = other_hash;
    } else {
      zv = telemetry_zone_stats.Lookup(zone_hash);
      do_zone_details = zinfo->details;
      owner_id = (bro_int_t)zinfo->owner_id;

      HashKey* stat_logger_key = new HashKey(owner_id);
      StatsLogInfo* stat_logger = STATS_LOGGER_INFO.Lookup(stat_logger_key);
      if (stat_logger) {
	custom_stats = &stat_logger->CNTS;
      }
      delete stat_logger_key;
    }

    if (do_counts) {

      if (is_query) {
	if (custom_stats) {
	  ++custom_stats->request;
	  custom_stats->qlen += qlen;
	}	
      
	if (analyzer->Conn()->ConnTransport() == TRANSPORT_TCP) {
	  ++CNTS.TCP;
	  ++TOTALS.TCP;
	  if (custom_stats) ++custom_stats->TCP;
	} else {
	  // Not really true :-(
	  ++CNTS.UDP;
	  ++TOTALS.UDP;
	  if (custom_stats) ++custom_stats->UDP;
	}
      
	if (analyzer->Conn()->GetOrigFlowLabel() == 0) {
	  ++CNTS.V4;
	  ++TOTALS.V4;
	  if (custom_stats) ++custom_stats->V4;
	} else {
	  ++CNTS.V6;
	  ++TOTALS.V6;
	  if (custom_stats) ++custom_stats->V4;
	}

	switch (msg->opcode) 
	  {
	  case DNS_OP_QUERY:
	    ++CNTS.OpQuery;
	    ++TOTALS.OpQuery;
	    if (custom_stats) ++custom_stats->OpQuery;
	    break;
	  case DNS_OP_IQUERY:
	    ++CNTS.OpIQuery;
	    ++TOTALS.OpIQuery;
	    if (custom_stats) ++custom_stats->OpIQuery;
	    break;
	  case DNS_OP_SERVER_STATUS:
	    ++CNTS.OpStatus;
	    ++TOTALS.OpStatus;
	    if (custom_stats) ++custom_stats->OpStatus;
	    break;
	  case 4:
	    ++CNTS.OpNotify;
	    ++TOTALS.OpNotify;
	    if (custom_stats) ++custom_stats->OpNotify;
	    break;
	  case 5:
	    ++CNTS.OpUpdate;
	    ++TOTALS.OpUpdate;
	    if (custom_stats) ++custom_stats->OpUpdate;
	    break;
	  default:
	    ++CNTS.OpUnassigned;
	    ++TOTALS.OpUnassigned;
	    if (custom_stats) ++custom_stats->OpUnassigned;
	    break;
	  }
	if (msg->RD) {
	  ++CNTS.RD;
	  ++TOTALS.RD;
	  if (custom_stats) ++custom_stats->RD;
	}
      } else {
	if (custom_stats) {
	  custom_stats->rlen += rlen;
	}	
      }
    }

    if (do_owner_stats && is_query) {
      // NOTE: The owner_id may the actual zone's ... or the OTHER owner id (0)
      HashKey* key = new HashKey(owner_id);
      owner_stats = OWNER_INFO.Lookup(key);
      if (owner_stats == 0) {
	// We don't even have an OTHER stats collector yet, create one
	owner_stats = new OwnerStats();
	owner_stats->id = 0;
	owner_stats->cnt = 0;
	OWNER_INFO.Insert(key, owner_stats);
      }
      ++owner_stats->cnt;
      delete key;
    }

    if (!zv) {
	      
      ++CNTS.zones;
      if (custom_stats) 
	++custom_stats->zones;
      zv = new ZoneStats();
      zv->cnt = 0;

      if (zinfo) {
	// A zone we know about
	strcpy(zv->key, tlz);
	zv->zone_id = zinfo->zone_id;
	zv->owner_id = zinfo->owner_id;
      } else {
	// OTHER bucket for now
	strcpy(zv->key, "OTHER");
	zv->zone_id = 0;
	zv->owner_id = 0;
      }
      telemetry_zone_stats.Insert(zone_hash, zv);
    }

  }

  QnameStats* qname_stat = 0;
  bool local_do_qname_stats = do_qname_stats;

  if (is_query && do_qname_stats && dns_telemetry_qname_info) {
    if (zinfo) {
      HashKey* filter_key = new HashKey((bro_int_t)zinfo->zone_id);
      QnameFilter* filter = QNAME_FILTERS.Lookup(filter_key);
      if (filter && filter->enabled) {
	char qname_key[256];
	sprintf(qname_key, "%s", name);
	HashKey* qname_hash = new HashKey(qname_key);
	qname_stat = telemetry_qname_stats.Lookup(qname_hash);
	if (!qname_stat) {
	  qname_stat = new QnameStats();
	  qname_stat->cnt = 0;
	  telemetry_qname_stats.Insert(qname_hash, qname_stat);
	} else {
	  ++qname_stat->cnt;
	}
	delete qname_hash;
	qname_stat->zone_id = zinfo->zone_id;
	qname_stat->owner_id = zinfo->owner_id;
      }
      delete filter_key;
      local_do_qname_stats = qname_stat != NULL;
    } else {
      fprintf(stderr, "ERROR: No zinfo!\n");
    }
  }

  if ( msg->QR == 0 ) {

    dns_event = dns_telemetry_request;

    if (do_counts) {
      ++CNTS.request;
      ++TOTALS.request;
    }
    if (do_zone_stats) {
      ++zv->cnt;
      if (msg->RD) {
	++zv->RD;
      }
    }
	
    const IPAddr& orig_addr = analyzer->Conn()->OrigAddr();
    string sAddr = orig_addr.AsString();
    if (is_query && do_client_stats) {
      char client_key[50];
      strcpy(client_key, sAddr.c_str()); 
      HashKey* client_hash = new HashKey(client_key);
      int* client_idx = telemetry_client_stats.Lookup(client_hash);
      if (client_idx) {
	++(*client_idx);
      } else {
	telemetry_client_stats.Insert(client_hash, new int(1));
	++CNTS.clients;
	++TOTALS.clients;
	if (custom_stats) {
	  ++custom_stats->clients;
	}
      }
      delete client_hash;
    }

    RR_Type qtype = RR_Type(ExtractShort(data, len));
    msg->qtype = qtype;
    if (do_counts) {
      switch (qtype) 
	{
	case TYPE_A:
	  ++CNTS.A;
	  ++TOTALS.A;
	  if (custom_stats) 
	    ++custom_stats->A;
	  if (local_do_qname_stats)
	    ++qname_stat->A;
	  if (do_zone_stats)
	    ++zv->A;
	  break;
	case TYPE_NS:
	  ++CNTS.NS;
	  ++TOTALS.NS;
	  if (custom_stats) 
	    ++custom_stats->NS;
	  if (local_do_qname_stats)
	    ++qname_stat->NS;
	  if (do_zone_stats)
	    ++zv->NS;
	  break;
	case TYPE_CNAME:
	  ++CNTS.CNAME;
	  ++TOTALS.CNAME;
	  if (custom_stats) 
	    ++custom_stats->CNAME;
	  if (local_do_qname_stats)
	    ++qname_stat->CNAME;
	  if (do_zone_stats)
	    ++zv->CNAME;
	  break;
	case TYPE_SOA:
	  ++CNTS.SOA;
	  ++TOTALS.SOA;
	  if (custom_stats) 
	    ++custom_stats->SOA;
	  if (local_do_qname_stats)
	    ++qname_stat->SOA;
	  if (do_zone_stats)
	    ++zv->SOA;
	  break;
	case TYPE_PTR:
	  ++CNTS.PTR;
	  ++TOTALS.PTR;
	  if (custom_stats) 
	    ++custom_stats->PTR;
	  if (local_do_qname_stats)
	    ++qname_stat->PTR;
	  if (do_zone_stats)
	    ++zv->PTR;
	  break;
	case TYPE_MX:
	  ++CNTS.MX;
	  ++TOTALS.MX;
	  if (custom_stats) 
	    ++custom_stats->MX;
	  if (local_do_qname_stats)
	    ++qname_stat->MX;
	  if (do_zone_stats)
	    ++zv->MX;
	  break;
	case TYPE_TXT:
	  ++CNTS.TXT;
	  ++TOTALS.TXT;
	  if (custom_stats) 
	    ++custom_stats->TXT;
	  if (local_do_qname_stats)
	    ++qname_stat->TXT;
	  if (do_zone_stats)
	    ++zv->TXT;
	  break;
	case TYPE_AAAA:
	  ++CNTS.AAAA;
	  ++TOTALS.AAAA;
	  if (custom_stats) 
	    ++custom_stats->AAAA;
	  if (local_do_qname_stats)
	    ++qname_stat->AAAA;
	  if (do_zone_stats)
	    ++zv->AAAA;
	  break;
	case TYPE_SRV:
	  ++CNTS.SRV;
	  ++TOTALS.SRV;
	  if (custom_stats) 
	    ++custom_stats->SRV;
	  if (local_do_qname_stats)
	    ++qname_stat->SRV;
	  if (do_zone_stats)
	    ++zv->SRV;
	  break;
	case TYPE_ALL:
	  ++CNTS.ANY;
	  ++TOTALS.ANY;
	  if (custom_stats) 
	    ++custom_stats->ANY;
	  if (local_do_qname_stats)
	    ++qname_stat->other;
	  if (do_zone_stats)
	    ++zv->other;
	  if (msg->RD) {
	    ++CNTS.ANY_RD;
	    ++TOTALS.ANY_RD;
	  if (custom_stats) 
	    ++custom_stats->RD;

	    if (do_anyrd_stats) {
	      char anyrd_key[560];
	      sprintf(anyrd_key, "%s|%s", sAddr.c_str(), name);
	      HashKey* anyrd_hash = new HashKey(anyrd_key);
	      // fprintf(stderr, "ANYRD key=%s len=%u hash_key=%s key_size=%d\n", anyrd_key, (unsigned int)strlen(anyrd_key), (const char*)anyrd_hash->Key(), anyrd_hash->Size());
	      int* count_idx = telemetry_anyrd_counts.Lookup(anyrd_hash);
	      if (count_idx) {
		++(*count_idx);
	      } else {
		telemetry_anyrd_counts.Insert(anyrd_hash, new int(1));
	      }
	      delete anyrd_hash;
	    }

	  }
	  break;
	default:
	  ++CNTS.other;
	  ++TOTALS.other;
	  if (custom_stats) 
	    ++custom_stats->other;
	  if (local_do_qname_stats)
	    ++qname_stat->other;
	  if (do_zone_stats)
	    ++zv->other;
	  break;
	}
    }
  }
  else if ( msg->QR == 1 &&
	    msg->ancount == 0 && msg->nscount == 0 && msg->arcount == 0 ) {
    // Service rejected in some fashion, and it won't be reported
    // via a returned RR because there aren't any.
    dns_event = dns_telemetry_rejected;
    if (do_counts) {
      ++CNTS.rejected;
      ++CNTS.rcode_refused;
      ++TOTALS.rejected;
      ++TOTALS.rcode_refused;
      if (custom_stats) {
	++custom_stats->rejected;
	++custom_stats->rcode_refused;
      }
    }
    if (do_zone_stats)
      ++zv->REFUSED;
  }
  else {

    dns_event = dns_telemetry_query_reply;

    if (do_details && do_zone_details) {

      ++CNTS.logged;
      ++TOTALS.logged;
      if (custom_stats)
	++custom_stats->logged;

      const IPAddr& orig_addr = analyzer->Conn()->OrigAddr();
      const IPAddr& resp_addr = analyzer->Conn()->RespAddr();

      char log_line[256];
      sprintf(log_line, "%f,%s,%u,%u,%d,%s,%s,%u", network_time,(char*)name,msg->qtype,msg->rcode,msg->ttl,"","",msg->opcode);
      uint len = strlen(log_line);
      log_line[len++] = '\n';
      log_line[len] = 0;

      // Determine which logger we should use
      DetailLogInfo* logger = 0;
      if (zinfo->log_id != 0) {

	HashKey* log_key = new HashKey((bro_int_t)zinfo->zone_id);
	logger = DETAIL_LOGGER_INFO.Lookup(log_key);

	if (logger == 0) {
	  fprintf(stderr, "WARN: Unexpected lack of DetailLogInfo config zone_id=%d owner_id=%d log_id=%d\n", zinfo->zone_id, zinfo->owner_id, zinfo->log_id);
	  // Create new logger
	  logger = new DetailLogInfo();
	  logger->owner_id = zinfo->owner_id;
	  logger->log_id = zinfo->log_id;
	  logger->ts = network_time;
	  logger->enabled = true;
	  // Use the base multi-tenant logger's root
	  logger->fname = DETAIL_DEFAULT_PATH;
	  DETAIL_LOGGER_INFO.Insert(log_key, logger);
	}
	delete log_key;

	// Switch to using the common logger if that's what's configured
	if (logger->log_id == 3) {
	  logger = NULL;
	}

	if (logger == NULL) {
	  // Default to multi-tenant logger
	  HashKey* log_key = new HashKey((bro_int_t)0);
	  logger = DETAIL_LOGGER_INFO.Lookup(log_key);
	  delete log_key;
	}
	
	if (logger->file == NULL) {
	  static char source_fname[256];
	  static char* root_fname = logger->fname;
	
	  // sprintf(source_fname, "%s-%08d.log", root_fname, logger->owner_id);

	  switch (logger->log_id) 
	    {
	    case 1:
	      {
		// Multi Zone
		sprintf(source_fname, "%s-O-%08d.log", root_fname, logger->owner_id);
		break;
	      }
	    case 2:
	      {
		// Single Zone
		sprintf(source_fname, "%s-Z-%08d.log", root_fname, logger->zone_id);
		break;
	      }
	    case 3:
	      {
		// Common
		sprintf(source_fname, "%s-00000000.log", root_fname);
		break;
	      }
	    default:
	      {
		fprintf(stderr, "ERROR: Unexpected logid=%d name=%s tlz=%s\n", logger->log_id, name, tlz);
		break;
	      }
	    }

	  if (logger->log_id == 1) {
	    // Determine if we've got an open logger for the source name. If so, use that.
	    HashKey* open_logger_key = new HashKey(source_fname);
	    DetailLogInfo* open_logger = DETAIL_LOGGER_OPEN.Lookup(open_logger_key);
	    if (open_logger) {
	      // fprintf(stderr, "Using existing logger %s logid=%d owner=%d my_zone=%d other_zone=%d\n", source_fname, logger->log_id, logger->owner_id, logger->zone_id, open_logger->zone_id);
	      logger->file = open_logger->file;
	    } else {
	      FILE* f = fopen(source_fname, "wb");
	      logger->file = new BroFile(f, source_fname, "wb");
	      DETAIL_LOGGER_OPEN.Insert(open_logger_key, logger);
	      // fprintf(stderr, "Creating logger %s logid=%d owner=%d zone=%d file=%p\n", source_fname, logger->log_id, logger->owner_id, logger->zone_id, logger->file);
	    }
	    delete open_logger_key;

	  } else {
	    FILE* f = fopen(source_fname, "wb");
	    logger->file = new BroFile(f, source_fname, "wb");
	    fprintf(stderr, "Creating logger %s logid=%d owner=%d zone=%d file=%p\n", source_fname, logger->log_id, logger->owner_id, logger->zone_id, logger->file);
	  }
	}
	// fprintf(stderr, "...%p %s", logger->file, log_line);
	logger->file->Write(log_line, len);
      }
    }

    if (do_counts) {
      switch (msg->rcode) 
	{
	case DNS_CODE_OK: {
	  ++CNTS.rcode_noerror;
	  ++CNTS.reply;
	  ++TOTALS.reply;
	  ++TOTALS.rcode_noerror;
	  if (custom_stats) {
	    ++custom_stats->rcode_noerror;
	    ++custom_stats->reply;
	  }
	  if (do_zone_stats) {
	    ++zv->NOERROR;
	  }
	  break;
	}
	case DNS_CODE_FORMAT_ERR:
	  ++CNTS.rcode_format_err;
	  ++TOTALS.rcode_format_err;
	  if (custom_stats) 
	    ++custom_stats->rcode_format_err;
	  break;
	case DNS_CODE_SERVER_FAIL:
	  ++CNTS.rcode_server_fail;
	  ++TOTALS.rcode_server_fail;
	  if (custom_stats) 
	    ++custom_stats->rcode_server_fail;
	  break;
	case DNS_CODE_NAME_ERR:
	  ++CNTS.rcode_nxdomain;
	  ++TOTALS.rcode_nxdomain;
	  if (custom_stats) 
	    ++custom_stats->rcode_nxdomain;
	  if (do_zone_stats)
	    ++zv->NXDOMAIN;
	  break;
	case DNS_CODE_NOT_IMPL:
	  ++CNTS.rcode_not_impl;
	  ++TOTALS.rcode_not_impl;
	  if (custom_stats) 
	    ++custom_stats->rcode_not_impl;
	  break;
	case DNS_CODE_REFUSED:
	  ++CNTS.rcode_refused;
	  ++TOTALS.rcode_refused;
	  if (custom_stats) 
	    ++custom_stats->rcode_refused;
	  fprintf(stderr, "REFUSED\n");
	  if (do_zone_stats)
	    ++zv->REFUSED;
	  break;
	}
    }
  }

  
  if ( dns_event && ! msg->skip_event )
    {
      BroString* question_name =
	new BroString(name, name_end - name, 1);
      SendReplyOrRejectEvent(msg, dns_event, data, len, question_name);
    }
  else
    {
      // Consume the unused type/class.
      (void) ExtractShort(data, len);
      (void) ExtractShort(data, len);
    }

  delete zone_hash;
  return 1;
}

int DNS_Telemetry_Interpreter::ParseAnswer(DNS_Telemetry_MsgInfo* msg,
				const u_char*& data, int& len,
				const u_char* msg_start)
	{
	u_char name[513];
	int name_len = sizeof(name) - 1;

	fprintf(stderr, "ParseAnswer len=%d\n", len);
	return 1;

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start, 0);
	if ( ! name_end )
		return 0;

	if ( len < int(sizeof(short)) * 2 )
		{
		analyzer->Weird("DNS_truncated_ans_too_short");
		return 0;
		}

	// Note that the exact meaning of some of these fields will be
	// re-interpreted by other, more adventurous RR types.

	Unref(msg->query_name);
	msg->query_name = new StringVal(new BroString(name, name_end - name, 1));
	msg->atype = RR_Type(ExtractShort(data, len));
	msg->aclass = ExtractShort(data, len);
	msg->ttl = ExtractLong(data, len);

	int rdlength = ExtractShort(data, len);
	if ( rdlength > len )
		{
		analyzer->Weird("DNS_truncated_RR_rdlength_lt_len");
		return 0;
		}


	int status;
	switch ( msg->atype ) {
		case TYPE_EDNS:
			status = ParseRR_EDNS(msg, data, len, rdlength, msg_start);
			break;

		case TYPE_TSIG:
			status = ParseRR_TSIG(msg, data, len, rdlength, msg_start);
			break;

		default:
			data += rdlength;
			len -= rdlength;
			status = 1;
			break;
	}

	return status;
	}


u_char* DNS_Telemetry_Interpreter::ExtractName(const u_char*& data, int& len,
					       u_char* name, int name_len, const u_char* msg_start,
					       char* tlz)
{
  u_char* name_start = name;

  int label_cnt = 0;
  int label_idx[64];

  while (true) {
    int result = ExtractLabel(data, len, name, name_len, msg_start);
    if (!result) {
      break;
    } else {
      label_idx[label_cnt++] = result;
    }
  } 

  int n = name - name_start;

  if ( n >= 255 )
    analyzer->Weird("DNS_NAME_too_long");

  if ( n >= 2 && name[-1] == '.' )
    {
      // Remove trailing dot.
      --name;
      name[0] = 0;
    }

  // Convert labels to lower case for consistency.
  for ( u_char* np = name_start; np < name; ++np )
    if ( isupper(*np) )
      *np = tolower(*np);

  if (tlz != NULL) {
    // Now determine what the longest path match is...
    // Look for the host name in the zone map
    const char *pSearch = (const char*)name_start;
    const char *pDelim = ::strrchr(pSearch, '.');
    bool match = false;
    if (!pDelim) {
      // not good, ignore
    } else {
      do
	{
#ifdef UNORDERED_MAP
	  unordered_map<string,ZoneInfo*>::const_iterator got = zone_info.find(pSearch);
	  ZoneInfo* zinfo = got == zone_info.end() ? NULL : got->second;
#else
	  HashKey *key = new HashKey(pSearch);
	  ZoneInfo* zinfo = telemetry_zone_info.Lookup(key);
#endif
	  if (zinfo != 0) {
	    // We're done.
	    match = true;
	    strcpy(tlz, pSearch);
#ifndef UNORDERED_MAP
	    delete key;
#endif
	    break;
	  } else {
#ifndef UNORDERED_MAP
	    delete key;
#endif
	    pSearch = ::strchr(pSearch, '.');
	  }
	}
      while(pSearch && ++pSearch < pDelim);
    }
    if (!match) {
      strcpy(tlz, "OTHER");
    }
    // fprintf(stderr, "::ExtractName qname=%s len=%d tlz=%s\n", name_start, n, tlz);
  }

  return name;
}

int DNS_Telemetry_Interpreter::ExtractLabel(const u_char*& data, int& len,
				u_char*& name, int& name_len,
				const u_char* msg_start)
	{
	if ( len <= 0 )
		return 0;

	const u_char* orig_data = data;
	int label_len = data[0];

	++data;
	--len;

	if ( len <= 0 )
		return 0;

	if ( label_len == 0 )
		// Found terminating label.
		return 0;

	if ( (label_len & 0xc0) == 0xc0 )
		{
		unsigned short offset = (label_len & ~0xc0) << 8;

		offset |= *data;

		++data;
		--len;

		if ( offset >= orig_data - msg_start )
			{
			// (You'd think that actually the offset should be
			//  at least 6 bytes below our current position:
			//  2 bytes for a non-trivial label, plus 4 bytes for
			//  its class and type, which presumably are between
			//  our current location and the instance of the label.
			//  But actually this turns out not to be the case -
			//  sometimes compression points to compression.)

			analyzer->Weird("DNS_label_forward_compress_offset");
			return 0;
			}

		// Recursively resolve name.
		const u_char* recurse_data = msg_start + offset;
		int recurse_max_len = orig_data - recurse_data;

		u_char* name_end = ExtractName(recurse_data, recurse_max_len, name, name_len, msg_start,0);

		name_len -= name_end - name;
		name = name_end;

		return 0;
		}

	if ( label_len > len )
		{
		analyzer->Weird("DNS_label_len_gt_pkt");
		data += len;	// consume the rest of the packet
		len = 0;
		return 0;
		}

	if ( label_len > 63 )
		{
		analyzer->Weird("DNS_label_too_long");
		return 0;
		}

	if ( label_len >= name_len )
		{
		analyzer->Weird("DNS_label_len_gt_name_len");
		return 0;
		}

	memcpy(name, data, label_len);
	name[label_len] = '.';

	name += label_len + 1;
	name_len -= label_len + 1;

	data += label_len;
	len -= label_len;

	return label_len;
	}

uint16 DNS_Telemetry_Interpreter::ExtractShort(const u_char*& data, int& len)
	{
	if ( len < 2 )
		return 0;

	uint16 val;

	val = data[0] << 8;

	++data;
	--len;

	val |= data[0];

	++data;
	--len;

	return val;
	}

uint32 DNS_Telemetry_Interpreter::ExtractLong(const u_char*& data, int& len)
	{
	if ( len < 4 )
		return 0;

	uint32 val;

	val = data[0] << 24;
	val |= data[1] << 16;
	val |= data[2] << 8;
	val |= data[3];

	data += sizeof(val);
	len -= sizeof(val);

	return val;
	}

int DNS_Telemetry_Interpreter::ParseRR_Name(DNS_Telemetry_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	const u_char* data_start = data;

	u_char name[513];
	int name_len = sizeof(name) - 1;

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start, 0);
	if ( ! name_end )
		return 0;

	if ( data - data_start != rdlength )
		{
		analyzer->Weird("DNS_RR_length_mismatch");
		}

	/*
	EventHandlerPtr reply_event;
	switch ( msg->atype ) {
		case TYPE_NS:
			reply_event = dns_NS_reply;
			break;

		case TYPE_CNAME:
		case TYPE_AAAA:
		case TYPE_A6:
			reply_event = dns_CNAME_reply;
			break;

		case TYPE_PTR:
			reply_event = dns_PTR_reply;
			break;

		default:
			analyzer->Conn()->Internal("DNS_RR_bad_name");
			reply_event = 0;
	}
	*/

	if (do_counts) {
	  ++CNTS.reply;
	  ++TOTALS.reply;
	}
	/*
	if ( reply_event && ! msg->skip_event )
		{
		val_list* vl = new val_list;

		vl->append(analyzer->BuildConnVal());
		vl->append(msg->BuildHdrVal());
		vl->append(msg->BuildAnswerVal());
		vl->append(new StringVal(new BroString(name, name_end - name, 1)));
		analyzer->ConnectionEvent(reply_event, vl);
		}
	*/
	return 1;
	}

int DNS_Telemetry_Interpreter::ParseRR_SOA(DNS_Telemetry_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	const u_char* data_start = data;

	u_char mname[513];
	int mname_len = sizeof(mname) - 1;

	u_char* mname_end = ExtractName(data, len, mname, mname_len, msg_start, 0);
	if ( ! mname_end )
		return 0;

	u_char rname[513];
	int rname_len = sizeof(rname) - 1;

	u_char* rname_end = ExtractName(data, len, rname, rname_len, msg_start, 0);
	if ( ! rname_end )
		return 0;

	if ( len < 20 )
		return 0;

	uint32 serial = ExtractLong(data, len);
	uint32 refresh = ExtractLong(data, len);
	uint32 retry = ExtractLong(data, len);
	uint32 expire = ExtractLong(data, len);
	uint32 minimum = ExtractLong(data, len);

	if ( data - data_start != rdlength )
		analyzer->Weird("DNS_RR_length_mismatch");

	return 1;
	}

int DNS_Telemetry_Interpreter::ParseRR_MX(DNS_Telemetry_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	const u_char* data_start = data;

	int preference = ExtractShort(data, len);

	u_char name[513];
	int name_len = sizeof(name) - 1;

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start, 0);
	if ( ! name_end )
		return 0;

	if ( data - data_start != rdlength )
		analyzer->Weird("DNS_RR_length_mismatch");

	return 1;
	}

int DNS_Telemetry_Interpreter::ParseRR_NBS(DNS_Telemetry_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	data += rdlength;
	len -= rdlength;
	return 1;
	}

int DNS_Telemetry_Interpreter::ParseRR_SRV(DNS_Telemetry_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	const u_char* data_start = data;

	unsigned int priority = ExtractShort(data, len);
	unsigned int weight = ExtractShort(data, len);
	unsigned int port = ExtractShort(data, len);

	u_char name[513];
	int name_len = sizeof(name) - 1;

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start, 0);
	if ( ! name_end )
		return 0;
	*name_end = 0;	// terminate name so we can use it in snprintf()

	if ( data - data_start != rdlength )
		analyzer->Weird("DNS_RR_length_mismatch");

	// The following is just a placeholder.
	char buf[2048];
	safe_snprintf(buf, sizeof(buf), "SRV %s priority=%d weight=%d port=%d",
		      name, priority, weight, port);
	return 1;
	}

int DNS_Telemetry_Interpreter::ParseRR_EDNS(DNS_Telemetry_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	// We need a pair-value set mechanism here to dump useful information
	// out to the policy side of the house if rdlength > 0.

	if ( dns_telemetry_EDNS_addl && ! msg->skip_event )
		{
		val_list* vl = new val_list;

		vl->append(analyzer->BuildConnVal());
		vl->append(msg->BuildHdrVal());
		vl->append(msg->BuildEDNS_Val());
		analyzer->ConnectionEvent(dns_telemetry_EDNS_addl, vl);
		}

	// Currently EDNS supports the movement of type:data pairs
	// in the RR_DATA section.  Here's where we should put together
	// a corresponding mechanism.
	if ( rdlength > 0 )
		{ // deal with data
		data += rdlength;
		len -= rdlength;
		}
	else
		{ // no data, move on
		data += rdlength;
		len -= rdlength;
		}

	return 1;
	}

int DNS_Telemetry_Interpreter::ParseRR_TSIG(DNS_Telemetry_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
	{
	const u_char* data_start = data;
	u_char alg_name[1024];
	int alg_name_len = sizeof(alg_name) - 1;
	u_char* alg_name_end = ExtractName(data, len, alg_name, alg_name_len, msg_start,0);

	if ( ! alg_name_end )
		return 0;

	uint32 sign_time_sec = ExtractLong(data, len);
	unsigned int sign_time_msec = ExtractShort(data, len);
	unsigned int fudge = ExtractShort(data, len);

	u_char request_MAC[16];
	memcpy(request_MAC, data, sizeof(request_MAC));

	// Here we adjust the size of the requested MAC + u_int16_t
	// for length.  See RFC 2845, sec 2.3.
	int n = sizeof(request_MAC) + sizeof(u_int16_t);
	data += n;
	len -= n;

	unsigned int orig_id = ExtractShort(data, len);
	unsigned int rr_error = ExtractShort(data, len);

	msg->tsig = new TSIG_DATA;

	msg->tsig->alg_name =
		new BroString(alg_name, alg_name_end - alg_name, 1);
	msg->tsig->sig = new BroString(request_MAC, sizeof(request_MAC), 1);
	msg->tsig->time_s = sign_time_sec;
	msg->tsig->time_ms = sign_time_msec;
	msg->tsig->fudge = fudge;
	msg->tsig->orig_id = orig_id;
	msg->tsig->rr_error = rr_error;

	val_list* vl = new val_list;

	vl->append(analyzer->BuildConnVal());
	vl->append(msg->BuildHdrVal());
	vl->append(msg->BuildTSIG_Val());

	analyzer->ConnectionEvent(dns_telemetry_TSIG_addl, vl);

	return 1;
	}

int DNS_Telemetry_Interpreter::ParseRR_A(DNS_Telemetry_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength)
	{
	if ( rdlength != 4 )
		{
		analyzer->Weird("DNS_RR_bad_length");
		return 0;
		}

	uint32 addr = ExtractLong(data, len);
	return 1;
	}

int DNS_Telemetry_Interpreter::ParseRR_AAAA(DNS_Telemetry_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength)
	{
	uint32 addr[4];

	for ( int i = 0; i < 4; ++i )
		{
		addr[i] = htonl(ExtractLong(data, len));

		if ( len < 0 )
			{
			if ( msg->atype == TYPE_AAAA )
				analyzer->Weird("DNS_AAAA_neg_length");
			else
				analyzer->Weird("DNS_A6_neg_length");
			return 0;
			}
		}

	return 1;
	}

int DNS_Telemetry_Interpreter::ParseRR_WKS(DNS_Telemetry_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength)
	{
	data += rdlength;
	len -= rdlength;
	return 1;
	}

int DNS_Telemetry_Interpreter::ParseRR_HINFO(DNS_Telemetry_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength)
{
  data += rdlength;
  len -= rdlength;
  return 1;
}

int DNS_Telemetry_Interpreter::ParseRR_TXT(DNS_Telemetry_MsgInfo* msg,
				const u_char*& data, int& len, int rdlength,
				const u_char* msg_start)
{
  data += rdlength;
  len -= rdlength;
  return 1;
}

void DNS_Telemetry_Interpreter::SendReplyOrRejectEvent(DNS_Telemetry_MsgInfo* msg,
						EventHandlerPtr event,
						const u_char*& data, int& len,
						BroString* question_name)
	{
	RR_Type qtype = RR_Type(ExtractShort(data, len));
	int qclass = ExtractShort(data, len);

	val_list* vl = new val_list;
	vl->append(analyzer->BuildConnVal());
	vl->append(msg->BuildHdrVal());
	vl->append(new StringVal(question_name));
	vl->append(new Val(qtype, TYPE_COUNT));
	vl->append(new Val(qclass, TYPE_COUNT));

	analyzer->ConnectionEvent(event, vl);
	}


DNS_Telemetry_MsgInfo::DNS_Telemetry_MsgInfo(DNS_RawMsgHdr* hdr, int arg_is_query)
	{
	//### Need to fix alignment if hdr is misaligned (not on a short
	// boundary).
	unsigned short flags = ntohs(hdr->flags);

	QR = (flags & 0x8000) != 0;
	opcode = (flags & 0x7800) >> 11;
	AA = (flags & 0x0400) != 0;
	TC = (flags & 0x0200) != 0;
	RD = (flags & 0x0100) != 0;
	RA = (flags & 0x0080) != 0;
	Z = (flags & 0x0070) >> 4;
	rcode = (flags & 0x000f);

	qdcount = ntohs(hdr->qdcount);
	ancount = ntohs(hdr->ancount);
	nscount = ntohs(hdr->nscount);
	arcount = ntohs(hdr->arcount);

	id = ntohs(hdr->id);
	is_query = arg_is_query;

	query_name = 0;
	atype = TYPE_ALL;
	aclass = 0;
	ttl = 0;

	answer_type = DNS_QUESTION;
	skip_event = 0;
	tsig = 0;
	}

DNS_Telemetry_MsgInfo::~DNS_Telemetry_MsgInfo()
	{
	Unref(query_name);
	}

Val* DNS_Telemetry_MsgInfo::BuildHdrVal()
	{
	RecordVal* r = new RecordVal(dns_msg);

	r->Assign(0, new Val(id, TYPE_COUNT));
	r->Assign(1, new Val(opcode, TYPE_COUNT));
	r->Assign(2, new Val(rcode, TYPE_COUNT));
	r->Assign(3, new Val(QR, TYPE_BOOL));
	r->Assign(4, new Val(AA, TYPE_BOOL));
	r->Assign(5, new Val(TC, TYPE_BOOL));
	r->Assign(6, new Val(RD, TYPE_BOOL));
	r->Assign(7, new Val(RA, TYPE_BOOL));
	r->Assign(8, new Val(Z, TYPE_COUNT));
	r->Assign(9, new Val(qdcount, TYPE_COUNT));
	r->Assign(10, new Val(ancount, TYPE_COUNT));
	r->Assign(11, new Val(nscount, TYPE_COUNT));
	r->Assign(12, new Val(arcount, TYPE_COUNT));

	return r;
	}

Val* DNS_Telemetry_MsgInfo::BuildAnswerVal()
	{
	RecordVal* r = new RecordVal(dns_answer);

	Ref(query_name);
	r->Assign(0, new Val(int(answer_type), TYPE_COUNT));
	r->Assign(1, query_name);
	r->Assign(2, new Val(atype, TYPE_COUNT));
	r->Assign(3, new Val(aclass, TYPE_COUNT));
	r->Assign(4, new IntervalVal(double(ttl), Seconds));

	return r;
	}

Val* DNS_Telemetry_MsgInfo::BuildEDNS_Val()
	{
	// We have to treat the additional record type in EDNS differently
	// than a regular resource record.
	RecordVal* r = new RecordVal(dns_edns_additional);

	Ref(query_name);
	r->Assign(0, new Val(int(answer_type), TYPE_COUNT));
	r->Assign(1, query_name);

	// type = 0x29 or 41 = EDNS
	r->Assign(2, new Val(atype, TYPE_COUNT));

	// sender's UDP payload size, per RFC 2671 4.3
	r->Assign(3, new Val(aclass, TYPE_COUNT));

	// Need to break the TTL field into three components:
	// initial: [------------- ttl (32) ---------------------]
	// after:   [DO][ ext rcode (7)][ver # (8)][ Z field (16)]

	unsigned int ercode = (ttl >> 24) & 0xff;
	unsigned int version = (ttl >> 16) & 0xff;
	unsigned int DO = ttl & 0x8000;	// "DNSSEC OK" - RFC 3225
	unsigned int z = ttl & 0xffff;

	if (do_counts) {
	  if (DO) {
	    ++CNTS.DO;
	    ++TOTALS.DO;
	  }
	}

	unsigned int return_error = (ercode << 8) | rcode;

	r->Assign(4, new Val(return_error, TYPE_COUNT));
	r->Assign(5, new Val(version, TYPE_COUNT));
	r->Assign(6, new Val(z, TYPE_COUNT));
	r->Assign(7, new IntervalVal(double(ttl), Seconds));
	r->Assign(8, new Val(is_query, TYPE_COUNT));
	r->Assign(8, new Val(DO, TYPE_BOOL));

	return r;
	}

Val* DNS_Telemetry_MsgInfo::BuildTSIG_Val()
	{
	RecordVal* r = new RecordVal(dns_tsig_additional);
	double rtime = tsig->time_s + tsig->time_ms / 1000.0;

	Ref(query_name);
	// r->Assign(0, new Val(int(answer_type), TYPE_COUNT));
	r->Assign(0, query_name);
	r->Assign(1, new Val(int(answer_type), TYPE_COUNT));
	r->Assign(2, new StringVal(tsig->alg_name));
	r->Assign(3, new StringVal(tsig->sig));
	r->Assign(4, new Val(rtime, TYPE_TIME));
	r->Assign(5, new Val(double(tsig->fudge), TYPE_TIME));
	r->Assign(6, new Val(tsig->orig_id, TYPE_COUNT));
	r->Assign(7, new Val(tsig->rr_error, TYPE_COUNT));
	r->Assign(8, new Val(is_query, TYPE_COUNT));

	delete tsig;
	tsig = 0;

	return r;
	}

Contents_DNS_Telemetry::Contents_DNS_Telemetry(Connection* conn, bool orig,
				DNS_Telemetry_Interpreter* arg_interp)
: tcp::TCP_SupportAnalyzer("CONTENTS_DNS_TELEMETRY", conn, orig)
	{
	interp = arg_interp;

	msg_buf = 0;
	buf_n = buf_len = msg_size = 0;
	state = DNS_LEN_HI;
	}

Contents_DNS_Telemetry::~Contents_DNS_Telemetry()
	{
	free(msg_buf);
	}

void Contents_DNS_Telemetry::Flush()
	{
	if ( buf_n > 0 )
		{ // Deliver partial message.
		interp->ParseMessage(msg_buf, buf_n, true);
		msg_size = 0;
		}
	}

void Contents_DNS_Telemetry::DeliverStream(int len, const u_char* data, bool orig)
	{
	if ( state == DNS_LEN_HI )
		{
		msg_size = (*data) << 8;
		state = DNS_LEN_LO;

		++data;
		--len;

		if ( len == 0 )
			return;
		}

	if ( state == DNS_LEN_LO )
		{
		msg_size += *data;
		state = DNS_MESSAGE_BUFFER;

		buf_n = 0;

		if ( msg_buf )
			{
			if ( buf_len < msg_size )
				{
				buf_len = msg_size;
				msg_buf = (u_char*) safe_realloc((void*) msg_buf, buf_len);
				}
			}
		else
			{
			buf_len = msg_size;
			msg_buf = (u_char*) safe_malloc(buf_len);
			}

		++data;
		--len;

		if ( len == 0 )
			return;
		}

	if ( state != DNS_MESSAGE_BUFFER )
		Conn()->Internal("state inconsistency in Contents_DNS_Telemetry::DeliverStream");

	int n;
	for ( n = 0; buf_n < msg_size && n < len; ++n )
		msg_buf[buf_n++] = data[n];

	if ( buf_n < msg_size )
		// Haven't filled up the message buffer yet, no more to do.
		return;

	ForwardPacket(msg_size, msg_buf, orig, -1, 0, 0);

	buf_n = 0;
	state = DNS_LEN_HI;

	if ( n < len )
		// More data to munch on.
		DeliverStream(len - n, data + n, orig);
	}

DNS_Telemetry_Analyzer::DNS_Telemetry_Analyzer(Connection* conn)
: tcp::TCP_ApplicationAnalyzer("DNS_TELEMETRY", conn)
	{
	interp = new DNS_Telemetry_Interpreter(this);
	contents_dns_orig = contents_dns_resp = 0;
	did_session_done = 0;

	if ( Conn()->ConnTransport() == TRANSPORT_TCP )
		{
		contents_dns_orig = new Contents_DNS_Telemetry(conn, true, interp);
		contents_dns_resp = new Contents_DNS_Telemetry(conn, false, interp);
		AddSupportAnalyzer(contents_dns_orig);
		AddSupportAnalyzer(contents_dns_resp);
		}
	else
		{
		ADD_ANALYZER_TIMER(&DNS_Telemetry_Analyzer::ExpireTimer,
					network_time + dns_session_timeout, 1,
					TIMER_DNS_EXPIRE);
		}
	}

DNS_Telemetry_Analyzer::~DNS_Telemetry_Analyzer()
	{
	delete interp;
	}

void DNS_Telemetry_Analyzer::Init()
	{
	}

void DNS_Telemetry_Analyzer::Done()
{
  tcp::TCP_ApplicationAnalyzer::Done();
  if ( Conn()->ConnTransport() == TRANSPORT_UDP && ! did_session_done )
    Event(udp_session_done);
  else
    interp->Timeout();
}

void DNS_Telemetry_Analyzer::DeliverPacket(int len, const u_char* data, bool orig,
					int seq, const IP_Hdr* ip, int caplen)
{
  tcp::TCP_ApplicationAnalyzer::DeliverPacket(len, data, orig, seq, ip, caplen);
  if ( orig )
    {
      if ( ! interp->ParseMessage(data, len, 1)) {
	if (do_counts) {
	  ++CNTS.non_dns_request;
	  ++TOTALS.non_dns_request;
	}
	if (non_dns_telemetry_request )
	  {
	    val_list* vl = new val_list;
	    vl->append(BuildConnVal());
	    vl->append(new StringVal(len, (const char*) data));
	    ConnectionEvent(non_dns_telemetry_request, vl);
	  }
      }
    }

  else {
    interp->ParseMessage(data, len, 0);
  }
}


void DNS_Telemetry_Analyzer::ConnectionClosed(tcp::TCP_Endpoint* endpoint, tcp::TCP_Endpoint* peer,
					int gen_event)
	{
	tcp::TCP_ApplicationAnalyzer::ConnectionClosed(endpoint, peer, gen_event);

	assert(contents_dns_orig && contents_dns_resp);
	contents_dns_orig->Flush();
	contents_dns_resp->Flush();
	}

void DNS_Telemetry_Analyzer::ExpireTimer(double t)
{
  // The - 1.0 in the following is to allow 1 second for the
  // common case of a single request followed by a single reply,
  // so we don't needlessly set the timer twice in that case.
  if ( t - Conn()->LastTime() >= dns_session_timeout - 1.0 || terminating )
    {
      Event(connection_timeout);
      sessions->Remove(Conn());
    }
  else
    ADD_ANALYZER_TIMER(&DNS_Telemetry_Analyzer::ExpireTimer,
		       t + dns_session_timeout, 1, TIMER_DNS_EXPIRE);
}

void __dns_telemetry_zone_info_list() {

  // Dump the zone map
  IterCookie* c = telemetry_zone_info.InitForIteration();
  HashKey* k;
  ZoneInfo* val;
  uint size = DETAIL_LOGGER_INFO.MemoryAllocation();
  int loggers = DETAIL_LOGGER_INFO.Length();
  int len = telemetry_zone_info.Length();
  fprintf(stderr,"Config @ %f - Zone Info len=%d size=%u loggers=%d\n", current_time(),len, size, loggers);
}

int __dns_telemetry_set_zones(const char* fname, const char* details_fname) {

  // Config the common logger (logid=3, owner_id=0)
  DetailLogInfo* common_logger;
  HashKey* key = new HashKey((bro_int_t)0);
  if (DETAIL_LOGGER_INFO.Length() == 0 && details_fname != NULL) {
    common_logger = new DetailLogInfo();
    strcpy(DETAIL_DEFAULT_PATH, details_fname);
    common_logger->fname = DETAIL_DEFAULT_PATH;
    common_logger->owner_id = 0;
    common_logger->enabled = false;
    common_logger->log_id = 3;
    if (common_logger->file != 0) {
      delete common_logger->file;
    }
    common_logger->file = NULL;
    common_logger->log_id = 3;
    common_logger->ts = network_time;
    DETAIL_LOGGER_INFO.Insert(key, common_logger);
  } else {
    common_logger = DETAIL_LOGGER_INFO.Lookup(key);
  }
  delete key;


  double start = current_time();
  struct stat buf;
  stat(fname, &buf);
  int size = buf.st_size;
  int estimated_cnt = size / 45;
  strcpy(ZONE_MAP_INFO.fname, fname);
  ZONE_MAP_INFO.last_mod = buf.st_mtime;
  static char timestr[256];
  strftime(timestr, sizeof(timestr), "%Y%m%dT%H%M%S", localtime(&ZONE_MAP_INFO.last_mod));
  fprintf(stderr, "%f set_zones.start %s size=%d cnt=%d (estimate) lastmod=%s\n", start, fname, size, estimated_cnt, timestr);

  FILE* f = fopen(fname, "rt");

  if (f == NULL) {
    fprintf(stderr,"ERROR: Invalid zone config file: %s\n", fname);
    return 0;
  } else {
    ssize_t read;
    size_t len = 0;
    uint cnt = 0;
    uint change = 0;
    uint add = 0;
    char line [128];
    while ( fgets ( line, sizeof line, f) != NULL ) {
      if (line[0] == '#') 
	  continue;
      ++cnt;

      // Raw processing speed for now. No error checking whatsoever. Get the config file right! ^_^
      char *array[7];
      uint i = 0;
      char *p = strtok (line,"\t");  
      while (p != NULL)
	{
	  if (i > 6)
	    break;
	  array[i++] = p;
	  p = strtok (NULL, "\t");
	}

      char* name = array[1];
      int zone_id = atoi(array[2]);
      int owner_id = atoi(array[3]);
      int log_id = atoi(array[4]);
      int stat_id = atoi(array[5]);
      int qname_id = atoi(array[6]);

      if (log_id > 3) {
	fprintf(stderr, "ERROR: log_id must be either 0 (none), 1 (owner), 2 (zone) or 3 (common) logid=%d owner_id=%d zone_id=%d %s\n", log_id, owner_id, zone_id, name);
      }

      ZoneInfo* zinfo;
#ifdef UNORDERED_MAP
      unordered_map<string,ZoneInfo*>::const_iterator got = zone_info.find(name);
      if (got == zone_info.end()) {
	zinfo = new ZoneInfo();
	zone_info.insert({name, zinfo});
	add++;
      } else {
	zinfo = got->second;
	if (zinfo->zone_id == zone_id && zinfo->log_id == log_id && zinfo->stat_id == stat_id && zinfo->qname_id == qname_id) {
	  continue;
	}
	change++;
      }
#else
      HashKey* zone_hash = new HashKey(name);
      zinfo = telemetry_zone_info.Lookup(zone_hash);
      if (!zinfo) {
	zinfo = new ZoneInfo();
	telemetry_zone_info.Insert(zone_hash, zinfo);
      }
      delete zone_hash;
#endif

      if (log_id != 0 || qname_id != 0 || stat_id != 0) {
	fprintf(stderr, "%f zone_info %s\tzid=%d\toid=%d\tlid=%d\tsid=%d\tqid=%d\n", current_time(), name, zone_id, owner_id, log_id, stat_id, qname_id);
      }

      strcpy(zinfo->key, name);
      zinfo->zone_id = zone_id;
      zinfo->owner_id = owner_id;
      zinfo->log_id = log_id;
      zinfo->stat_id = stat_id;
      zinfo->qname_id = qname_id;
      zinfo->details = log_id != 0;

      HashKey* stat_logger_key = new HashKey((bro_int_t)owner_id);
      StatsLogInfo* stat_logger = STATS_LOGGER_INFO.Lookup(stat_logger_key);
      if (stat_logger) {
	stat_logger->fname = DETAIL_DEFAULT_PATH;
      } else if (stat_id != 0) {
	fprintf(stderr, "Adding stat logger owner_id=%d stat_id=%d\n", owner_id, stat_id);
	stat_logger = new StatsLogInfo();
	stat_logger->owner_id = owner_id;
	STATS_LOGGER_INFO.Insert(stat_logger_key, stat_logger);
	stat_logger->enabled = true;
      }
      delete stat_logger_key;

      HashKey* filter_key = new HashKey((bro_int_t)zone_id);
      QnameFilter* filter =QNAME_FILTERS.Lookup(filter_key);
      if (filter) {
	filter->enabled = qname_id != 0;
	fprintf(stderr, "Existing qname filter owner_id=%d zone_id=%d qname_id=%d\n", owner_id, zone_id, qname_id);
      } else if (qname_id != 0) {
	fprintf(stderr, "Adding qname filter owner_id=%d zone_id=%d qname_id=%d\n", owner_id, zone_id, qname_id);
	filter = new QnameFilter();
	filter->owner_id = owner_id;
	filter->zone_id = zone_id;
	filter->enabled = true;
	QNAME_FILTERS.Insert(filter_key, filter);
      }
      delete filter_key;

      DetailLogInfo* logger = NULL;
      HashKey* logger_key = new HashKey((bro_int_t)zinfo->zone_id);
      logger = DETAIL_LOGGER_INFO.Lookup(logger_key);
      delete logger_key;
      
      if (log_id == 0 && logger) {

	// Update the logid. Could be toggling details on/off for a particular customer
	// Owner ID can't / shouldn't change. Nor the location that we write these logs to.
	if (logger->log_id != 0) {
	  fprintf(stderr, "%f zone_info\t%s\tdisabling logging (was %d) zoneid=%d ownerid=%d\n", current_time(), name, logger->log_id, logger->zone_id, logger->owner_id);
	}
	if (logger->file != 0) {
	  fprintf(stderr, "  pending log entries to be rotated %p %s\n", logger->file, logger->file->Name());
	} else {
	  fprintf(stderr, "  WARN: no pending log entries to be rotated, create file?\n");
	}
	logger->log_id = log_id;
	logger->enabled = false;

      } else if (log_id != 0) {

	// If we don't have a logger info yet, create it.
	if (logger == NULL) {
	  // Create and init a DetailLogInfo structure
	  logger = new DetailLogInfo();
	  logger->owner_id = zinfo->owner_id;
	  logger->log_id = zinfo->log_id;
	  logger->zone_id = zinfo->zone_id;
	  logger->ts = network_time;
	  logger->enabled = true;
      
	  // Use the base multi-tenant logger's root
	  logger->fname = common_logger->fname;
	  HashKey* log_key = new HashKey((bro_int_t)zinfo->zone_id);
	  DETAIL_LOGGER_INFO.Insert(log_key, logger);
	  delete log_key;
	} else {
	  // Validate that we're not changing owner or zoneid?
	  logger->log_id = log_id;
	  logger->enabled = true;
	}
      }

    }

    fclose(f);
    double diff = current_time() - start;
    double rate = cnt / diff;
    size_t map_size = zone_info.size();
    uint ignored = cnt - map_size;
#ifdef UNORDERED_MAP
    fprintf(stderr, "%f set_zones.done time=%f error=%u add=%u change=%u cnt=%lu %.0f/sec \n", current_time(), diff, ignored, add, change, map_size, rate);
#else
    int map_size = telementry_zone_info.Length();
    uint ignored = cnt - map_size;
    fprintf(stderr, "%f set_zones.done time=%f error=%u add=%u change=%u cnt=%d %.0f\n", current_time(), diff, ignored, add, change, map_size, rate);
#endif

    if (ZONE_UPDATER == NULL) {
      ZONE_UPDATER = new ZoneUpdater(ZONE_MAP_INFO.fname, 5);
      ZONE_UPDATER->Start();
    }

  }
  return 1;
}

val_list* buildCountsRecord(CurCounts* cnts, uint owner_id, double ts, double lag) {
  val_list* vl = new val_list;
  RecordVal* r = new RecordVal(dns_telemetry_counts);

  r->Assign(0, new Val(ts, TYPE_DOUBLE));
  r->Assign(1, new Val(lag, TYPE_DOUBLE));
  r->Assign(2, new Val(owner_id, TYPE_COUNT));
  r->Assign(3, new Val(cnts->request, TYPE_COUNT));
  r->Assign(4, new Val(cnts->rejected, TYPE_COUNT));
  r->Assign(5, new Val(cnts->reply, TYPE_COUNT));
  r->Assign(6, new Val(cnts->non_dns_request, TYPE_COUNT));

  r->Assign(7, new Val(cnts->ANY_RD, TYPE_COUNT));

  r->Assign(8, new Val(cnts->ANY, TYPE_COUNT));
  r->Assign(9, new Val(cnts->A, TYPE_COUNT));
  r->Assign(10, new Val(cnts->AAAA, TYPE_COUNT));
  r->Assign(11, new Val(cnts->NS, TYPE_COUNT));
  r->Assign(12, new Val(cnts->CNAME, TYPE_COUNT));

  r->Assign(13, new Val(cnts->PTR, TYPE_COUNT));
  r->Assign(14, new Val(cnts->SOA, TYPE_COUNT));
  r->Assign(15, new Val(cnts->MX, TYPE_COUNT));
  r->Assign(16, new Val(cnts->TXT, TYPE_COUNT));
  r->Assign(17, new Val(cnts->SRV, TYPE_COUNT));
  r->Assign(18, new Val(cnts->other, TYPE_COUNT));

  r->Assign(19, new Val(cnts->TCP, TYPE_COUNT));
  r->Assign(20, new Val(cnts->UDP, TYPE_COUNT));
  r->Assign(21, new Val(cnts->TSIG, TYPE_COUNT));
  r->Assign(22, new Val(cnts->EDNS, TYPE_COUNT));
  r->Assign(23, new Val(cnts->RD, TYPE_COUNT));
  r->Assign(24, new Val(cnts->DO, TYPE_COUNT));
  r->Assign(25, new Val(cnts->CD, TYPE_COUNT));
  r->Assign(26, new Val(cnts->V4, TYPE_COUNT));
  r->Assign(27, new Val(cnts->V6, TYPE_COUNT));

  r->Assign(28, new Val(cnts->OpQuery, TYPE_COUNT));
  r->Assign(29, new Val(cnts->OpIQuery, TYPE_COUNT));
  r->Assign(30, new Val(cnts->OpStatus, TYPE_COUNT));
  r->Assign(31, new Val(cnts->OpNotify, TYPE_COUNT));
  r->Assign(32, new Val(cnts->OpUpdate, TYPE_COUNT));
  r->Assign(33, new Val(cnts->OpUnassigned, TYPE_COUNT));

  r->Assign(34, new Val(cnts->rcode_noerror, TYPE_COUNT));
  r->Assign(35, new Val(cnts->rcode_format_err, TYPE_COUNT));
  r->Assign(36, new Val(cnts->rcode_server_fail, TYPE_COUNT));
  r->Assign(37, new Val(cnts->rcode_nxdomain, TYPE_COUNT));
  r->Assign(38, new Val(cnts->rcode_not_impl, TYPE_COUNT));
  r->Assign(39, new Val(cnts->rcode_refused, TYPE_COUNT));

  r->Assign(40, new Val(cnts->logged, TYPE_COUNT));

  // Compute average qlen & rlen
  uint qlen = cnts->qlen ? cnts->qlen / cnts->request : 0;
  uint rlen = cnts->rlen ? cnts->rlen / (cnts->reply + cnts->rejected) : 0;

  // fprintf(stderr, "qlen=%u rlen=%u\n", qlen, rlen);

  r->Assign(41, new Val(qlen, TYPE_COUNT));
  r->Assign(42, new Val(rlen, TYPE_COUNT));

  // r->Assign(41, new Val(cnts->qlen, TYPE_COUNT));
  // r->Assign(42, new Val(cnts->rlen, TYPE_COUNT));

  r->Assign(43, new Val(cnts->clients, TYPE_COUNT));
  r->Assign(44, new Val(cnts->zones, TYPE_COUNT));
  r->Assign(45, new Val(cnts->qlen/1048576.0, TYPE_DOUBLE));
  r->Assign(46, new Val(cnts->rlen/1048576.0, TYPE_DOUBLE));
  r->Assign(47, new Val((cnts->qlen+cnts->rlen)/1048576.0, TYPE_DOUBLE));

  vl->append(r);
  return vl;
}

void __dns_telemetry_fire_counts(double ts) {
  if ( dns_telemetry_count ) {
    double lag = current_time() - ts;
    val_list* vl = buildCountsRecord(&CNTS, 0, ts, lag);
    if (lag > 2) {
      fprintf(stderr, "WARN: Lagging on real-time processing. TODO, send event up to script land\n");
    }
    mgr.Dispatch(new Event(dns_telemetry_count, vl), true);

    // Clear counters
    memset(&CNTS, 0, sizeof(CurCounts));

    // Now process each custom stats logger
    int len = STATS_LOGGER_INFO.Length();
    if (len > 0) {
      IterCookie* cookie = STATS_LOGGER_INFO.InitForIteration();
      HashKey* key;
      StatsLogInfo* logger;
      while ((logger = STATS_LOGGER_INFO.NextEntry(key, cookie))) {
	// fprintf(stderr, "STATS_LOGGER oid=%d enabled=%d request=%d\n", logger->owner_id, logger->enabled, logger->CNTS.request);
	if (logger->enabled) {
	  // if (logger->CNTS.request > 0) {
	  val_list* vl = buildCountsRecord(&logger->CNTS, logger->owner_id, ts, lag);
	  mgr.Dispatch(new Event(dns_telemetry_count, vl), true);
	  // }
	  memset(&logger->CNTS, 0, sizeof(CurCounts));
	}
      }
    }
  }
}

void __dns_telemetry_fire_totals(double ts) {
  if ( dns_telemetry_totals ) {
    // val_list* vl = new val_list;
    // vl->append(__dns_telemetry_get_totals(ts));
    val_list* vl = buildCountsRecord(&TOTALS, 0, ts, 0);
    mgr.Dispatch(new Event(dns_telemetry_totals, vl), true);
  } 
}

void __dns_telemetry_fire_anyrd(double ts) {
  if ( dns_telemetry_anyrd_info ) {
    int len = telemetry_anyrd_counts.Length();
    if (len > 0) {
      IterCookie* c = telemetry_anyrd_counts.InitForIteration();
      HashKey* k;
      int* val;
      while ((val = telemetry_anyrd_counts.NextEntry(k, c)))
	{
	  char* key =  (char*)k->Key();
	  int key_size =  k->Size();
	  // @componentry. NOT SAFE. FIX THIS. 
	  // Making copy because of use of STRTOK which is destructive.	  
	  char anyrd_key[600];
	  strncpy(anyrd_key, key, key_size);
	  anyrd_key[key_size] = 0;
	  char seps[] = "|";
	  char* ip = strtok(anyrd_key, seps );
	  char* qname = strtok( NULL, seps);
	  RecordVal* r = new RecordVal(dns_telemetry_anyrd_stats);
	  r->Assign(0, new Val(ts, TYPE_DOUBLE));
	  r->Assign(1, new StringVal(ip));
	  r->Assign(2, new StringVal(qname));
	  r->Assign(3, new Val(*val, TYPE_COUNT));
	  val_list* vl = new val_list;
	  vl->append(r);
	  mgr.Dispatch(new Event(dns_telemetry_anyrd_info, vl), true);
	}
      telemetry_anyrd_counts.Clear();
    } else {
      // Always emit an empty record for consistency and to ensure a file exists for the interval
      RecordVal* r = new RecordVal(dns_telemetry_anyrd_stats);
      r->Assign(0, new Val(ts, TYPE_DOUBLE));
      r->Assign(1, new StringVal(""));
      r->Assign(2, new StringVal(""));
      r->Assign(3, new Val(0, TYPE_COUNT));
      val_list* vl = new val_list;
      vl->append(r);
      mgr.Dispatch(new Event(dns_telemetry_anyrd_info, vl), true);
    }
  }
}

void __dns_telemetry_fire_clients(double ts) {
  if ( dns_telemetry_client_info ) {
    int len = telemetry_client_stats.Length();
    if (len > 0) {
      IterCookie* client_c = telemetry_client_stats.InitForIteration();
      HashKey* client_k;
      int* client_v;
      while ((client_v = telemetry_client_stats.NextEntry(client_k, client_c)))
	{
	  char* key =  (char*)client_k->Key();
	  RecordVal* r = new RecordVal(dns_telemetry_client_stats);
	  r->Assign(0, new Val(ts, TYPE_DOUBLE));
	  r->Assign(1, new StringVal(key));
	  r->Assign(2, new Val(*client_v, TYPE_COUNT));
	  val_list* vl = new val_list;
	  vl->append(r);
	  mgr.Dispatch(new Event(dns_telemetry_client_info, vl), true);
	} 
      telemetry_client_stats.Clear();
    }
    else {
      // Always emit an empty record for consistency and to ensure a file exists for the interval
      RecordVal* r = new RecordVal(dns_telemetry_client_stats);
      r->Assign(0, new Val(ts, TYPE_DOUBLE));
      r->Assign(1, new StringVal(""));
      r->Assign(2, new Val(0, TYPE_COUNT));
      val_list* vl = new val_list;
      vl->append(r);
      mgr.Dispatch(new Event(dns_telemetry_client_info, vl), true);
    }
  }
}

FILE* file_rotate(const char* name, const char* to_name)
{
  // Build file names.
  const int buflen = strlen(name) + 128;
  char tmpname[buflen], newname[buflen+4];
  safe_snprintf(newname, buflen, "%s", to_name);
  newname[buflen-1] = '\0';
  strcpy(tmpname, newname);
  strcat(tmpname, ".tmp");

  // First open the new file using a temporary name.
  FILE* newf = fopen(tmpname, "w");
  if ( ! newf ) {
    fprintf(stderr, "file_rotate (open): can't open %s: %s\n", tmpname, strerror(errno));
    return 0;
  }

  // Then move old file to and make sure it really gets created.
  struct stat dummy;
  if ( link(name, newname) < 0 || stat(newname, &dummy) < 0 ) {
    fprintf(stderr, "file_rotate (move): can't move %s to %s: %s\n", name, newname, strerror(errno));
    fclose(newf);
    unlink(newname);
    unlink(tmpname);
    return 0;
  }

  // Close current file, and move the tmp to its place.
  if ( unlink(name) < 0 || link(tmpname, name) < 0 || unlink(tmpname) < 0 ) {
    reporter->Error("file_rotate (close): can't move %s to %s: %s\n", tmpname, name, strerror(errno));
    exit(1);	// hard to fix, but shouldn't happen anyway...
  }

  fclose(newf);
  return 0;
  // return newf;
}

// #define ROTATE_LOGGING 

void __dns_telemetry_fire_details(double ts, bool terminating) {

  // How we deal with synchronous, manual rotation.
  // Special case for high-perf writing scenarios (> 200K QPS)
  static char timestamp[256];
  static char rotate_fname[256];
  static char source_fname[256];
  time_t time = (time_t) ts-59;; // ugly. We're getting called @ the 59'th
  strftime(timestamp, sizeof(timestamp), "%y-%m-%d_%H.%M.%S", localtime(&time));

  IterCookie* cookie = DETAIL_LOGGER_INFO.InitForIteration();
  HashKey* key;
  OwnerStats* info;
  DetailLogInfo* logger;
  int i = 0;
  bool common_rotated = false;
  PDict(int) owners;

  while ((logger = DETAIL_LOGGER_INFO.NextEntry(key, cookie))) {

    char* root_fname = logger->fname;

    bool enabled = logger->enabled;

    switch  (logger->log_id) 
      {
      case 1:
	{
	  // Multi Zone
	  sprintf(source_fname, "%s-O-%08d.log", root_fname, logger->owner_id);
	  sprintf(rotate_fname, "%s-O-%08d-%s.log", root_fname, logger->owner_id, timestamp);
	  break;
	}
      case 2:
	{
	  // Single Zone
	  sprintf(source_fname, "%s-Z-%08d.log", root_fname, logger->zone_id);
	  sprintf(rotate_fname, "%s-Z-%08d-%s.log", root_fname, logger->zone_id, timestamp);
	  break;
	}
      case 3:
	{
	  // Common
	  sprintf(source_fname, "%s-00000000.log", root_fname);
	  sprintf(rotate_fname, "%s-00000000-%s.log", root_fname, timestamp);
	  break;
	}
      }

    // See if we've processed this owner yet. 
    HashKey* owner_key = new HashKey(source_fname);
    DetailLogInfo* open_logger = DETAIL_LOGGER_OPEN.Lookup(owner_key);
    int* rotated_by = owners.Lookup(owner_key);

#ifdef ROTATE_LOGGING
    fprintf(stderr, "Processing logid=%d owner=%d zone=%d rotated=%p file=%p open_logger=%p\n", logger->log_id, logger->owner_id, logger->zone_id, rotated_by, logger->file, open_logger);
#endif

    FILE* newf = 0;

    // Rotate
    if (logger->file != 0) {

      if (rotated_by == NULL) {
	logger->file->Flush();
	logger->file->Close();
	if (strstr(source_fname, logger->file->Name())) {
#ifdef ROTATE_LOGGING
	  fprintf(stderr, "  Rotating %s => %s logger=%p\n", source_fname, rotate_fname, logger);
#endif
	} else {
	  strcpy(rotate_fname, logger->file->Name());
	  strcpy(source_fname, rotate_fname);
	  char rotate_timestamp[128];
	  sprintf(rotate_timestamp, "-%s.log", timestamp);
	  strcpy(strstr(rotate_fname, ".log"), rotate_timestamp);
#ifdef ROTATE_LOGGING
	  fprintf(stderr, "  Rotating %s => %s logger=%p\n", source_fname, rotate_fname, logger);
#endif
	}
	newf = file_rotate(source_fname, rotate_fname);
	
	if (logger->log_id == 1) {
	  // Remember the fact that we've already rotated for this Multi-Zone file
	  owners.Insert(owner_key, new int(logger->zone_id));
	} else if (logger->log_id == 3) {
	  // Remember the fact that we've already rotated for the Multi-Customer/Zone (Common) file
	  common_rotated = true;
	}
      } else {
	if (strstr(source_fname, logger->file->Name())) {
#ifdef ROTATE_LOGGING
	  fprintf(stderr, "  Ignoring %s, already rotated via zoneid=%d file=%p %s\n", source_fname, *rotated_by, logger->file, logger->file->Name());
#endif
	} else {
	  strcpy(rotate_fname, logger->file->Name());
	  char rotate_timestamp[128];
	  sprintf(rotate_timestamp, "-%s.log", timestamp);
	  strcpy(strstr(rotate_fname, ".log"), rotate_timestamp);
#ifdef ROTATE_LOGGING
	  fprintf(stderr, "  ZZ TODO Rotating %s => %s logger=%p\n", logger->file->Name(), rotate_fname, logger);
#endif
	  newf = file_rotate(logger->file->Name(), rotate_fname);
	}
	// Previous rotation will have cleaned this dangling pointer up. Ugly. :-(
	logger->file = 0;
      }

    } else if (logger->log_id == 3) {

      // No open file. Creating empty Common details. 
      // TODO: Consider tracking the number of active zones being common logged. If > 1 then create empty.
      if (!common_rotated) {
#ifdef ROTATE_LOGGING
	fprintf(stderr, "  Creating empty details for %s logid=%d owner=%d zone=%d\n", rotate_fname, logger->log_id, logger->owner_id, logger->zone_id);
#endif
	FILE* f = fopen(rotate_fname, "wb");
	fclose(f);
	common_rotated = true;
#ifdef ROTATE_LOGGING
      } else {
	fprintf(stderr, "  Common already rotated\n");
#endif
      }

    } else if (logger->log_id == 2) {

      // Single Zone
#ifdef ROTATE_LOGGING
      fprintf(stderr, "  Creating empty details for %s logid=%d owner=%d zone=%d\n", rotate_fname, logger->log_id, logger->owner_id, logger->zone_id);
#endif
      FILE* f = fopen(rotate_fname, "wb");
      fclose(f);
    }
    else if (logger->log_id == 1) {

      // Multi-Zone -- we may have already rotated. No need to create if that's the case.
      if (rotated_by != NULL) {
#ifdef ROTATE_LOGGING
	fprintf(stderr, "  NOT creating empty details for %s, already rotated/created zoneid=%d\n", rotate_fname, *rotated_by);
#endif
      } else {
#ifdef ROTATE_LOGGING
	fprintf(stderr, "  Creating empty details for %s logid=%d owner=%d zone=%d\n", rotate_fname, logger->log_id, logger->owner_id, logger->zone_id);
#endif
	FILE* f = fopen(rotate_fname, "wb");
	fclose(f);
	owners.Insert(owner_key, new int(logger->zone_id));
      }

    }
      
    if (!terminating) {
      if (logger->file != NULL) {
	delete logger->file;
	logger->file = NULL;
	HashKey* open_logger_key = new HashKey(source_fname);
	DetailLogInfo* open_logger = DETAIL_LOGGER_OPEN.Lookup(open_logger_key);
	if (open_logger != NULL) {
#ifdef ROTATE_LOGGING
	  fprintf(stderr, "  Removing open logger info %s\n", source_fname);
#endif
	  DETAIL_LOGGER_OPEN.Remove(open_logger_key);
	}
	delete open_logger_key;
      }
	
      // Only reopen if we're still logging 
      if (!enabled) {
	logger->file = NULL;
#ifdef ROTATE_LOGGING
	fprintf(stderr, "  Not opening logger file, now not logging for %s %d %d\n", logger->fname, logger->owner_id, logger->log_id);
#endif
	unlink(source_fname);
      } else {
	if (logger->log_id == 1 || logger->log_id == 2) {
	  // TODO What if we can't open the file? Permissions, etc...
	  FILE* f = fopen(source_fname, "wb");
	  logger->file = new BroFile(f, source_fname, "wb");
#ifdef ROTATE_LOGGING
	  fprintf(stderr, "  Opening new logger source=%s file=%p\n", source_fname, logger->file);
#endif
	}
      }
    } else {
      unlink(source_fname);
    }

    delete owner_key;
  }
  owners.Clear();
}

void __dns_telemetry_fire_owners(double ts) {
  if (dns_telemetry_owner_info) {
    
    int len = OWNER_INFO.Length();
    if (len > 0) {

      IterCookie* cookie = OWNER_INFO.InitForIteration();
      HashKey* key;
      OwnerStats* info;
      while ((info = OWNER_INFO.NextEntry(key, cookie))) {
	RecordVal* r = new RecordVal(dns_telemetry_owner_stats);
	r->Assign(0, new Val(ts, TYPE_DOUBLE));
	r->Assign(1, new Val(info->id, TYPE_COUNT));
	r->Assign(2, new Val(info->cnt, TYPE_COUNT));
	val_list* vl = new val_list;
	vl->append(r);
	mgr.Dispatch(new Event(dns_telemetry_owner_info, vl), true);
      }
      OWNER_INFO.Clear();

    } else {
      // Always emit an empty record for consistency and to ensure a file exists for the interval
      RecordVal* r = new RecordVal(dns_telemetry_owner_stats);
      r->Assign(0, new Val(ts, TYPE_DOUBLE));
      r->Assign(1, new Val(0, TYPE_COUNT));
      r->Assign(2, new Val(0, TYPE_COUNT));
      val_list* vl = new val_list;
      vl->append(r);
      mgr.Dispatch(new Event(dns_telemetry_owner_info, vl), true);
    }
  }
}

void __dns_telemetry_fire_zones(double ts) {

  if ( dns_telemetry_zone_info ) {

    int len = telemetry_zone_stats.Length();
    if (len > 0) {
      IterCookie* zone_cookie = telemetry_zone_stats.InitForIteration();
      HashKey* zone_k;
      ZoneStats* zv;
      int cnt = 0;
      while ((zv = telemetry_zone_stats.NextEntry(zone_k, zone_cookie)))
	{
	  // Do we need to free each entry (not key) as we iterate?
	  RecordVal* r = new RecordVal(dns_telemetry_zone_stats);
	  r->Assign(0, new Val(ts, TYPE_DOUBLE));
	  r->Assign(1, new StringVal(zv->key));
	  r->Assign(2, new Val(zv->zone_id, TYPE_COUNT));
	  r->Assign(3, new Val(zv->owner_id, TYPE_COUNT));
	  r->Assign(4, new Val(zv->cnt, TYPE_COUNT));
	  r->Assign(5, new Val(zv->A, TYPE_COUNT));
	  r->Assign(6, new Val(zv->AAAA, TYPE_COUNT));
	  r->Assign(7, new Val(zv->CNAME, TYPE_COUNT));
	  r->Assign(8, new Val(zv->NS, TYPE_COUNT));
	  r->Assign(9, new Val(zv->SOA, TYPE_COUNT));
	  r->Assign(10, new Val(zv->SRV, TYPE_COUNT));
	  r->Assign(11, new Val(zv->TXT, TYPE_COUNT));
	  r->Assign(12, new Val(zv->MX, TYPE_COUNT));
	  r->Assign(13, new Val(zv->DO, TYPE_COUNT));
	  r->Assign(14, new Val(zv->RD, TYPE_COUNT));
	  r->Assign(15, new Val(zv->other, TYPE_COUNT));
	  r->Assign(16, new Val(zv->NOERROR, TYPE_COUNT));
	  r->Assign(17, new Val(zv->REFUSED, TYPE_COUNT));
	  r->Assign(18, new Val(zv->NXDOMAIN, TYPE_COUNT));
	  val_list* vl = new val_list;
	  vl->append(r);
	  mgr.Dispatch(new Event(dns_telemetry_zone_info, vl), true);
	}
      telemetry_zone_stats.Clear();
    } else {
      // Always emit an empty record for consistency and to ensure a file exists for the interval
      RecordVal* r = new RecordVal(dns_telemetry_zone_stats);
      r->Assign(0, new Val(ts, TYPE_DOUBLE));
      r->Assign(1, new StringVal(""));
      r->Assign(2, new Val(0, TYPE_COUNT));
      r->Assign(3, new Val(0, TYPE_COUNT));
      r->Assign(4, new Val(0, TYPE_COUNT));
      r->Assign(5, new Val(0, TYPE_COUNT));
      r->Assign(6, new Val(0, TYPE_COUNT));
      r->Assign(7, new Val(0, TYPE_COUNT));
      r->Assign(8, new Val(0, TYPE_COUNT));
      r->Assign(9, new Val(0, TYPE_COUNT));
      r->Assign(10, new Val(0, TYPE_COUNT));
      r->Assign(11, new Val(0, TYPE_COUNT));
      r->Assign(12, new Val(0, TYPE_COUNT));
      r->Assign(13, new Val(0, TYPE_COUNT));
      r->Assign(14, new Val(0, TYPE_COUNT));
      r->Assign(15, new Val(0, TYPE_COUNT));
      r->Assign(16, new Val(0, TYPE_COUNT));
      r->Assign(17, new Val(0, TYPE_COUNT));
      r->Assign(18, new Val(0, TYPE_COUNT));
      val_list* vl = new val_list;
      vl->append(r);
      mgr.Dispatch(new Event(dns_telemetry_zone_info, vl), true);
    }

  }
}

void __dns_telemetry_fire_qnames(double ts) {
  if ( dns_telemetry_qname_info ) {
    int len = 0;
    len = telemetry_qname_stats.Length();
    if (len > 0) {
      IterCookie* qname_cookie = telemetry_qname_stats.InitForIteration();
      HashKey* qname_k;
      QnameStats* qname_v;
      while ((qname_v = telemetry_qname_stats.NextEntry(qname_k, qname_cookie)))
	{
	  char* key =  (char*)qname_k->Key();
	  RecordVal* r = new RecordVal(dns_telemetry_qname_stats);
	  r->Assign(0, new Val(ts, TYPE_DOUBLE));
	  r->Assign(1, new StringVal(key));
	  r->Assign(2, new Val(qname_v->zone_id, TYPE_COUNT));
	  r->Assign(3, new Val(qname_v->owner_id, TYPE_COUNT));
	  r->Assign(4, new Val(qname_v->cnt, TYPE_COUNT));
	  r->Assign(5, new Val(qname_v->A, TYPE_COUNT));
	  r->Assign(6, new Val(qname_v->AAAA, TYPE_COUNT));
	  r->Assign(7, new Val(qname_v->CNAME, TYPE_COUNT));
	  r->Assign(8, new Val(qname_v->MX, TYPE_COUNT));
	  r->Assign(9, new Val(qname_v->SOA, TYPE_COUNT));
	  r->Assign(10, new Val(qname_v->TXT, TYPE_COUNT));
	  r->Assign(11, new Val(qname_v->SRV, TYPE_COUNT));
	  r->Assign(12, new Val(qname_v->NS, TYPE_COUNT));
	  r->Assign(13, new Val(qname_v->other, TYPE_COUNT));
	  val_list* vl = new val_list;
	  vl->append(r);
	  mgr.Dispatch(new Event(dns_telemetry_qname_info, vl), true);
	}
      telemetry_qname_stats.Clear();
    } 

    if (len == 0) {
      RecordVal* r = new RecordVal(dns_telemetry_qname_stats);
      r->Assign(0, new Val(ts, TYPE_DOUBLE));
      r->Assign(1, new StringVal(""));
      r->Assign(2, new Val(0, TYPE_COUNT));
      r->Assign(3, new Val(0, TYPE_COUNT));
      r->Assign(4, new Val(0, TYPE_COUNT));
      r->Assign(5, new Val(0, TYPE_COUNT));
      r->Assign(6, new Val(0, TYPE_COUNT));
      r->Assign(7, new Val(0, TYPE_COUNT));
      r->Assign(8, new Val(0, TYPE_COUNT));
      r->Assign(9, new Val(0, TYPE_COUNT));
      r->Assign(10, new Val(0, TYPE_COUNT));
      r->Assign(11, new Val(0, TYPE_COUNT));
      r->Assign(12, new Val(0, TYPE_COUNT));
      r->Assign(13, new Val(0, TYPE_COUNT));
      val_list* vl = new val_list;
      vl->append(r);
      mgr.Dispatch(new Event(dns_telemetry_qname_info, vl), true);
    }
  }
}

