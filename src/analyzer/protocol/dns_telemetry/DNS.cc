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
#include "NetVar.h"
#include "DNS.h"
#include "Sessions.h"
#include "Event.h"
#include "Hash.h"
#include "Dict.h"
#include "File.h"

#include "events.bif.h"
#include <pthread.h>

#include "sys/sysinfo.h"
#include "sys/times.h"
#include "sys/vtimes.h"
#include "statsd-client.c"

#include <Judy.h>
#include "hiredis.c"
#include "net.c"
#include "sds.c"

static char MY_NODE_ID[10] = "BEACON_ID";
statsd_link *STATSD_LINK;
#define MAX_LINE_LEN 200
#define PKT_LEN 1400

void __dns_telemetry_set_node_id(const char* id) {
  strcpy(MY_NODE_ID, id);
}

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
  uint T2R_min;
  uint T2R_max;
  uint T2R_avg;
  uint NX_T2R_min;
  uint NX_T2R_max;
  uint NX_T2R_avg;
  uint A_T2R_min;
  uint A_T2R_max;
  uint A_T2R_avg;
  uint ANY_T2R_min;
  uint ANY_T2R_max;
  uint ANY_T2R_avg;
  uint CNAME_T2R_min;
  uint CNAME_T2R_max;
  uint CNAME_T2R_avg;
  uint PTR_T2R_min;
  uint PTR_T2R_max;
  uint PTR_T2R_avg;
  uint AAAA_T2R_min;
  uint AAAA_T2R_max;
  uint AAAA_T2R_avg;
};

struct AnyRDCounts {
  char ip[20];
  char query[128];
  int cnt;
};

struct AnchorPoint {
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
declare(PDict,AnchorPoint);

PDict(int) telemetry_anyrd_counts;
PDict(int) telemetry_client_stats;
PDict(QnameStats) telemetry_qname_stats;
PDict(ZoneStats) telemetry_zone_stats;
PDict(AnchorPoint) telemetry_anchor_map;

// #define DEBUG_ROTATE_LOGGING 

bool do_counts = false;
bool do_totals = false;
bool do_zone_stats = true;
bool do_owner_stats = true;
bool do_qname_stats = true;
bool do_anyrd_stats = true;
bool do_client_stats = true;
bool do_details = true;
bool do_details_all = false;
uint sample_rate = 1;
bool do_details_statsd = false;
bool do_details_redis = false;

#define MAX_LOG_BUFFER 1024*1024

// We support three types of detail logging
//
// ZONE_MANY - A combination of zones. Presumably for an owner who operates mulitple zones and wants a aggregate log of activity.
// ZONE_ONLY - A per zone detail only.
// ZONE_ALL  - All (common log lines). How things are with 'traditional' DBIND.

#define LOGGER_ZONE_NONE 0
#define LOGGER_ZONE_MANY 1
#define LOGGER_ZONE_ONLY 2
#define LOGGER_ZONE_ALL  3

struct DetailLogInfo {
  double ts;
  int owner_id;
  int log_id;
  int zone_id;
  bool enabled;
  PDict(int) zones;
  char* fname;
  BroFile* file;
  FILE* raw_file;
  uint buflen;
  uint bufcnt;
  char buffer[MAX_LOG_BUFFER];
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
  FILE* raw_file;
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

struct QueryClient {
  double start;
  uint32 atype;
  uint32 qtype;
};

declare(PDict,QueryClient);
PDict(QueryClient) QUERY_CLIENTS;

CurCounts CNTS;
CurCounts TOTALS;

// ----------------------------------------------------
// ----------------------------------------------------

class AnchorMapUpdater : public threading::MsgThread {
public:
  AnchorMapUpdater(char* _fname, double _interval = 60);
  virtual ~AnchorMapUpdater();
  virtual bool OnHeartbeat(double network_time, double current_time);
  virtual bool OnFinish(double network_time);
protected:
  double interval;
  double next;
  time_t last;
  char fname[512];
};


int parseLine(char* line){
  int i = strlen(line);
  while (*line < '0' || *line > '9') line++;
  line[i-3] = '\0';
  i = atoi(line);
  return i;
}
    

static int getValues(int* VIRT, int* RES, int* DATA, int* FD){
  //Note: this value is in KB!
  FILE* file = fopen("/proc/self/status", "r");
  int result = -1;
  char line[128];
    

  while (fgets(line, 128, file) != NULL) {
    if (strncmp(line, "VmSize:", 7) == 0){
      *VIRT = parseLine(line);
    }
    else if (strncmp(line, "VmRSS:", 6) == 0){
      *RES = parseLine(line);
    }
    else if (strncmp(line, "VmData:", 7) == 0){
      *DATA = parseLine(line);
    }
    else if (strncmp(line, "FDSize:", 7) == 0){
      *FD = parseLine(line);
    }
  }
  fclose(file);
  return result;
}

// -------------------------
// Redis Utils
// -------------------------

Pvoid_t EVENT_CACHE = (Pvoid_t) NULL;
Word_t  EVENT_TOTAL = 0;
Word_t  EVENT_COUNT = 0;
const char* EVENT_CHANNEL = "beacon";
#define MAXVAL 32
int     LAST_SUBSCRIBERS = 0;

redisContext *REDIS = NULL;

static void redis_init() {
  struct timeval timeout = { 1, 500000 }; // 1.5 seconds
  REDIS = redisConnectWithTimeout("127.0.0.1", 6379, timeout);
  if (REDIS == NULL || REDIS->err) {
    if (REDIS) {
      printf("Connection error: %s\n", REDIS->errstr);
      redisFree(REDIS);
    } else {
      printf("Connection error: can't allocate redis context\n");
    }
    exit(1);
  }

}

static void redis_term() {
  fprintf(stderr, "Closing redis connection\n");
  if (REDIS != NULL) {
    redisFree(REDIS);
    REDIS = NULL;
  }
}

AnchorMapUpdater::AnchorMapUpdater(char* _fname, double _interval) {
  double now = current_time();

  SetName("ZoneUpdater");
  interval = _interval;
  strcpy(fname, _fname);
  next = now + interval;
  struct stat buf;
  stat(fname, &buf);
  int size = buf.st_size;
  last = buf.st_mtime;

  fprintf(stderr, "%f statsd_init NODE=%s\n", now, MY_NODE_ID);
  STATSD_LINK = statsd_init_with_namespace("127.0.0.1", 8125, MY_NODE_ID);
  redis_init();
}

AnchorMapUpdater::~AnchorMapUpdater() {
  fprintf(stderr, "%f AnchorMapUpdater::dtor\n", current_time());
  statsd_finalize(STATSD_LINK);
  redis_term();
}

int __dns_telemetry_load_anchor_map(const char* fname, const char* details_fname);

bool AnchorMapUpdater::OnHeartbeat(double network_time, double current_time) {
  if (current_time > next) {
    // See if the zonemap has changed
    struct stat buf;
    stat(fname, &buf);
    if (buf.st_mtime != last) {
      static char old_timestr[256];
      strftime(old_timestr, sizeof(old_timestr), "%Y%m%dT%H%M%S", localtime(&last));
      static char new_timestr[256];
      strftime(new_timestr, sizeof(new_timestr), "%Y%m%dT%H%M%S", localtime(&buf.st_mtime));
      fprintf(stderr,"%f zonemap change detected old=%s new=%s\n", current_time, old_timestr, new_timestr);
      last = buf.st_mtime;
      __dns_telemetry_load_anchor_map(fname, NULL);
    }
    next += interval;
  }
  return 1;
}

bool AnchorMapUpdater::OnFinish(double network_time) {
  return 1;
}

AnchorMapUpdater* ANCHOR_MAP_UPDATER = NULL;

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

	// fprintf(stderr, "Message %f\n", network_time);

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

	/*
	if ( dns_telemetry_message )
		{
		val_list* vl = new val_list();
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(is_query, TYPE_BOOL));
		vl->append(msg.BuildHdrVal());
		vl->append(new Val(len, TYPE_COUNT));
		analyzer->ConnectionEvent(dns_telemetry_message, vl);
		}
	*/

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
		fprintf(stderr, "..REFUSED handling needed\n");
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

  // We'll calculte TLZ (apex) based on anchor map while extracting the name.
  // Since we have to do the lookup into the ZoneMap, calculate that as well so as to avoid an extra lookup

  char tlz [513];
  AnchorPoint* anchor_entry = 0;
  u_char* name_end = ExtractName(data, len, name, name_len, msg_start, tlz, (void**)&anchor_entry);


  if ( ! name_end )
    return 0;

  if ( len < int(sizeof(short)) * 2 )
    {
      analyzer->Weird("DNS_truncated_quest_too_short");
      return 0;
    }

  // fprintf(stderr, "..ParseQuestion qname=%s len=%d tlz=%s anchor=%p query=%d rcode=%d id=%d\n", name, len, tlz, anchor_entry, is_query, msg->rcode, msg->id);

  const char* s_addr = analyzer->Conn()->OrigAddr().AsString().c_str();
  char s_orig_addr[32];
  strcpy(s_orig_addr, s_addr);	// save copy Conn() calls will reset this pointer

  // Ignore stats on requests originating on the 10 net.
  bool skip = false;
  if (strstr(s_orig_addr, "10.") != NULL) {
    skip = true;
  }

  if (!skip) {

    bool local_do_counts = do_counts;
    bool local_do_zone_stats = do_zone_stats;
    bool local_do_owner_stats = do_owner_stats;
    bool local_do_qname_stats = do_qname_stats;

    EventHandlerPtr dns_event = 0;
    ZoneStats* zone_stats = 0;
    OwnerStats* owner_stats = 0;
    bool do_zone_details = false;
    CurCounts* custom_stats= 0;
    bro_int_t owner_id = 0;
    HashKey* zone_hash = new HashKey(tlz);

    if (local_do_zone_stats && dns_telemetry_zone_info) {

      anchor_entry = telemetry_anchor_map.Lookup(zone_hash);

      if (!anchor_entry) {
	// Get rid of the zoneid based specific hash and use the OTHER zone hash
	delete zone_hash;
	const char other[] = "?";
	HashKey* other_hash = new HashKey(other);
	zone_stats = telemetry_zone_stats.Lookup(other_hash);
	zone_hash = other_hash;

      } else {
	zone_stats = telemetry_zone_stats.Lookup(zone_hash);
	do_zone_details = anchor_entry->details;
	owner_id = (bro_int_t)anchor_entry->owner_id;
	HashKey* stat_logger_key = new HashKey(owner_id);
	StatsLogInfo* stat_logger = STATS_LOGGER_INFO.Lookup(stat_logger_key);
	if (stat_logger) {
	  custom_stats = &stat_logger->CNTS;
	}
	delete stat_logger_key;
      }
    }

    // Detemrine if we should do additional processing based on sampling rate.
    if (sample_rate != 1) {
      local_do_counts = (TOTALS.request % sample_rate) == 0;
      if (do_counts && local_do_counts == false) {
	local_do_zone_stats = false;
	local_do_qname_stats = false;
	local_do_owner_stats = false;
	if (is_query) {
	  ++TOTALS.request;
	} else {
	  ++TOTALS.reply;
	}
      }
    }

    if (local_do_counts) {

      if (is_query) {

	++CNTS.request;
	++TOTALS.request;

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

    if (local_do_owner_stats && is_query) {
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

    if (local_do_counts && !zone_stats) {
    
      ++CNTS.zones;
      if (custom_stats) 
	++custom_stats->zones;
      zone_stats = new ZoneStats();
      zone_stats->cnt = 0;
    
      if (anchor_entry) {
	// An anchor point that  we know about
	strcpy(zone_stats->key, tlz);
	zone_stats->zone_id = anchor_entry->zone_id;
	zone_stats->owner_id = anchor_entry->owner_id;
      } else {
	// OTHER bucket for now
	strcpy(zone_stats->key, "?");
	zone_stats->zone_id = 0;
	zone_stats->owner_id = 0;
      }
      telemetry_zone_stats.Insert(zone_hash, zone_stats);
    }

    QnameStats* qname_stat = 0;

    if (is_query && local_do_qname_stats && dns_telemetry_qname_info) {
      if (anchor_entry) {
	HashKey* filter_key = new HashKey((bro_int_t)anchor_entry->zone_id);
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
	  qname_stat->zone_id = anchor_entry->zone_id;
	  qname_stat->owner_id = anchor_entry->owner_id;
	}
	delete filter_key;
	local_do_qname_stats = qname_stat != NULL;
      } else {
	// fprintf(stderr, "ERROR: No anchor entry! name=%s tlz=%s\n", name, tlz);
	local_do_qname_stats = false;
      }
    }

    if ( msg->QR == 0 ) {

      dns_event = dns_telemetry_request;

      RR_Type qtype = RR_Type(ExtractShort(data, len));
      msg->qtype = qtype;
    
      if (local_do_zone_stats) {
	++zone_stats->cnt;
	if (msg->RD) {
	  ++zone_stats->RD;
	}
      }
	
      const IPAddr& resp_addr = analyzer->Conn()->RespAddr();
      string sAddrResp = resp_addr.AsString();
      const char* sAddrResp_cstr = sAddrResp.c_str();

      // fprintf(stderr, "QUERY|ORIG: %s RESP: %s id=%d qtype=%u %f\n", s_orig_addr_cstr, sAddrResp_cstr, msg->id, msg->qtype, network_time);

      if (is_query) {
	// Remember the client's IP. Use the message transaction id as the temporary key. 
	// There is chance of a small/probablistic chance of collision. See BRO transaction id comments in their source code.
	HashKey* client_hash = new HashKey((uint32)msg->id);
	QueryClient* query_client = QUERY_CLIENTS.Lookup(client_hash);
	if (query_client) {
	  query_client->start = network_time;
	  query_client->qtype = msg->qtype;
	} else {
	  query_client = new QueryClient();
	  query_client->start = network_time;
	  query_client->qtype = msg->qtype;
	  QUERY_CLIENTS.Insert(client_hash, query_client);
	}
	delete client_hash;
      }

      if (is_query && do_client_stats) {

	HashKey* client_hash = new HashKey(s_orig_addr);
	int* client_idx = telemetry_client_stats.Lookup(client_hash);
	if (client_idx) {
	  ++(*client_idx);
	} else {
	  telemetry_client_stats.Insert(client_hash, new int(1));
	  if (local_do_counts) {
	    ++CNTS.clients;
	  }
	  ++TOTALS.clients;
	  if (custom_stats) {
	    ++custom_stats->clients;
	  }
	}
	delete client_hash;
      }

      if (local_do_counts) {
	switch (qtype) 
	  {
	  case TYPE_A:
	    // fprintf(stderr, "QUERY|qtype=%u %f\n", qtype, network_time);
	    ++CNTS.A;
	    ++TOTALS.A;
	    if (custom_stats) 
	      ++custom_stats->A;
	    if (local_do_qname_stats)
	      ++qname_stat->A;
	    if (do_zone_stats)
	      ++zone_stats->A;
	    break;
	  case TYPE_NS:
	    ++CNTS.NS;
	    ++TOTALS.NS;
	    if (custom_stats) 
	      ++custom_stats->NS;
	    if (local_do_qname_stats)
	      ++qname_stat->NS;
	    if (do_zone_stats)
	      ++zone_stats->NS;
	    break;
	  case TYPE_CNAME:
	    ++CNTS.CNAME;
	    ++TOTALS.CNAME;
	    if (custom_stats) 
	      ++custom_stats->CNAME;
	    if (local_do_qname_stats)
	      ++qname_stat->CNAME;
	    if (do_zone_stats)
	      ++zone_stats->CNAME;
	    break;
	  case TYPE_SOA:
	    ++CNTS.SOA;
	    ++TOTALS.SOA;
	    if (custom_stats) 
	      ++custom_stats->SOA;
	    if (local_do_qname_stats)
	      ++qname_stat->SOA;
	    if (do_zone_stats)
	      ++zone_stats->SOA;
	    break;
	  case TYPE_PTR:
	    ++CNTS.PTR;
	    ++TOTALS.PTR;
	    if (custom_stats) 
	      ++custom_stats->PTR;
	    if (local_do_qname_stats)
	      ++qname_stat->PTR;
	    if (do_zone_stats)
	      ++zone_stats->PTR;
	    break;
	  case TYPE_MX:
	    ++CNTS.MX;
	    ++TOTALS.MX;
	    if (custom_stats) 
	      ++custom_stats->MX;
	    if (local_do_qname_stats)
	      ++qname_stat->MX;
	    if (do_zone_stats)
	      ++zone_stats->MX;
	    break;
	  case TYPE_TXT:
	    ++CNTS.TXT;
	    ++TOTALS.TXT;
	    if (custom_stats) 
	      ++custom_stats->TXT;
	    if (local_do_qname_stats)
	      ++qname_stat->TXT;
	    if (do_zone_stats)
	      ++zone_stats->TXT;
	    break;
	  case TYPE_AAAA:
	    ++CNTS.AAAA;
	    ++TOTALS.AAAA;
	    if (custom_stats) 
	      ++custom_stats->AAAA;
	    if (local_do_qname_stats)
	      ++qname_stat->AAAA;
	    if (do_zone_stats)
	      ++zone_stats->AAAA;
	    break;
	  case TYPE_SRV:
	    ++CNTS.SRV;
	    ++TOTALS.SRV;
	    if (custom_stats) 
	      ++custom_stats->SRV;
	    if (local_do_qname_stats)
	      ++qname_stat->SRV;
	    if (do_zone_stats)
	      ++zone_stats->SRV;
	    break;
	  case TYPE_ALL:
	    ++CNTS.ANY;
	    ++TOTALS.ANY;
	    if (custom_stats) 
	      ++custom_stats->ANY;
	    if (local_do_qname_stats)
	      ++qname_stat->other;
	    if (do_zone_stats)
	      ++zone_stats->other;
	    if (msg->RD) {
	      ++CNTS.ANY_RD;
	      ++TOTALS.ANY_RD;
	      if (custom_stats) 
		++custom_stats->RD;

	      if (do_anyrd_stats) {
		char anyrd_key[560];
		sprintf(anyrd_key, "%s|%s", s_orig_addr, name);
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
	      ++zone_stats->other;
	    break;
	  }
      }
    }
    else if ( msg->QR == 1 &&  msg->ancount == 0 && msg->nscount == 0 && msg->arcount == 0 ) {
      // Service rejected in some fashion, and it won't be reported
      // via a returned RR because there aren't any.
      dns_event = dns_telemetry_rejected;
      if (local_do_counts) {
	++CNTS.rejected;
	++CNTS.rcode_refused;
	++TOTALS.rejected;
	++TOTALS.rcode_refused;
	if (custom_stats) {
	  ++custom_stats->rejected;
	  ++custom_stats->rcode_refused;
	}
      }

      string resp_addr = analyzer->Conn()->RespAddr().AsString();
      const char* s_resp_addr = resp_addr.c_str();

      HashKey* client_hash = new HashKey((uint32)msg->id);
      QueryClient* query_client = QUERY_CLIENTS.Lookup(client_hash);
      double start_time = 0;
      uint orig_qtype = 0;
      if (query_client) {
	start_time = query_client->start;
	orig_qtype = query_client->qtype;
	// TODO: Delete? Do we care. If we overlap on a 32bit int we're just eating memory
      }
      delete client_hash;
      uint t2r = (network_time - start_time)*1000000; // As unsigned micro seconds!

      CNTS.T2R_min = CNTS.T2R_min == 0 ? t2r : min(CNTS.T2R_min, t2r);
      CNTS.T2R_max = max(CNTS.T2R_max, t2r);
      CNTS.T2R_avg += t2r;

      // fprintf(stderr, "..ORIG qtype=%u A T2R %f\n", orig_qtype, network_time);

      switch (orig_qtype) {
      case TYPE_A:
      case TYPE_AAAA:
	{
	  CNTS.A_T2R_min = CNTS.A_T2R_min == 0 ? t2r : min(CNTS.A_T2R_min, t2r);
	  CNTS.A_T2R_max = max(CNTS.A_T2R_max, t2r);
	  CNTS.A_T2R_avg += t2r;
	  break;
	}
      case TYPE_CNAME:
	{
	  CNTS.CNAME_T2R_min = CNTS.CNAME_T2R_min == 0 ? t2r : min(CNTS.CNAME_T2R_min, t2r);
	  CNTS.CNAME_T2R_max = max(CNTS.CNAME_T2R_max, t2r);
	  CNTS.CNAME_T2R_avg += t2r;
	  break;
	}
      case TYPE_ALL:
	{
	  CNTS.ANY_T2R_min = CNTS.ANY_T2R_min == 0 ? t2r : min(CNTS.ANY_T2R_min, t2r);
	  CNTS.ANY_T2R_max = max(CNTS.ANY_T2R_max, t2r);
	  CNTS.ANY_T2R_avg += t2r;
	  break;
	}
      case TYPE_PTR:
	{
	  CNTS.PTR_T2R_min = CNTS.PTR_T2R_min == 0 ? t2r : min(CNTS.PTR_T2R_min, t2r);
	  CNTS.PTR_T2R_max = max(CNTS.PTR_T2R_max, t2r);
	  CNTS.PTR_T2R_avg += t2r;
	  break;
	}
      default:
	{
	  break;
	}
      }
      if (local_do_zone_stats)
	++zone_stats->REFUSED;
    } else {

      // A REPLY. We don't do details until we've received the reply because of what we want to includes as part of that.
      dns_event = dns_telemetry_query_reply;

      HashKey* client_hash = new HashKey((uint32)msg->id);
      QueryClient* query_client = QUERY_CLIENTS.Lookup(client_hash);
      double start_time = 0;
      uint orig_qtype = 0;
      if (query_client) {
	start_time = query_client->start;
	orig_qtype = query_client->qtype;
	// TODO: Delete? Do we care. If we overlap on a 32bit int we're just eating memory
      }
      delete client_hash;
      uint t2r = (network_time - start_time)*1000000; // As unsigned micro seconds!
    
      CNTS.T2R_min = CNTS.T2R_min == 0 ? t2r : min(CNTS.T2R_min, t2r);
      CNTS.T2R_max = max(CNTS.T2R_max, t2r);
      CNTS.T2R_avg += t2r;
    
      if (msg->rcode == DNS_CODE_NAME_ERR) {
	CNTS.NX_T2R_min = CNTS.NX_T2R_min == 0 ? t2r : min(CNTS.NX_T2R_min, t2r);
	CNTS.NX_T2R_max = max(CNTS.NX_T2R_max, t2r);
	CNTS.NX_T2R_avg += t2r;
      }

      // fprintf(stderr, "..ORIG qtype=%u A T2R %f\n", orig_qtype, network_time);

      switch (orig_qtype) {
      case TYPE_A:
      case TYPE_AAAA:
	{
	  CNTS.A_T2R_min = CNTS.A_T2R_min == 0 ? t2r : min(CNTS.A_T2R_min, t2r);
	  CNTS.A_T2R_max = max(CNTS.A_T2R_max, t2r);
	  CNTS.A_T2R_avg += t2r;
	  break;
	}
      case TYPE_CNAME:
	{
	  CNTS.CNAME_T2R_min = CNTS.CNAME_T2R_min == 0 ? t2r : min(CNTS.CNAME_T2R_min, t2r);
	  CNTS.CNAME_T2R_max = max(CNTS.CNAME_T2R_max, t2r);
	  CNTS.CNAME_T2R_avg += t2r;
	  break;
	}
      case TYPE_ALL:
	{
	  CNTS.ANY_T2R_min = CNTS.ANY_T2R_min == 0 ? t2r : min(CNTS.ANY_T2R_min, t2r);
	  CNTS.ANY_T2R_max = max(CNTS.ANY_T2R_max, t2r);
	  CNTS.ANY_T2R_avg += t2r;
	  break;
	}
      case TYPE_PTR:
	{
	  CNTS.PTR_T2R_min = CNTS.PTR_T2R_min == 0 ? t2r : min(CNTS.PTR_T2R_min, t2r);
	  CNTS.PTR_T2R_max = max(CNTS.PTR_T2R_max, t2r);
	  CNTS.PTR_T2R_avg += t2r;
	  break;
	}
      default:
	{
	  break;
	}
      }

      if (do_details_redis && anchor_entry != 0) {

	char beacon[256];  
	strcpy(beacon, (char*)name);
	char* saveptr;
	strtok_r(beacon, ".", &saveptr);
	char* cust_data = strtok_r(NULL, ".", &saveptr);
	char* cust_id = strtok_r(NULL, ".", &saveptr);
	
	char redis_cmd[256];
#if PUBLISH_REALTIME
	sprintf(redis_cmd, "PUBLISH beacon %f,D,%s,%s,%s,%s,%s", network_time,MY_NODE_ID,s_orig_addr,beacon,cust_id, cust_data);
	redisReply *reply = (redisReply*)redisCommand(REDIS, redis_cmd);
	freeReplyObject(reply);
#else
	// Add to event cache. Flushed when we dump per second stats
	char* val = (char*)malloc(256);
	sprintf(val, "%f,D,%s,%s,%s,%s,%s", network_time,MY_NODE_ID,s_orig_addr,beacon,cust_id,cust_data);
	PWord_t PV = NULL;
	++EVENT_COUNT;
	// fprintf(stderr, "%s %lu\n", val, EVENT_COUNT);
	JError_t J_Error;
	if (((PV) = (PWord_t)JudyLIns(&EVENT_CACHE, EVENT_COUNT, &J_Error)) == PJERR) {
	  J_E("JudyLIns", &J_Error);
	}
	*PV = (Word_t)val;
#endif
      }

      if (do_details_statsd && anchor_entry != 0) {

	char log_line[256];
	char beacon[256];
	strcpy(beacon, (char*)name);
	char* saveptr;
	strtok_r(beacon, ".", &saveptr);
	char* cust_id = strtok_r(NULL, ".", &saveptr);
	sprintf(log_line, "%f,D,%s,%s,%s,", network_time,s_orig_addr,beacon,cust_id);

	char pkt[PKT_LEN];
	statsd_prepare(STATSD_LINK, log_line, 1, "kv", 1, pkt, MAX_LINE_LEN, 1);
	statsd_send(STATSD_LINK, pkt);

      }
      else if (do_details_all || (do_details && do_zone_details)) {

	++CNTS.logged;
	++TOTALS.logged;
	if (custom_stats)
	  ++custom_stats->logged;
      
	string resp_addr = analyzer->Conn()->RespAddr().AsString();
	const char* s_resp_addr = resp_addr.c_str();

	// string orig_addr = analyzer->Conn()->OrigAddr().AsString();
	// const char* s_orig_addr = orig_addr.c_str();
	// fprintf(stderr, "REPLY|ORIG: %s RESP: %s id=%d qtype=%u rcode=%u %f %f t2r=%u\n", s_orig_addr, s_resp_addr, msg->id, orig_qtype, msg->rcode, network_time, start_time, t2r);

	char log_line[256];
	sprintf(log_line, "%f,%s,%u,%u,%d,%s,%s,%u\n", network_time,(char*)name,orig_qtype,msg->rcode,msg->ttl,s_orig_addr,s_resp_addr,msg->opcode);
	uint len = strlen(log_line);

	// fprintf(stderr, "%s", log_line);

	// Determine which logger we should use
	DetailLogInfo* logger = 0;
	if (anchor_entry != 0 && anchor_entry->log_id != 0) {

	  if (!do_details_all) {
	    HashKey* log_key = new HashKey((bro_int_t)anchor_entry->zone_id);
	    logger = DETAIL_LOGGER_INFO.Lookup(log_key);
	  
	    if (logger == 0) {
	      fprintf(stderr, "WARN: Unexpected lack of DetailLogInfo config zone_id=%d owner_id=%d log_id=%d\n", anchor_entry->zone_id, anchor_entry->owner_id, anchor_entry->log_id);
	      // Create new logger
	      logger = new DetailLogInfo();
	      logger->owner_id = anchor_entry->owner_id;
	      logger->log_id = anchor_entry->log_id;
	      logger->ts = network_time;
	      logger->enabled = true;
	      logger->buflen = 0;
	      logger->bufcnt = 0;
	      // Use the base multi-tenant logger's root
	      logger->fname = DETAIL_DEFAULT_PATH;
	      DETAIL_LOGGER_INFO.Insert(log_key, logger);
	    }
	    delete log_key;

	    // Switch to using the common logger if that's what's configured
	    if (logger->log_id == 3) {
	      // fprintf(stderr, "using common logger\n");
	      logger = NULL;
	    }
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
	      case LOGGER_ZONE_MANY:
		{
		  // Multi Zone
		  sprintf(source_fname, "%s-O-%08d.log", root_fname, logger->owner_id);
		  break;
		}
	      case LOGGER_ZONE_ONLY:
		{
		  // Single Zone
		  sprintf(source_fname, "%s-Z-%08d.log", root_fname, logger->zone_id);
		  break;
		}
	      case LOGGER_ZONE_ALL:
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

	    if (logger->log_id == LOGGER_ZONE_MANY) {
	      // Determine if we've got an open logger for the source name. If so, use that.
	      HashKey* open_logger_key = new HashKey(source_fname);
	      DetailLogInfo* open_logger = DETAIL_LOGGER_OPEN.Lookup(open_logger_key);
	      if (open_logger) {
		// fprintf(stderr, "Using existing logger %s logid=%d owner=%d my_zone=%d other_zone=%d\n", source_fname, logger->log_id, logger->owner_id, logger->zone_id, open_logger->zone_id);
		logger->file = open_logger->file;
		logger->raw_file = open_logger->raw_file;
	      } else {
		FILE* f = fopen(source_fname, "wb");
		logger->file = new BroFile(f, source_fname, "wb");
		logger->raw_file = f;
		DETAIL_LOGGER_OPEN.Insert(open_logger_key, logger);
		// fprintf(stderr, "Creating logger %s logid=%d owner=%d zone=%d file=%p\n", source_fname, logger->log_id, logger->owner_id, logger->zone_id, logger->file);
	      }
	      delete open_logger_key;

	    } else {
	      FILE* f = fopen(source_fname, "wb");
	      logger->file = new BroFile(f, source_fname, "wb");
	      logger->raw_file = f;
#ifdef ROTATE_LOGGING
	      fprintf(stderr, "Creating logger %s logid=%d owner=%d zone=%d file=%p\n", source_fname, logger->log_id, logger->owner_id, logger->zone_id, logger->file);
#endif
	    }
	  }

	  if (logger->buflen + len > MAX_LOG_BUFFER) {
	    logger->file->Write(logger->buffer, logger->buflen);
	    logger->buflen = 0;
	    logger->bufcnt = 0;
	  }
	  memcpy(logger->buffer + logger->buflen, log_line, len);
	  logger->buflen += len;
	  ++logger->bufcnt;
	}
      }

      if (local_do_counts) {

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
	      ++zone_stats->NOERROR;
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
	      ++zone_stats->NXDOMAIN;
	    break;
	  case DNS_CODE_NOT_IMPL:
	    ++CNTS.rcode_not_impl;
	    ++TOTALS.rcode_not_impl;
	    if (custom_stats) 
	      ++custom_stats->rcode_not_impl;
	    break;
	  case DNS_CODE_REFUSED:
	    ++CNTS.rejected;
	    ++CNTS.rcode_refused;
	    ++TOTALS.rcode_refused;
	    ++TOTALS.rejected;
	    if (custom_stats) {
	      ++custom_stats->rcode_refused;
	      ++custom_stats->rejected;
	    }
	    if (do_zone_stats)
	      ++zone_stats->REFUSED;
	    break;
	  }
      }
    }
    delete zone_hash;
  } 

  // Consume the unused type/class.
  (void) ExtractShort(data, len);
  (void) ExtractShort(data, len);

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

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start, 0, 0);
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
					       char* tlz, void** pzinfo)
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
	  HashKey *key = new HashKey(pSearch);
	  AnchorPoint* anchor_entry = telemetry_anchor_map.Lookup(key);
	  if (anchor_entry != 0) {
	    // We're done.
	    match = true;
	    strcpy(tlz, pSearch);
	    if (pzinfo) {
	      *pzinfo = anchor_entry;
	    }
	    delete key;
	    break;
	  } else {
	    delete key;
	    pSearch = ::strchr(pSearch, '.');
	  }
	}
      while(pSearch && ++pSearch < pDelim);
    }
    if (!match) {
      strcpy(tlz, "?");
    }
    // fprintf(stderr, "::ExtractName qname=%s len=%d tlz=%s %p %p\n", name_start, n, tlz, pzinfo, pzinfo ? *pzinfo : 0);
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

		u_char* name_end = ExtractName(recurse_data, recurse_max_len, name, name_len, msg_start,0, 0);

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

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start, 0, 0);
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

	u_char* mname_end = ExtractName(data, len, mname, mname_len, msg_start, 0, 0);
	if ( ! mname_end )
		return 0;

	u_char rname[513];
	int rname_len = sizeof(rname) - 1;

	u_char* rname_end = ExtractName(data, len, rname, rname_len, msg_start, 0, 0);
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

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start, 0, 0);
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

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start, 0, 0);
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
	u_char* alg_name_end = ExtractName(data, len, alg_name, alg_name_len, msg_start,0, 0);

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
  IterCookie* c = telemetry_anchor_map.InitForIteration();
  HashKey* k;
  AnchorPoint* val;
  uint size = DETAIL_LOGGER_INFO.MemoryAllocation();
  int loggers = DETAIL_LOGGER_INFO.Length();
  int len = telemetry_anchor_map.Length();
  fprintf(stderr,"Config @ %f - Zone Info len=%d size=%u loggers=%d\n", current_time(),len, size, loggers);
}

int __dns_telemetry_load_anchor_map(const char* fname, const char* details_fname) {

  // Config the common logger (logid=3, owner_id=0)
  DetailLogInfo* common_logger;
  HashKey* key = new HashKey((bro_int_t)0);
  if (DETAIL_LOGGER_INFO.Length() == 0 && details_fname != NULL) {
    common_logger = new DetailLogInfo();
    strcpy(DETAIL_DEFAULT_PATH, details_fname);
    common_logger->fname = DETAIL_DEFAULT_PATH;
    common_logger->owner_id = 0;
    common_logger->enabled = true;
    common_logger->buflen = 0;
    common_logger->bufcnt = 0;
    common_logger->log_id = LOGGER_ZONE_ALL;
    if (common_logger->file != 0) {
      delete common_logger->file;
    }
    common_logger->file = NULL;
    common_logger->log_id = LOGGER_ZONE_ALL;
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
  int estimated_cnt = size / 43;
  char anchor_map_fname[512];
  strcpy(anchor_map_fname, fname);
  char timestr[256];
  strftime(timestr, sizeof(timestr), "%Y%m%dT%H%M%S", localtime(&buf.st_mtime));
  fprintf(stderr, "%f anchor_map.start %s size=%d cnt=%d (estimate) lastmod=%s\n", start, fname, size, estimated_cnt, timestr);

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

      if (log_id > LOGGER_ZONE_ALL) {
	fprintf(stderr, "ERROR: log_id must be either 0 (none), 1 (owner), 2 (zone) or 3 (common) logid=%d owner_id=%d zone_id=%d %s\n", log_id, owner_id, zone_id, name);
      }

      AnchorPoint* anchor_entry;

      HashKey* zone_hash = new HashKey(name);
      anchor_entry = telemetry_anchor_map.Lookup(zone_hash);
      if (!anchor_entry) {
	anchor_entry = new AnchorPoint();
	telemetry_anchor_map.Insert(zone_hash, anchor_entry);
      }
      delete zone_hash;

      if (log_id != 0 || qname_id != 0 || stat_id != 0) {
	fprintf(stderr, "%f anchor_map %s\tzid=%d\toid=%d\tlid=%d\tsid=%d\tqid=%d\n", current_time(), name, zone_id, owner_id, log_id, stat_id, qname_id);
      }

      strcpy(anchor_entry->key, name);
      anchor_entry->zone_id = zone_id;
      anchor_entry->owner_id = owner_id;
      anchor_entry->log_id = log_id;
      anchor_entry->stat_id = stat_id;
      anchor_entry->qname_id = qname_id;
      anchor_entry->details = log_id != 0;

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
      HashKey* logger_key = new HashKey((bro_int_t)anchor_entry->zone_id);
      logger = DETAIL_LOGGER_INFO.Lookup(logger_key);
      delete logger_key;
      
      if (log_id == LOGGER_ZONE_NONE && logger) {

	// Update the logid. Could be toggling details on/off for a particular customer
	// Owner ID can't / shouldn't change. Nor the location that we write these logs to.
	if (logger->log_id != 0) {
	  fprintf(stderr, "%f anchor_map\t%s\tdisabling logging (was %d) zoneid=%d ownerid=%d\n", current_time(), name, logger->log_id, logger->zone_id, logger->owner_id);
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
	  logger->owner_id = anchor_entry->owner_id;
	  logger->log_id = anchor_entry->log_id;
	  logger->zone_id = anchor_entry->zone_id;
	  logger->ts = network_time;
	  logger->enabled = true;
	  logger->buflen = 0;
	  logger->bufcnt = 0;
	  logger->fname = common_logger->fname;
	  HashKey* log_key = new HashKey((bro_int_t)anchor_entry->zone_id);
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
    int map_size = telemetry_anchor_map.Length();
    uint ignored = cnt - map_size;
    fprintf(stderr, "%f anchor_map.done time=%f error=%u add=%u change=%u cnt=%d %.0f\n", current_time(), diff, ignored, add, change, map_size, rate);

    if (ANCHOR_MAP_UPDATER == NULL) {
      ANCHOR_MAP_UPDATER = new AnchorMapUpdater(anchor_map_fname, 5);
      ANCHOR_MAP_UPDATER->Start();
    }

  }
  return 1;
}

val_list* buildCountsRecord(CurCounts* cnts, uint owner_id, double ts, double lag, uint _rate, bool is_totals) {
  val_list* vl = new val_list;
  RecordVal* r = new RecordVal(dns_telemetry_counts);

  // fprintf(stderr, "..building Counts Record ts=%f lag=%f rate=%u owner_id=%u %p\n", ts, lag, rate, owner_id, cnts);

  uint rate = _rate;
  if ((_rate != 1 && is_totals) || cnts->request < rate)
    rate = 1;

  r->Assign(0, new Val(ts, TYPE_DOUBLE));
  r->Assign(1, new Val(lag, TYPE_DOUBLE));
  r->Assign(2, new Val(owner_id, TYPE_COUNT));

  r->Assign(3, new Val(cnts->request*rate, TYPE_COUNT));
  r->Assign(4, new Val(cnts->rejected*rate, TYPE_COUNT));
  r->Assign(5, new Val(cnts->reply*rate, TYPE_COUNT));
  r->Assign(6, new Val(cnts->non_dns_request*rate, TYPE_COUNT));

  r->Assign(7, new Val(cnts->ANY_RD*rate, TYPE_COUNT));
  r->Assign(8, new Val(cnts->ANY*rate, TYPE_COUNT));
  r->Assign(9, new Val(cnts->A*rate, TYPE_COUNT));
  r->Assign(10, new Val(cnts->AAAA*rate, TYPE_COUNT));
  r->Assign(11, new Val(cnts->NS*rate, TYPE_COUNT));
  r->Assign(12, new Val(cnts->CNAME*rate, TYPE_COUNT));
  r->Assign(13, new Val(cnts->PTR*rate, TYPE_COUNT));
  r->Assign(14, new Val(cnts->SOA*rate, TYPE_COUNT));
  r->Assign(15, new Val(cnts->MX*rate, TYPE_COUNT));
  r->Assign(16, new Val(cnts->TXT*rate, TYPE_COUNT));
  r->Assign(17, new Val(cnts->SRV*rate, TYPE_COUNT));
  r->Assign(18, new Val(cnts->other*rate, TYPE_COUNT));
  r->Assign(19, new Val(cnts->TCP*rate, TYPE_COUNT));
  r->Assign(20, new Val(cnts->UDP*rate, TYPE_COUNT));
  r->Assign(21, new Val(cnts->TSIG*rate, TYPE_COUNT));
  r->Assign(22, new Val(cnts->EDNS*rate, TYPE_COUNT));
  r->Assign(23, new Val(cnts->RD*rate, TYPE_COUNT));
  r->Assign(24, new Val(cnts->DO*rate, TYPE_COUNT));
  r->Assign(25, new Val(cnts->CD*rate, TYPE_COUNT));
  r->Assign(26, new Val(cnts->V4*rate, TYPE_COUNT));
  r->Assign(27, new Val(cnts->V6*rate, TYPE_COUNT));

  r->Assign(28, new Val(cnts->OpQuery*rate, TYPE_COUNT));
  r->Assign(29, new Val(cnts->OpIQuery*rate, TYPE_COUNT));
  r->Assign(30, new Val(cnts->OpStatus*rate, TYPE_COUNT));
  r->Assign(31, new Val(cnts->OpNotify*rate, TYPE_COUNT));
  r->Assign(32, new Val(cnts->OpUpdate*rate, TYPE_COUNT));
  r->Assign(33, new Val(cnts->OpUnassigned*rate, TYPE_COUNT));

  r->Assign(34, new Val(cnts->rcode_noerror*rate, TYPE_COUNT));
  r->Assign(35, new Val(cnts->rcode_format_err*rate, TYPE_COUNT));
  r->Assign(36, new Val(cnts->rcode_server_fail*rate, TYPE_COUNT));
  r->Assign(37, new Val(cnts->rcode_nxdomain*rate, TYPE_COUNT));
  r->Assign(38, new Val(cnts->rcode_not_impl*rate, TYPE_COUNT));
  r->Assign(39, new Val(cnts->rcode_refused*rate, TYPE_COUNT));

  r->Assign(40, new Val(cnts->logged, TYPE_COUNT));

  // Compute average qlen & rlen
  uint qlen = cnts->qlen;
  if (qlen != 0 && cnts->request > 0)
    qlen = qlen / (cnts->request*rate);

  uint rlen = cnts->rlen;
  if (rlen != 0) {
    uint denominator = cnts->reply + cnts->rejected;
    if (denominator > 0 && rlen != 0)
      rlen = rlen / (denominator*rate);
  }

  r->Assign(41, new Val(qlen, TYPE_COUNT));
  r->Assign(42, new Val(rlen, TYPE_COUNT));
  r->Assign(43, new Val(cnts->clients*rate, TYPE_COUNT));
  r->Assign(44, new Val(cnts->zones, TYPE_COUNT));
  r->Assign(45, new Val(cnts->qlen/1048576.0, TYPE_DOUBLE));
  r->Assign(46, new Val(cnts->rlen/1048576.0, TYPE_DOUBLE));

  // TOTAL in/out MB/s
  r->Assign(47, new Val((cnts->qlen+cnts->rlen)*rate/1048576.0, TYPE_DOUBLE));

  // Sampling Rate
  r->Assign(48, new Val(1.0/rate, TYPE_DOUBLE));

  // T2OP (Time 2 Outbound Packet - aka Response as observed at the server)
#define T2R_READY
#ifdef T2R_READY
  r->Assign(49, new Val(cnts->T2R_min, TYPE_COUNT));
  r->Assign(50, new Val(cnts->T2R_max, TYPE_COUNT));
  uint avg = (cnts->T2R_avg != 0 && cnts->request != 0) ? cnts->T2R_avg / cnts->request : 0;
  r->Assign(51, new Val(avg, TYPE_COUNT));

  r->Assign(52, new Val(cnts->NX_T2R_min, TYPE_COUNT));
  r->Assign(53, new Val(cnts->NX_T2R_max, TYPE_COUNT));
  avg = (cnts->NX_T2R_avg != 0 && cnts->request != 0) ? cnts->NX_T2R_avg / cnts->request : 0;
  r->Assign(54, new Val(avg, TYPE_COUNT));

  r->Assign(55, new Val(cnts->A_T2R_min, TYPE_COUNT));
  r->Assign(56, new Val(cnts->A_T2R_max, TYPE_COUNT));
  avg = (cnts->A_T2R_avg != 0 && cnts->request != 0) ? cnts->A_T2R_avg / cnts->request : 0;
  r->Assign(57, new Val(avg, TYPE_COUNT));

  r->Assign(58, new Val(cnts->ANY_T2R_min, TYPE_COUNT));
  r->Assign(59, new Val(cnts->ANY_T2R_max, TYPE_COUNT));
  avg = (cnts->ANY_T2R_avg != 0 && cnts->request != 0) ? cnts->ANY_T2R_avg / cnts->request : 0;
  r->Assign(60, new Val(avg, TYPE_COUNT));

  r->Assign(61, new Val(cnts->CNAME_T2R_min, TYPE_COUNT));
  r->Assign(62, new Val(cnts->CNAME_T2R_max, TYPE_COUNT));
  avg = (cnts->CNAME_T2R_avg != 0 && cnts->request != 0) ? cnts->CNAME_T2R_avg / cnts->request : 0;
  r->Assign(63, new Val(avg, TYPE_COUNT));

  r->Assign(64, new Val(cnts->PTR_T2R_min, TYPE_COUNT));
  r->Assign(65, new Val(cnts->PTR_T2R_max, TYPE_COUNT));
  avg = (cnts->PTR_T2R_avg != 0 && cnts->request != 0) ? cnts->PTR_T2R_avg / cnts->request : 0;
  r->Assign(66, new Val(avg, TYPE_COUNT));

#else
  r->Assign(49, new Val(0, TYPE_COUNT));
  r->Assign(50, new Val(0, TYPE_COUNT));
  r->Assign(51, new Val(0, TYPE_COUNT));

  r->Assign(52, new Val(0, TYPE_COUNT));
  r->Assign(53, new Val(cnts->NX_T2R_max, TYPE_COUNT));
  r->Assign(54, new Val(0, TYPE_COUNT));

  r->Assign(55, new Val(0, TYPE_COUNT));
  r->Assign(56, new Val(0, TYPE_COUNT));
  r->Assign(57, new Val(0, TYPE_COUNT));

  r->Assign(58, new Val(0, TYPE_COUNT));
  r->Assign(59, new Val(0, TYPE_COUNT));
  r->Assign(60, new Val(0, TYPE_COUNT));

  r->Assign(61, new Val(0, TYPE_COUNT));
  r->Assign(62, new Val(0, TYPE_COUNT));
  r->Assign(63, new Val(0, TYPE_COUNT));

#endif

  // fprintf(stderr,"reqs=%u reply=%u A=%u clients=%u ", cnts->request, cnts->reply, cnts->A, cnts->clients);

  vl->append(r);
  return vl;
}


static double last_utime = 0, last_stime = 0;
static long last_signals = 0, last_majflt = 0, last_minflt = 0, last_inblock = 0, last_oublock = 0, last_nswap = 0, last_nvcsw = 0, last_nivcsw = 0;
static int last_FD = 0;

void __dns_telemetry_fire_counts(double ts) {
  if ( dns_telemetry_count ) {
    double start = current_time();
    double lag = start - ts;
    val_list* vl = buildCountsRecord(&CNTS, 0, ts, lag, sample_rate, false);
    if (lag > 2) {
      fprintf(stderr, "WARN: Lagging on real-time processing. TODO, send event up to script land\n");
    }

    char pkt[PKT_LEN];
    char tmp[MAX_LINE_LEN];
    pkt[0]=0;

    int self_VIRT = 0, self_RES = 0, self_DATA = 0, self_FD = 0;
    getValues(&self_VIRT, &self_RES, &self_DATA, &self_FD);

    struct rusage self_usage;
    getrusage(RUSAGE_SELF, &self_usage);
    double utime = self_usage.ru_utime.tv_sec + self_usage.ru_utime.tv_usec/1000000.0;
    double stime = self_usage.ru_stime.tv_sec + self_usage.ru_stime.tv_usec/1000000.0;

    // Calc delta since last interval for key per process metrics
    double delta_utime = 100 * (utime - last_utime);
    double delta_stime = 100 * (stime - last_stime);
    double total_time = delta_utime + delta_stime;
    long delta_nsignals = self_usage.ru_nsignals - last_signals;
    long delta_inblock = self_usage.ru_inblock - last_inblock;
    long delta_oublock = self_usage.ru_oublock - last_oublock;
    long delta_nswap = self_usage.ru_nswap - last_nswap;
    long delta_minflt = self_usage.ru_minflt - last_minflt;
    long delta_majflt = self_usage.ru_majflt - last_majflt;
    int delta_fd = self_FD - last_FD;
    long delta_nvcsw = self_usage.ru_nvcsw - last_nvcsw;
    long delta_nivcsw = self_usage.ru_nivcsw - last_nivcsw;

    last_utime = utime;
    last_stime = stime;
    last_signals = self_usage.ru_nsignals;
    last_minflt = self_usage.ru_minflt;
    last_majflt = self_usage.ru_majflt;
    last_inblock = self_usage.ru_inblock;
    last_oublock = self_usage.ru_oublock;
    last_nswap = self_usage.ru_nswap;
    last_FD = self_FD;
    last_nvcsw = self_usage.ru_nvcsw;
    last_nivcsw = self_usage.ru_nivcsw;

#if 0
    fprintf(stderr, "cpu bro CPU%% (tot/usr/sys) %f/%f/%f MEM (VIRT/RES/DATA) %d/%d/%d fd=%d swap=%ld inblock=%ld oublock=%ld minflt=%ld majflt=%ld signals=%ld vcsw=%ld ivcsw=%ld\n\n", 
	    total_time, delta_utime, delta_stime, self_VIRT, self_RES, self_DATA, delta_fd, delta_nswap, delta_inblock, delta_oublock, delta_minflt, delta_majflt, delta_nsignals, delta_nvcsw, delta_nivcsw);
#endif

    statsd_prepare(STATSD_LINK, (char*)"bro_cpu_tot", total_time, "c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);

    statsd_prepare(STATSD_LINK, (char*)"bro_cpu_sys", delta_stime, "c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);

    statsd_prepare(STATSD_LINK, (char*)"bro_cpu_usr", delta_utime, "c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);

    statsd_prepare(STATSD_LINK, (char*)"bro_mem_vrt", self_VIRT, "g", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);

    statsd_prepare(STATSD_LINK, (char*)"bro_mem_res", self_RES, "g", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);

    statsd_prepare(STATSD_LINK, (char*)"bro_mem_dat", self_DATA, "g", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);

    statsd_prepare(STATSD_LINK, (char*)"bro_fd", delta_fd, "c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);

    statsd_prepare(STATSD_LINK, (char*)"bro_nswap", delta_nswap, "c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);

    statsd_prepare(STATSD_LINK, (char*)"bro_minflt", delta_minflt, "c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);

    statsd_prepare(STATSD_LINK, (char*)"bro_majflt", delta_majflt, "c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);

    statsd_prepare(STATSD_LINK, (char*)"bro_inblock", delta_inblock, "c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);

    statsd_prepare(STATSD_LINK, (char*)"bro_oublock", delta_oublock, "c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);

    statsd_prepare(STATSD_LINK, (char*)"bro_signals", delta_nsignals, "c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);

    statsd_prepare(STATSD_LINK, (char*)"bro_signals", delta_nsignals, "c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);

    statsd_prepare(STATSD_LINK, (char*)"bro_vcsw", delta_nvcsw, "c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);

    statsd_prepare(STATSD_LINK, (char*)"bro_ivcsw", delta_nivcsw, "c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);

    statsd_prepare(STATSD_LINK, (char*)"bro_lag", lag, "c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);

    statsd_prepare(STATSD_LINK, (char*)"dns_request", CNTS.request, (char*)"c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);
    statsd_prepare(STATSD_LINK, (char*)"dns_reply", CNTS.reply, (char*)"c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);
    statsd_prepare(STATSD_LINK, (char*)"dns_A", CNTS.A, (char*)"c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);
    statsd_prepare(STATSD_LINK, (char*)"dns_AAAA", CNTS.AAAA, "c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);
    statsd_prepare(STATSD_LINK, (char*)"dns_AAAA", CNTS.AAAA, "c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);
    statsd_prepare(STATSD_LINK, (char*)"dns_TCP", CNTS.TCP, "c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);
    statsd_prepare(STATSD_LINK, (char*)"dns_UDP", CNTS.UDP, "c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);
    statsd_prepare(STATSD_LINK, (char*)"dns_noerror", CNTS.rcode_noerror, "c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);
    statsd_prepare(STATSD_LINK, (char*)"dns_refused", CNTS.rcode_refused, "c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);
    statsd_prepare(STATSD_LINK, (char*)"dns_T2R_min", CNTS.T2R_min, "c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);
    statsd_prepare(STATSD_LINK, (char*)"dns_T2R_max", CNTS.T2R_max, "c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);

    uint avg = (CNTS.T2R_avg != 0 && CNTS.request != 0) ? CNTS.T2R_avg / CNTS.request : 0;
    statsd_prepare(STATSD_LINK, (char*)"dns_T2R_avg", avg, "c", 1.0, tmp, MAX_LINE_LEN, 1);
    strcat(pkt, tmp);
    statsd_send(STATSD_LINK, pkt);

    if (do_details_redis) {

      Word_t delta = EVENT_COUNT - EVENT_TOTAL;
      EVENT_TOTAL = EVENT_COUNT;

      if (delta > 0) {
	// Emit 32K msg at a time
	char buffer[32*1024];
	uint bufi = 0;
	// Dump cached events and publish them
	Word_t cache_count = 0;
	PWord_t PV = NULL;
	
	sprintf(buffer, "PUBLISH %s ", EVENT_CHANNEL);
	bufi = strlen(buffer);
	buffer[bufi] = 0;

	Word_t Index;
	// JLF(PV, EVENT_CACHE, Index);
	// J_1P(PV,    EVENT_CACHE, &(Index), JudyLFirst, "JudyLFirst");
	JError_t J_Error;
	if (((PV) = (PWord_t)JudyLFirst(EVENT_CACHE, &Index, &J_Error)) == PJERR) J_E("JudyLFirst", &J_Error);
	
	while (PV != NULL) {
	  ++cache_count;
	  const char* val = (const char*)*PV;
	  uint len = strlen(val);
	  // fprintf(stderr, "  cached key: %lu val: %s\n", Index, val);
	  if (bufi + len > sizeof(buffer)) {
	    // fprintf(stderr, "%s\n", buffer);
	    redisReply *reply = (redisReply*)redisCommand(REDIS, buffer);
	    freeReplyObject(reply);
	    sprintf(buffer, "PUBLISH %s ", EVENT_CHANNEL);
	    bufi = strlen(buffer);
	    buffer[bufi] = 0;
	  } 

	  // Cache the value
	  if (bufi > 30) {
	    buffer[bufi++] = '|';
	  }
	  memcpy(buffer+bufi, (void*)*PV, len);
	  bufi += len;
	  buffer[bufi] = 0;
	  
	  free((void*)val);
	  // JLN(PV, EVENT_CACHE, Index);   // get next string
	  JError_t J_Error;
	  if (((PV) = (PWord_t)JudyLNext(EVENT_CACHE, &Index, &J_Error)) == PJERR) J_E("JudyLNext", &J_Error);
	}
	
	// Cleanup array
	Word_t index_size;  
	JLFA(index_size, EVENT_CACHE);
	
	// fprintf(stderr, "%s\n", buffer);
	// fprintf(stderr, "The index used %lu bytes of memory, total cache cost: %lu expected=%lu found=%lu total=%lu\n", index_size, (cache_count*MAXKEY)+index_size, delta, cache_count, EVENT_TOTAL);

	redisReply *reply = (redisReply*)redisCommand(REDIS, buffer);
	LAST_SUBSCRIBERS = reply->integer;
	freeReplyObject(reply);

      }

      // Simple heartbeat to keep the channel alive 
      if ((int)start % 30 == 0) {
	char redis_cmd[256];
	sprintf(redis_cmd, "PUBLISH beacon %f,A,%s,%s,%s,SUBSCRIBERS=%d", start,MY_NODE_ID,"127.0.0.0","BRO_PULSE",LAST_SUBSCRIBERS);
	redisReply *reply = (redisReply*)redisCommand(REDIS, redis_cmd);
	LAST_SUBSCRIBERS = reply->integer;
	freeReplyObject(reply);
      }

      if ((int)start % 55 == 0) {
	if (REDIS == NULL || REDIS->err) {
	  redisFree(REDIS);
	  REDIS = NULL;
	}

	struct timeval timeout = { 1, 500000 }; // 1.5 seconds
	REDIS = redisConnectWithTimeout("127.0.0.1", 6379, timeout);
	if (REDIS != NULL && REDIS->err) {
	  fprintf(stderr, "Error renewing REDIS connection: %s\n", REDIS->errstr);
	  redisFree(REDIS);
	} else {
	  // fprintf(stderr, "Renewed REDIS connection\n");
	}
      }

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
	fprintf(stderr, "STATS_LOGGER oid=%d enabled=%d request=%d\n", logger->owner_id, logger->enabled, logger->CNTS.request);
	if (logger->enabled) {
	  // if (logger->CNTS.request > 0) {
	  val_list* vl = buildCountsRecord(&logger->CNTS, logger->owner_id, ts, lag, sample_rate, false);
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
    fprintf(stderr, "TOTALS req=%u rpl=%u log=%u udp=%u tcp=%u v4=%u\n", TOTALS.request, TOTALS.reply, TOTALS.logged, TOTALS.UDP, TOTALS.TCP, TOTALS.V4);
    val_list* vl = buildCountsRecord(&TOTALS, 0, ts, 0, sample_rate, true);
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
      case LOGGER_ZONE_MANY:
	{
	  // Multi Zone
	  sprintf(source_fname, "%s-O-%08d.log", root_fname, logger->owner_id);
	  sprintf(rotate_fname, "%s-O-%08d-%s.log", root_fname, logger->owner_id, timestamp);
	  break;
	}
      case LOGGER_ZONE_ONLY:
	{
	  // Single Zone
	  sprintf(source_fname, "%s-Z-%08d.log", root_fname, logger->zone_id);
	  sprintf(rotate_fname, "%s-Z-%08d-%s.log", root_fname, logger->zone_id, timestamp);
	  break;
	}
      case LOGGER_ZONE_ALL:
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

#ifdef DEBUG_ROTATE_LOGGING
    fprintf(stderr, "Processing logid=%d owner=%d zone=%d rotated=%p file=%p open_logger=%p\n", logger->log_id, logger->owner_id, logger->zone_id, rotated_by, logger->file, open_logger);
#endif

    FILE* newf = 0;

    // Rotate
    if (logger->file != 0) {

      if (rotated_by == NULL) {
	if (logger->buflen != 0) {
#ifdef DEBUG_ROTATE_LOGGING
	  fprintf(stderr, "  Flush pending writes len=%u cnt=%u\n", logger->buflen, logger->bufcnt);
	  logger->file->Write(logger->buffer, logger->buflen);
	  logger->buflen = 0;
	  logger->bufcnt = 0;
#endif
	}
	logger->file->Flush();
	logger->file->Close();
	if (strstr(source_fname, logger->file->Name())) {
#ifdef DEBUG_ROTATE_LOGGING
	  fprintf(stderr, "  Rotating %s => %s logger=%p\n", source_fname, rotate_fname, logger);
#endif
	} else {
	  strcpy(rotate_fname, logger->file->Name());
	  strcpy(source_fname, rotate_fname);
	  char rotate_timestamp[128];
	  sprintf(rotate_timestamp, "-%s.log", timestamp);
	  strcpy(strstr(rotate_fname, ".log"), rotate_timestamp);
#ifdef DEBUG_ROTATE_LOGGING
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
#ifdef DEBUG_ROTATE_LOGGING
	  fprintf(stderr, "  Ignoring %s, already rotated via zoneid=%d file=%p %s\n", source_fname, *rotated_by, logger->file, logger->file->Name());
#endif
	} else {
	  strcpy(rotate_fname, logger->file->Name());
	  char rotate_timestamp[128];
	  sprintf(rotate_timestamp, "-%s.log", timestamp);
	  strcpy(strstr(rotate_fname, ".log"), rotate_timestamp);
#ifdef DEBUG_ROTATE_LOGGING
	  fprintf(stderr, "  ZZ TODO Rotating %s => %s logger=%p\n", logger->file->Name(), rotate_fname, logger);
#endif
	  newf = file_rotate(logger->file->Name(), rotate_fname);
	}
	// Previous rotation will have cleaned this dangling pointer up. Ugly. :-(
	logger->file = 0;
      }

    } else if (logger->log_id == LOGGER_ZONE_ALL) {

      // No open file. Creating empty Common details. 
      // TODO: Consider tracking the number of active zones being common logged. If > 1 then create empty.
      if (!common_rotated) {
#ifdef DEBUG_ROTATE_LOGGING
	fprintf(stderr, "  Creating empty details for %s logid=%d owner=%d zone=%d\n", rotate_fname, logger->log_id, logger->owner_id, logger->zone_id);
#endif
	FILE* f = fopen(rotate_fname, "wb");
	fclose(f);
	common_rotated = true;
#ifdef DEBUG_ROTATE_LOGGING
      } else {
	fprintf(stderr, "  Common already rotated\n");
#endif
      }

    } else if (logger->log_id == LOGGER_ZONE_ONLY) {

      // Single Zone
#ifdef DEBUG_ROTATE_LOGGING
      fprintf(stderr, "  Creating empty details for %s logid=%d owner=%d zone=%d\n", rotate_fname, logger->log_id, logger->owner_id, logger->zone_id);
#endif
      FILE* f = fopen(rotate_fname, "wb");
      fclose(f);
    }
    else if (logger->log_id == LOGGER_ZONE_MANY) {

      // Multi-Zone -- we may have already rotated. No need to create if that's the case.
      if (rotated_by != NULL) {
#ifdef DEBUG_ROTATE_LOGGING
	fprintf(stderr, "  NOT creating empty details for %s, already rotated/created zoneid=%d\n", rotate_fname, *rotated_by);
#endif
      } else {
#ifdef DEBUG_ROTATE_LOGGING
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
#ifdef DEBUG_ROTATE_LOGGING
	  fprintf(stderr, "  Removing open logger info %s\n", source_fname);
#endif
	  DETAIL_LOGGER_OPEN.Remove(open_logger_key);
	}
	delete open_logger_key;
      }
	
      // Only reopen if we're still logging 
      if (!enabled) {
	logger->file = NULL;
#ifdef DEBUG_ROTATE_LOGGING
	fprintf(stderr, "  Not opening logger file, now not logging for %s %d %d\n", logger->fname, logger->owner_id, logger->log_id);
#endif
	unlink(source_fname);
      } else {
	if (logger->log_id == 1 || logger->log_id == 2) {
	  // TODO What if we can't open the file? Permissions, etc...
	  FILE* f = fopen(source_fname, "wb");
	  logger->file = new BroFile(f, source_fname, "wb");
#ifdef DEBUG_ROTATE_LOGGING
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
      ZoneStats* zone_stats;
      int cnt = 0;
      while ((zone_stats = telemetry_zone_stats.NextEntry(zone_k, zone_cookie)))
	{
	  // Do we need to free each entry (not key) as we iterate?
	  RecordVal* r = new RecordVal(dns_telemetry_zone_stats);
	  r->Assign(0, new Val(ts, TYPE_DOUBLE));
	  r->Assign(1, new StringVal(zone_stats->key));
	  r->Assign(2, new Val(zone_stats->zone_id, TYPE_COUNT));
	  r->Assign(3, new Val(zone_stats->owner_id, TYPE_COUNT));
	  r->Assign(4, new Val(zone_stats->cnt, TYPE_COUNT));
	  r->Assign(5, new Val(zone_stats->A, TYPE_COUNT));
	  r->Assign(6, new Val(zone_stats->AAAA, TYPE_COUNT));
	  r->Assign(7, new Val(zone_stats->CNAME, TYPE_COUNT));
	  r->Assign(8, new Val(zone_stats->NS, TYPE_COUNT));
	  r->Assign(9, new Val(zone_stats->SOA, TYPE_COUNT));
	  r->Assign(10, new Val(zone_stats->SRV, TYPE_COUNT));
	  r->Assign(11, new Val(zone_stats->TXT, TYPE_COUNT));
	  r->Assign(12, new Val(zone_stats->MX, TYPE_COUNT));
	  r->Assign(13, new Val(zone_stats->DO, TYPE_COUNT));
	  r->Assign(14, new Val(zone_stats->RD, TYPE_COUNT));
	  r->Assign(15, new Val(zone_stats->other, TYPE_COUNT));
	  r->Assign(16, new Val(zone_stats->NOERROR, TYPE_COUNT));
	  r->Assign(17, new Val(zone_stats->REFUSED, TYPE_COUNT));
	  r->Assign(18, new Val(zone_stats->NXDOMAIN, TYPE_COUNT));
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

