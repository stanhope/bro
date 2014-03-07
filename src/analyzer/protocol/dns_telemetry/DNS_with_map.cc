// See the file "COPYING" in the main distribution directory for copyright.

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
#include "logging/Manager.h"

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
  uint zoneid;
  uint custid;
  bool details;
};

struct ZoneStats {
  char key[128];
  uint zoneid;
  uint custid;
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
  char query[128];
  uint zoneid;
  uint custid;
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

bool do_counts = false;
bool do_totals = false;
bool do_zone_stats = true;
bool do_qname_stats = true;
bool do_anyrd_stats = true;
bool do_client_stats = true;
bool do_details = true;

int  DETAILS_WRITER_ID = 3;
bool DETAILS_WRITE_VIA_EVENTS = false;
char DETAILS_FILE_NAME[256]; // = "/var/log/dyn/qps/details.log";
BroFile* DETAILS_FILE = NULL;

declare(PDict,int);
declare(PDict,QnameStats);
declare(PDict,ZoneStats);
declare(PDict,ZoneInfo);

PDict(int) telemetry_anyrd_counts;
PDict(int) telemetry_client_stats;
PDict(QnameStats) telemetry_qname_stats;
PDict(ZoneStats) telemetry_zone_stats;
PDict(int) telemetry_details_table;

PDict(ZoneInfo) telemetry_zone_info;

uint MAP_TYPE = 0;

std::unordered_map <string,ZoneStats*> zone_stats;
std::unordered_map <string,ZoneStats*>::iterator zone_stats_iter;
std::unordered_map <string,QnameStats*> qname_stats;
std::unordered_map <string,QnameStats*>::iterator qname_stats_iter;
std::unordered_map <string,int> anyrd_stats;
std::unordered_map <string,int>::iterator anyrd_stats_iter;
std::unordered_map <string,int> client_stats;
std::unordered_map <string,int>::iterator client_stats_iter;
std::unordered_map <string,int> details_map;
std::unordered_map <string,int>::iterator details_map_iter;

void set_index_type(uint map_t) {
  MAP_TYPE = map_t;
  switch (MAP_TYPE) 
    {
    case 0:
      fprintf(stderr, "set_index_type: Using BRO Dictionary\n");
      break;
    case 1:
      fprintf(stderr, "set_index_type: Using C++ unordered_map\n");
      break;
    case 2:
      fprintf(stderr, "set_index_type: Using Google dense_hash_map\n");
      /*
      ZoneStats* test = new ZoneStats();
      test->cnt=100;
      const char* key = "foo";
      fprintf(stderr, " size=%lu\n", zone_stats_dense.size());
      fprintf(stderr, " setting key %s cnt=%d\n", key, test->cnt);
      zone_stats_dense[key] = test;
      fprintf(stderr, " size=%lu\n", zone_stats_dense.size());
      fprintf(stderr, " set key, now retrieving\n");
      ZoneStats* val = zone_stats_dense[key];
      fprintf(stderr, " set key\n");
      fprintf(stderr, " Retrieved from skiplist %d\n", val->cnt);
      */
      break;
    }
}

void set_do_details(bool enable, int logid, bool via_events, const char* fname) {
  DETAILS_WRITE_VIA_EVENTS = via_events;
  DETAILS_WRITER_ID = logid;
  strcpy(DETAILS_FILE_NAME, fname);
  do_details = enable;
  fprintf(stderr, "set_do_details enable=%d logid=%d events=%d fname=%s\n", do_details, logid, via_events, DETAILS_FILE_NAME);
}

CurCounts CNTS;
CurCounts TOTALS;

int logQueueSize = 0;
char logQueue[512*1024];

// Used to use logging framework directly with no route BRO eventing framework.

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

	if (do_counts) {

	  if (is_query) {

	    CNTS.qlen += len;
	    TOTALS.qlen += len;

	    if (analyzer->Conn()->ConnTransport() == TRANSPORT_TCP) {
	      ++CNTS.TCP;
	      ++TOTALS.TCP;
	    } else {
	      // Not really true :-(
	      ++CNTS.UDP;
	      ++TOTALS.UDP;
	    }

	    if (analyzer->Conn()->GetOrigFlowLabel() == 0) {
	      ++CNTS.V4;
	      ++TOTALS.V4;
	    } else {
	      ++CNTS.V6;
	      ++TOTALS.V6;
	    }

	    switch (msg.opcode) 
	      {
	      case DNS_OP_QUERY:
		++CNTS.OpQuery;
		++TOTALS.OpQuery;
		break;
	      case DNS_OP_IQUERY:
		++CNTS.OpIQuery;
		++TOTALS.OpIQuery;
		break;
	      case DNS_OP_SERVER_STATUS:
		++CNTS.OpStatus;
		++TOTALS.OpStatus;
		break;
	      case 4:
		++CNTS.OpNotify;
		++TOTALS.OpNotify;
		break;
	      case 5:
		++CNTS.OpUpdate;
		++TOTALS.OpUpdate;
		break;
	      default:
		++CNTS.OpUnassigned;
		++TOTALS.OpUnassigned;
		break;
	      }
	    if (msg.RD) {
	      ++CNTS.RD;
	      ++TOTALS.RD;
	    }
	  } else {
	    CNTS.rlen += len;
	    TOTALS.rlen += len;
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

	data += hdr_len;
	len -= hdr_len;

	if ( ! ParseQuestions(&msg, data, len, msg_start, is_query) )
		{
		EndMessage(&msg);
		return 0;
		}

	if ( ! ParseAnswers(&msg, msg.ancount, DNS_ANSWER,
				data, len, msg_start) )
		{
		EndMessage(&msg);
		return 0;
		}

	analyzer->ProtocolConfirmation();

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
	return 1;
	}

int DNS_Telemetry_Interpreter::EndMessage(DNS_Telemetry_MsgInfo* msg)
	{
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

void __dns_telemetry_details_add_zone(StringVal* zone) {

  details_map[zone->CheckString()] = 1;

  HashKey* zone_hash = new HashKey(zone->CheckString());
  int* zone_idx = telemetry_details_table.Lookup(zone_hash);
  if (!zone_idx) {
    telemetry_details_table.Insert(zone_hash, new int(1));
  }
}

void __dns_telemetry_details_zone_list() {

  IterCookie* c = telemetry_details_table.InitForIteration();
  HashKey* k;
  int* val;
  while ((val = telemetry_details_table.NextEntry(k, c))) {
    fprintf(stderr,"  details_table %s\n", (const char*)k->Key());
  }

}

void __dns_telemetry_zone_info_add(StringVal* name, uint zoneid, uint custid, bool do_details) {

  if (do_details) {
    __dns_telemetry_details_add_zone(name);
  }

  HashKey* zone_hash = new HashKey(name->CheckString());
  ZoneInfo* info = new ZoneInfo();
  strcpy(info->key, name->CheckString());
  info->zoneid = zoneid;
  info->custid = custid;
  info->details = do_details;
  ZoneInfo* old= telemetry_zone_info.Insert(zone_hash, info);
}

void __dns_telemetry_zone_info_list() {

  IterCookie* c = telemetry_zone_info.InitForIteration();
  HashKey* k;
  ZoneInfo* val;
  fprintf(stderr,"---- Zone Info Map len=%d----\n", telemetry_zone_info.Length());
  while ((val = telemetry_zone_info.NextEntry(k, c))) {
    fprintf(stderr," name=%s zoneid=%u custid=%d details=%d\n", val->key, val->zoneid, val->custid, val->details);
  }

}

void __dns_telemetry_fire_counts(double ts) {
  if ( dns_telemetry_count )
    {
      val_list* vl = new val_list;
      RecordVal* r = new RecordVal(dns_telemetry_counts);

      double lag = current_time() - ts;
      if (lag > 2) {
	fprintf(stderr, "WARN: Lagging on real-time processing. TODO, send event up to script land\n");
      }

      r->Assign(0, new Val(ts, TYPE_DOUBLE));
      r->Assign(1, new Val(lag, TYPE_DOUBLE));
      r->Assign(2, new Val(CNTS.request, TYPE_COUNT));
      r->Assign(3, new Val(CNTS.rejected, TYPE_COUNT));
      r->Assign(4, new Val(CNTS.reply, TYPE_COUNT));
      r->Assign(5, new Val(CNTS.non_dns_request, TYPE_COUNT));

      r->Assign(6, new Val(CNTS.ANY_RD, TYPE_COUNT));

      r->Assign(7, new Val(CNTS.ANY, TYPE_COUNT));
      r->Assign(8, new Val(CNTS.A, TYPE_COUNT));
      r->Assign(9, new Val(CNTS.AAAA, TYPE_COUNT));
      r->Assign(10, new Val(CNTS.NS, TYPE_COUNT));
      r->Assign(11, new Val(CNTS.CNAME, TYPE_COUNT));

      r->Assign(12, new Val(CNTS.PTR, TYPE_COUNT));
      r->Assign(13, new Val(CNTS.SOA, TYPE_COUNT));
      r->Assign(14, new Val(CNTS.MX, TYPE_COUNT));
      r->Assign(15, new Val(CNTS.TXT, TYPE_COUNT));
      r->Assign(16, new Val(CNTS.SRV, TYPE_COUNT));
      r->Assign(17, new Val(CNTS.other, TYPE_COUNT));

      r->Assign(18, new Val(CNTS.TCP, TYPE_COUNT));
      r->Assign(19, new Val(CNTS.UDP, TYPE_COUNT));
      r->Assign(20, new Val(CNTS.TSIG, TYPE_COUNT));
      r->Assign(21, new Val(CNTS.EDNS, TYPE_COUNT));
      r->Assign(22, new Val(CNTS.RD, TYPE_COUNT));
      r->Assign(23, new Val(CNTS.DO, TYPE_COUNT));
      r->Assign(24, new Val(CNTS.CD, TYPE_COUNT));
      r->Assign(25, new Val(CNTS.V4, TYPE_COUNT));
      r->Assign(26, new Val(CNTS.V6, TYPE_COUNT));

      r->Assign(27, new Val(CNTS.OpQuery, TYPE_COUNT));
      r->Assign(28, new Val(CNTS.OpIQuery, TYPE_COUNT));
      r->Assign(29, new Val(CNTS.OpStatus, TYPE_COUNT));
      r->Assign(30, new Val(CNTS.OpNotify, TYPE_COUNT));
      r->Assign(31, new Val(CNTS.OpUpdate, TYPE_COUNT));
      r->Assign(32, new Val(CNTS.OpUnassigned, TYPE_COUNT));

      r->Assign(33, new Val(CNTS.rcode_noerror, TYPE_COUNT));
      r->Assign(34, new Val(CNTS.rcode_format_err, TYPE_COUNT));
      r->Assign(35, new Val(CNTS.rcode_server_fail, TYPE_COUNT));
      r->Assign(36, new Val(CNTS.rcode_nxdomain, TYPE_COUNT));
      r->Assign(37, new Val(CNTS.rcode_not_impl, TYPE_COUNT));
      r->Assign(38, new Val(CNTS.rcode_refused, TYPE_COUNT));

      r->Assign(39, new Val(CNTS.logged, TYPE_COUNT));

      uint qlen = CNTS.qlen ? CNTS.qlen / CNTS.request : 0;
      uint rlen = CNTS.rlen ? CNTS.rlen / (CNTS.reply + CNTS.rejected) : 0;

      r->Assign(40, new Val(qlen, TYPE_COUNT));
      r->Assign(41, new Val(rlen, TYPE_COUNT));

      r->Assign(42, new Val(CNTS.clients, TYPE_COUNT));
      r->Assign(43, new Val(CNTS.zones, TYPE_COUNT));
      r->Assign(44, new Val(CNTS.qlen/1048576.0, TYPE_DOUBLE));
      r->Assign(45, new Val(CNTS.rlen/1048576.0, TYPE_DOUBLE));
      r->Assign(46, new Val((CNTS.qlen+CNTS.rlen)/1048576.0, TYPE_DOUBLE));

      vl->append(r);
      mgr.Dispatch(new Event(dns_telemetry_count, vl), true);
    }
  // Clear counters
  memset(&CNTS, 0, sizeof(CurCounts));
}

RecordVal*  __dns_telemetry_get_totals(double ts) {
  RecordVal* r = new RecordVal(dns_telemetry_counts);

  r->Assign(0, new Val(ts, TYPE_DOUBLE));
  r->Assign(1, new Val(0, TYPE_DOUBLE));
  r->Assign(2, new Val(TOTALS.request, TYPE_COUNT));
  r->Assign(3, new Val(TOTALS.rejected, TYPE_COUNT));
  r->Assign(4, new Val(TOTALS.reply, TYPE_COUNT));
  r->Assign(5, new Val(TOTALS.non_dns_request, TYPE_COUNT));

  r->Assign(6, new Val(TOTALS.ANY_RD, TYPE_COUNT));

  r->Assign(7, new Val(TOTALS.ANY, TYPE_COUNT));
  r->Assign(8, new Val(TOTALS.A, TYPE_COUNT));
  r->Assign(9, new Val(TOTALS.AAAA, TYPE_COUNT));
  r->Assign(10, new Val(TOTALS.NS, TYPE_COUNT));
  r->Assign(11, new Val(TOTALS.CNAME, TYPE_COUNT));

  r->Assign(12, new Val(TOTALS.PTR, TYPE_COUNT));
  r->Assign(13, new Val(TOTALS.SOA, TYPE_COUNT));
  r->Assign(14, new Val(TOTALS.MX, TYPE_COUNT));
  r->Assign(15, new Val(TOTALS.TXT, TYPE_COUNT));
  r->Assign(16, new Val(TOTALS.SRV, TYPE_COUNT));
  r->Assign(17, new Val(TOTALS.other, TYPE_COUNT));

  r->Assign(18, new Val(TOTALS.TCP, TYPE_COUNT));
  r->Assign(19, new Val(TOTALS.UDP, TYPE_COUNT));
  r->Assign(20, new Val(TOTALS.TSIG, TYPE_COUNT));
  r->Assign(21, new Val(TOTALS.EDNS, TYPE_COUNT));
  r->Assign(22, new Val(TOTALS.RD, TYPE_COUNT));
  r->Assign(23, new Val(TOTALS.DO, TYPE_COUNT));
  r->Assign(24, new Val(TOTALS.CD, TYPE_COUNT));
  r->Assign(25, new Val(TOTALS.V4, TYPE_COUNT));
  r->Assign(26, new Val(TOTALS.V6, TYPE_COUNT));

  r->Assign(27, new Val(TOTALS.OpQuery, TYPE_COUNT));
  r->Assign(28, new Val(TOTALS.OpIQuery, TYPE_COUNT));
  r->Assign(29, new Val(TOTALS.OpStatus, TYPE_COUNT));
  r->Assign(30, new Val(TOTALS.OpNotify, TYPE_COUNT));
  r->Assign(31, new Val(TOTALS.OpUpdate, TYPE_COUNT));
  r->Assign(32, new Val(TOTALS.OpUnassigned, TYPE_COUNT));

  r->Assign(33, new Val(TOTALS.rcode_noerror, TYPE_COUNT));
  r->Assign(34, new Val(TOTALS.rcode_format_err, TYPE_COUNT));
  r->Assign(35, new Val(TOTALS.rcode_server_fail, TYPE_COUNT));
  r->Assign(36, new Val(TOTALS.rcode_nxdomain, TYPE_COUNT));
  r->Assign(37, new Val(TOTALS.rcode_not_impl, TYPE_COUNT));
  r->Assign(38, new Val(TOTALS.rcode_refused, TYPE_COUNT));
  r->Assign(39, new Val(TOTALS.logged, TYPE_COUNT));

  // THIS ISN'T MEANINGFUL ... Just emitting so that we don't die 
  uint qlen = CNTS.qlen ? CNTS.qlen / CNTS.request : 0;
  uint rlen = CNTS.rlen ? CNTS.rlen / (CNTS.reply + CNTS.rejected) : 0;

  r->Assign(40, new Val(qlen, TYPE_COUNT));
  r->Assign(41, new Val(rlen, TYPE_COUNT));

  r->Assign(42, new Val(TOTALS.clients, TYPE_COUNT));
  r->Assign(43, new Val(TOTALS.zones, TYPE_COUNT));
  // NOT MEANINGFUL ... new total time and to keep track of total rlen/qlen
  r->Assign(44, new Val(TOTALS.qlen/1048576.0, TYPE_DOUBLE));
  r->Assign(45, new Val(TOTALS.rlen/1048576.0, TYPE_DOUBLE));
  r->Assign(46, new Val((TOTALS.qlen+TOTALS.rlen)/1048576.0, TYPE_DOUBLE));

  return r;
}

void __dns_telemetry_fire_totals(double ts) {
  if ( dns_telemetry_totals )
    {
      val_list* vl = new val_list;
      vl->append(__dns_telemetry_get_totals(ts));
      mgr.Dispatch(new Event(dns_telemetry_totals, vl), true);
    } 
}

void __dns_telemetry_fire_anyrd(double ts) {
  if ( dns_telemetry_anyrd_info ) {
    int len = 0;
    if (MAP_TYPE == 1) {
      len = anyrd_stats.size();
    } else if (MAP_TYPE == 0) {
      len = telemetry_anyrd_counts.Length();
      if (len > 0) {
	IterCookie* c = telemetry_anyrd_counts.InitForIteration();
	HashKey* k;
	int* val;
	while ((val = telemetry_anyrd_counts.NextEntry(k, c)))
	  {
	    char* key =  (char*)k->Key();
	    int key_size =  k->Size();
	    char anyrd_key[600]; // @componentry. NOT SAFE. FIX THIS. Making copy because of use of STRTOK which is destructive.
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
      }
    } else {
      fprintf(stderr, "ERROR: ANYRD Unknown MAP type %d\n", MAP_TYPE);
    } 

    if (len == 0) {
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
  if ( dns_telemetry_client_info )
    {
      int len = 0;
      if (MAP_TYPE == 1) {
	len = client_stats.size();
      } else if (MAP_TYPE == 0) {
	len = telemetry_client_stats.Length();
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
	}
	telemetry_client_stats.Clear();
      } else {
	fprintf(stderr, "ERROR: CLIENTS Unknown MAP type %d\n", MAP_TYPE);
      }

      if (len == 0) {
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

void __dns_telemetry_fire_details(double ts, bool terminating) {

  // How we deal with synchronous, manual rotation.
  // Special case for high-perf writing scenarios (> 250K QPS)
  static char buf[256];
  static char rotate_fname[256];
  static char source_fname[256];
  time_t time = (time_t) ts-59;; // ugly. We're getting called @ the 59'th
  strftime(buf, sizeof(buf), "%y-%m-%d_%H.%M.%S.log", localtime(&time));
  sprintf(source_fname, "%s.log", DETAILS_FILE_NAME);
  sprintf(rotate_fname, "%s-%s", DETAILS_FILE_NAME, buf);

  if (DETAILS_FILE != NULL) {
    DETAILS_FILE->Flush();
    DETAILS_FILE->Close();
    rotate_file_to_name(source_fname, rotate_fname, 0);
  } else {
    FILE* f = fopen(rotate_fname, "wb");
    fclose(f);
  }

  if (!terminating) {
    if (DETAILS_FILE) delete DETAILS_FILE;
    DETAILS_FILE = new BroFile(fopen(source_fname, "wb"));
  } else {
    unlink(source_fname);
  }
}

void __dns_telemetry_fire_zones(double ts) {
  if ( dns_telemetry_zone_info ) {
    int len = 0;
    if (MAP_TYPE == 1) {
      len = zone_stats.size();
      if (len > 0) {
	for(zone_stats_iter = zone_stats.begin(); zone_stats_iter != zone_stats.end(); zone_stats_iter++) {
	  fprintf(stderr,"  zone_stats %s\n", (const char*)zone_stats_iter->first.c_str());
	  ZoneStats* zv = zone_stats_iter->second;
	  RecordVal* r = new RecordVal(dns_telemetry_zone_stats);
	  r->Assign(0, new Val(ts, TYPE_DOUBLE));
	  r->Assign(1, new StringVal(zv->key));
	  r->Assign(2, new Val(zv->zoneid, TYPE_COUNT));
	  r->Assign(3, new Val(zv->custid, TYPE_COUNT));
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
	zone_stats.clear();
      }
    } else if (MAP_TYPE == 0) {
      int len = telemetry_zone_stats.Length();
      if (len > 0) {
	IterCookie* zone_cookie = telemetry_zone_stats.InitForIteration();
	HashKey* zone_k;
	ZoneStats* zv;
	while ((zv = telemetry_zone_stats.NextEntry(zone_k, zone_cookie)))
	  {
	    // Do we need to free each entry (not key) as we iterate?
	    RecordVal* r = new RecordVal(dns_telemetry_zone_stats);
	    r->Assign(0, new Val(ts, TYPE_DOUBLE));
	    r->Assign(1, new StringVal(zv->key));
	    r->Assign(2, new Val(zv->zoneid, TYPE_COUNT));
	    r->Assign(3, new Val(zv->custid, TYPE_COUNT));
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
      }
    } else {
      fprintf(stderr, "ERROR: ZONES Unknown MAP type %d\n", MAP_TYPE);
    }
 
    if (len == 0) {
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
    if (MAP_TYPE == 1) {
      len = qname_stats.size();
      if (len > 0) {
	for(qname_stats_iter = qname_stats.begin(); qname_stats_iter != qname_stats.end(); qname_stats_iter++) {
	  QnameStats* qname_v = qname_stats_iter->second;
	  RecordVal* r = new RecordVal(dns_telemetry_qname_stats);
	  r->Assign(0, new Val(ts, TYPE_DOUBLE));
	  r->Assign(1, new StringVal(qname_stats_iter->first));
	  r->Assign(2, new Val(qname_v->zoneid, TYPE_COUNT));
	  r->Assign(3, new Val(qname_v->custid, TYPE_COUNT));
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
      }
    } else if (MAP_TYPE == 0) {
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
	    r->Assign(2, new Val(qname_v->zoneid, TYPE_COUNT));
	    r->Assign(3, new Val(qname_v->custid, TYPE_COUNT));
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
    } else {
      fprintf(stderr, "ERROR: QNAME Unknown MAP type %d\n", MAP_TYPE);
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

void ReverseQname(char *string, int length) 
{
  int c;
  char *begin, *end, temp;
 
  begin = string;
  end = string;
 
  for ( c = 0 ; c < ( length - 1 ) ; c++ )
    end++;
 
  for ( c = 0 ; c < length/2 ; c++ ) 
    {        
      temp = *end;
      *end = *begin;
      *begin = temp;
 
      begin++;
      end--;
    }
}

int DNS_Telemetry_Interpreter::ParseQuestion(DNS_Telemetry_MsgInfo* msg,
				const u_char*& data, int& len,
					     const u_char* msg_start, int is_query)
	{
	u_char name[513];
	int name_len = sizeof(name) - 1;

	char key_host [255];
	char key_zone [255];
	char tlz [255];
	u_char* name_end;

	//	if (is_query) 
	  name_end = ExtractName(data, len, name, name_len, msg_start, key_host, key_zone, tlz);
	  
	  //	else 
	  //	  name_end = ExtractName(data, len, name, name_len, msg_start, 0, 0, 0);

	if ( ! name_end )
		return 0;

	if ( len < int(sizeof(short)) * 2 )
		{
		analyzer->Weird("DNS_truncated_quest_too_short");
		return 0;
		}

	EventHandlerPtr dns_event = 0;
	ZoneStats* zv = 0;
	if (do_zone_stats && dns_telemetry_zone_info) {

	  if (MAP_TYPE == 1) {
	    zv = zone_stats[tlz];
	    if (zv == NULL) {
	      fprintf(stderr," creating UMAP zone_stats name=%s tlz=%s zone_key=%s is_query=%d\n", name,tlz,key_zone, is_query);
	      zv = new ZoneStats();
	      zv->cnt = 0;
	      strcpy(zv->key, tlz);
	      zone_stats[tlz] = zv;
	      ++CNTS.zones;
	      ++TOTALS.zones;
	    } else {
	      zv = zone_stats[tlz];
	    }
	    
	  } else if (MAP_TYPE == 0) {
	    HashKey* zone_hash = new HashKey(tlz);
	    // HashKey* zone_hash = new HashKey(0, tlz, 32);
	    zv = telemetry_zone_stats.Lookup(zone_hash);

	    if (!zv) {
	      fprintf(stderr," creating DICT zone_stats name=%s tlz=%s zonekey=%s is_query=%d\n", name,tlz,key_zone, is_query);
	      zv = new ZoneStats();
	      zv->cnt = 0;
	      strcpy(zv->key, tlz);
	      telemetry_zone_stats.Insert(zone_hash, zv);
	      
	      ++CNTS.zones;
	      ++TOTALS.zones;
	    }
	    delete zone_hash;
	  } else {
	    fprintf(stderr, "ERROR: ZONE Unknown MAP type %d\n", MAP_TYPE);
	  }
	  
	}

	QnameStats* qname_stat = 0;
	if (is_query && do_qname_stats && dns_telemetry_qname_info) {
	  char qname_key[513];
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
	      ++TOTALS.zones;
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
		if (do_qname_stats)
		  ++qname_stat->A;
		if (do_zone_stats)
		  ++zv->A;
		break;
	      case TYPE_NS:
		++CNTS.NS;
		++TOTALS.NS;
		if (do_qname_stats)
		  ++qname_stat->NS;
		if (do_zone_stats)
		  ++zv->NS;
		break;
	      case TYPE_CNAME:
		++CNTS.CNAME;
		++TOTALS.CNAME;
		if (do_qname_stats)
		  ++qname_stat->CNAME;
		if (do_zone_stats)
		  ++zv->CNAME;
		break;
	      case TYPE_SOA:
		++CNTS.SOA;
		++TOTALS.SOA;
		if (do_qname_stats)
		  ++qname_stat->SOA;
		if (do_zone_stats)
		  ++zv->SOA;
		break;
	      case TYPE_PTR:
		++CNTS.PTR;
		++TOTALS.PTR;
		if (do_qname_stats)
		  ++qname_stat->PTR;
		if (do_zone_stats)
		  ++zv->PTR;
		break;
	      case TYPE_MX:
		++CNTS.MX;
		++TOTALS.MX;
		if (do_qname_stats)
		  ++qname_stat->MX;
		if (do_zone_stats)
		  ++zv->MX;
		break;
	      case TYPE_TXT:
		++CNTS.TXT;
		++TOTALS.TXT;
		if (do_qname_stats)
		  ++qname_stat->TXT;
		if (do_zone_stats)
		  ++zv->TXT;
		break;
	      case TYPE_AAAA:
		++CNTS.AAAA;
		++TOTALS.AAAA;
		if (do_qname_stats)
		  ++qname_stat->AAAA;
		if (do_zone_stats)
		  ++zv->AAAA;
		break;
	      case TYPE_SRV:
		++CNTS.SRV;
		++TOTALS.SRV;
		if (do_qname_stats)
		  ++qname_stat->SRV;
		if (do_zone_stats)
		  ++zv->SRV;
		break;
	      case TYPE_ALL:
		++CNTS.ANY;
		++TOTALS.ANY;
		if (do_qname_stats)
		  ++qname_stat->other;
		if (do_zone_stats)
		  ++zv->other;
		if (msg->RD) {
		  ++CNTS.ANY_RD;
		  ++TOTALS.ANY_RD;

		  if (do_anyrd_stats) {
		    char anyrd_key[560];
		    sprintf(anyrd_key, "%s|%s", sAddr.c_str(), name);
		    HashKey* anyrd_hash = new HashKey(anyrd_key);
		    //		    fprintf(stderr, "ANYRD key=%s len=%u hash_key=%s key_size=%d\n", anyrd_key, (unsigned int)strlen(anyrd_key), (const char*)anyrd_hash->Key(), anyrd_hash->Size());
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
		if (do_qname_stats)
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
		}
		if (do_zone_stats)
		  ++zv->REFUSED;
	}
	else {
	  dns_event = dns_telemetry_query_reply;

	  if (do_details && dns_telemetry_detail_info) {

	    bool do_zone_details = false;
	    if (MAP_TYPE == 1) {
	      do_zone_details = details_map[tlz];
	    } else if (MAP_TYPE == 0) {
	      HashKey* zone_hash = new HashKey(tlz);
	      do_zone_details = telemetry_details_table.Lookup(zone_hash);
	      delete zone_hash;
	    } else {
	      fprintf(stderr, "ERROR: DETAILS Unknown MAP type %d\n", MAP_TYPE);
	    }

	    if (do_zone_details) {


	      ++CNTS.logged;
	      ++TOTALS.logged;

	      const IPAddr& orig_addr = analyzer->Conn()->OrigAddr();
	      const IPAddr& resp_addr = analyzer->Conn()->RespAddr();

	      char log_line[256];
	      sprintf(log_line, "%f,%s,%u,%u,%d,%s,%s,%u", network_time,(char*)name,msg->qtype,msg->rcode,msg->ttl,"","",msg->opcode);
	      uint len = strlen(log_line);
	      if (DETAILS_WRITE_VIA_EVENTS) {
		if (true || logQueueSize + len > sizeof(logQueue)) {
		  StringVal* logentry = new StringVal(log_line);
		  val_list* vl = new val_list;
		  RecordVal* r = new RecordVal(dns_telemetry_detail);
		  r->Assign(0, logentry);
		  vl->append(r);
		  mgr.Dispatch(new Event(dns_telemetry_detail_info, vl), true);
		  logQueue[0] = 0;
		  logQueueSize = 0;
		}
		memcpy(logQueue+logQueueSize, log_line, len);
		logQueueSize += len;
	      } 
	      else {
		log_line[len++] = '\n';
		log_line[len] = 0;
		if (true || logQueueSize + len > sizeof(logQueue)) {
		  if (DETAILS_FILE == NULL) {
		    static char source_fname[256];
		    sprintf(source_fname, "%s.log", DETAILS_FILE_NAME);
		    DETAILS_FILE = new BroFile(fopen(source_fname, "wb"));
		  }
		  DETAILS_FILE->Write(log_line, len);
		  /*
		    logQueue[0] = 0;
		    logQueueSize = 0;
		  */
		}
		/*
		memcpy(logQueue+logQueueSize, log_line, len);
		logQueueSize += len;
		logQueue[logQueueSize]=0;
		*/
		/*
		EnumType* writerType = new EnumType();
		EnumVal* writerId = new EnumVal(DETAILS_WRITER_ID, writerType);
		StringVal* val = new StringVal(log_line);
		RecordVal* r = new RecordVal(dns_telemetry_detail);
		r->Assign(0, val);
		log_mgr->WriteAt(network_time, writerId->AsEnumVal(), r);
		Unref(r);
		*/
	      }
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
		if (do_zone_stats) {
		  ++zv->NOERROR;
		}
		break;
	      }
	      case DNS_CODE_FORMAT_ERR:
		++CNTS.rcode_format_err;
		++TOTALS.rcode_format_err;
		break;
	      case DNS_CODE_SERVER_FAIL:
		++CNTS.rcode_server_fail;
		++TOTALS.rcode_server_fail;
		break;
	      case DNS_CODE_NAME_ERR:
		++CNTS.rcode_nxdomain;
		++TOTALS.rcode_nxdomain;
		if (do_zone_stats)
		  ++zv->NXDOMAIN;
		break;
	      case DNS_CODE_NOT_IMPL:
		++CNTS.rcode_not_impl;
		++TOTALS.rcode_not_impl;
		break;
	      case DNS_CODE_REFUSED:
		++CNTS.rcode_refused;
		++TOTALS.rcode_refused;
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

	return 1;
	}

int DNS_Telemetry_Interpreter::ParseAnswer(DNS_Telemetry_MsgInfo* msg,
				const u_char*& data, int& len,
				const u_char* msg_start)
	{
	u_char name[513];
	int name_len = sizeof(name) - 1;

	return 1;

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start, 0, 0, 0);
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

	fprintf(stderr, " ttl=%d\n", msg->ttl);

	int rdlength = ExtractShort(data, len);
	if ( rdlength > len )
		{
		analyzer->Weird("DNS_truncated_RR_rdlength_lt_len");
		return 0;
		}


	int status;
	switch ( msg->atype ) {
	  /*
		case TYPE_A:
			status = ParseRR_A(msg, data, len, rdlength);
			break;

		case TYPE_A6:
		case TYPE_AAAA:
			status = ParseRR_AAAA(msg, data, len, rdlength);
			break;

		case TYPE_NS:
		case TYPE_CNAME:
		case TYPE_PTR:
			status = ParseRR_Name(msg, data, len, rdlength, msg_start);
			break;

		case TYPE_SOA:
			status = ParseRR_SOA(msg, data, len, rdlength, msg_start);
			break;

		case TYPE_WKS:
			status = ParseRR_WKS(msg, data, len, rdlength);
			break;

		case TYPE_HINFO:
			status = ParseRR_HINFO(msg, data, len, rdlength);
			break;

		case TYPE_MX:
			status = ParseRR_MX(msg, data, len, rdlength, msg_start);
			break;

		case TYPE_TXT:
			status = ParseRR_TXT(msg, data, len, rdlength, msg_start);
			break;

		case TYPE_NBS:
			status = ParseRR_NBS(msg, data, len, rdlength, msg_start);
			break;

		case TYPE_SRV:
			status = ParseRR_SRV(msg, data, len, rdlength, msg_start);
			break;
	  */
		case TYPE_EDNS:
			status = ParseRR_EDNS(msg, data, len, rdlength, msg_start);
			break;

		case TYPE_TSIG:
			status = ParseRR_TSIG(msg, data, len, rdlength, msg_start);
			break;

		default:
			analyzer->Weird("DNS_RR_unknown_type");
			data += rdlength;
			len -= rdlength;
			status = 1;
			break;
	}

	return status;
	}


u_char* DNS_Telemetry_Interpreter::ExtractName(const u_char*& data, int& len,
					u_char* name, int name_len,
					       const u_char* msg_start, char* key_host, char* key_zone, char* tlz)
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

	if (key_host) {
	  int key_len = 0;
	  int label_start = n;
	  int label_processed = 0;
	  int label_tlz = 0; // Need to calculate this based on # of labels for the suffix (.com, .co.uk, etc)
	  int label_max_idx = label_cnt - 1;

	  key_host[0] = 0;
	  key_zone[0] = 0;
	  tlz[0] = 0;
	  int label_zones = 0;

	  for (int i = label_max_idx; i >= 0; i--) {
	    int label_len = label_idx[i];
	    label_start -= (label_len+1);
	    char label[64];
	    memcpy(label, name_start+label_start, label_len);
	    label[label_len] = 0;

	    // If we've not yet figured out what the TLZ is, do so.
	    if (label_tlz == 0) {
	      if (i == label_max_idx) {
		// TODO: build entire list of single-label suffixes for TLDs
		if (strstr("arpa",label)) {
		  strcpy(key_host, "other");
		  strcpy(key_zone, "other");
		  strcpy(tlz, "other");
		  return name;
		}
		else if (strstr("comnetorginfo",label)) {
		  label_tlz = 2;
		}	
	      } else if (i == label_max_idx-1) {
		fprintf(stderr, "TODO: build and check for two-label suffixes for TLDs qname=%s label_cnt=%d\n", name, label_cnt);
	      } else {
		fprintf(stderr, "TODO: build and check for multi-label suffixes for TLDs qname=%s label_cnt=%d\n", name, label_cnt);
	      }
	    }

	    // Build up the host key. It will contain only the labels (no periods).
	    key_len += label_len;
	    strcat(key_host,label);


	    // Build up the zone key. It will contain only the labels (no periods).
	    if (label_zones < label_tlz) {
	      strcat(key_zone, label);
	      label_zones++;
	    }

	  }

	  // Determine how many chars to strip from the beginning of the qname to leave the remaining TLZ in original order
	  int skip_chars = 0;
	  for (int i = 0; i < label_cnt - label_tlz; i++) {
	    skip_chars += (label_idx[i]+1);
	  }
	  strcpy(tlz, (char*)name_start+skip_chars);
	  // fprintf(stderr, "::ExtractName qname=%s len=%d label_cnt=%d key_host=%s key_zone=%s tlz_labels=%d tlz=%s\n",name_start, n, label_cnt, key_host, key_zone, label_tlz,tlz);
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

		u_char* name_end = ExtractName(recurse_data, recurse_max_len, name, name_len, msg_start, 0, 0, 0);

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

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start, 0, 0, 0);
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

	u_char* mname_end = ExtractName(data, len, mname, mname_len, msg_start, 0, 0, 0);
	if ( ! mname_end )
		return 0;

	u_char rname[513];
	int rname_len = sizeof(rname) - 1;

	u_char* rname_end = ExtractName(data, len, rname, rname_len, msg_start, 0, 0, 0);
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

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start, 0, 0, 0);
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

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start, 0, 0, 0);
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
	u_char* alg_name_end = ExtractName(data, len, alg_name, alg_name_len, msg_start, 0, 0, 0);

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
	  //// 	int name_len = data[0];
	  //// 	char* name = new char[name_len];
	  //// 	memcpy(name, data+1, name_len);

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

	else
		interp->ParseMessage(data, len, 0);
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
