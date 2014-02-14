// See the file "COPYING" in the main distribution directory for copyright.

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

#include "events.bif.h"

using namespace analyzer::dns_telemetry;

struct CurCounts {
  int request;
  int rejected;
  int reply;
  int non_dns_request;
  int ANY_RD;
  int ANY;
  int A;
  int AAAA;
  int NS;
  int CNAME;
  int PTR;
  int SOA;
  int MX;
  int TXT;
  int SRV;
  int other;
  int TCP;
  int UDP;
  int TSIG;
  int EDNS;
  int RD;
  int DO;
  int CD;
  int V4;
  int V6;
  int OpQuery;
  int OpIQuery;
  int OpStatus;
  int OpNotify;
  int OpUpdate;
  int OpUnassigned;
  int rcode_noerror;
  int rcode_format_err;
  int rcode_server_fail;
  int rcode_nxdomain;
  int rcode_not_impl;
  int rcode_refused;
};

struct TotCounts {
  int request;
  int rejected;
  int reply;
  int non_dns_request;
  int ANY_RD;
  int ANY;
  int A;
  int AAAA;
  int NS;
  int CNAME;
  int PTR;
  int SOA;
  int MX;
  int TXT;
  int SRV;
  int other;
  int TCP;
  int UDP;
  int TSIG;
  int EDNS;
  int RD;
  int DO;
  int CD;
  int V4;
  int V6;
  int OpQuery;
  int OpIQuery;
  int OpStatus;
  int OpNotify;
  int OpUpdate;
  int OpUnassigned;
  int rcode_noerror;
  int rcode_format_err;
  int rcode_server_fail;
  int rcode_nxdomain;
  int rcode_not_impl;
  int rcode_refused;
};

struct AnyRDCounts {
  char ip[20];
  char query[128];
  int cnt;
};

struct QnameStats {
  char query[128];
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

struct ZoneStats {
  char key[128];
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
  int DO;
  int RD;
  int NOERROR;
  int NXDOMAIN;
  int REFUSED;
};

CurCounts TELEMETRY_CNTS;
TotCounts TELEMETRY_TOTALS;

bool t_do_counts = false;
bool t_do_totals = false;
bool t_do_zone_stats = true;
bool t_do_qname_stats = true;
bool t_do_anyrd_stats = true;
bool t_do_client_stats = true;

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

	if (t_do_counts) {

	  if (is_query) {

	    if (analyzer->Conn()->ConnTransport() == TRANSPORT_TCP) {
	      ++TELEMETRY_CNTS.TCP;
	      ++TELEMETRY_TOTALS.TCP;
	    } else {
	      // Not really true :-(
	      ++TELEMETRY_CNTS.UDP;
	      ++TELEMETRY_TOTALS.UDP;
	    }

	    if (analyzer->Conn()->GetOrigFlowLabel() == 0) {
	      ++TELEMETRY_CNTS.V4;
	      ++TELEMETRY_TOTALS.V4;
	    } else {
	      ++TELEMETRY_CNTS.V6;
	      ++TELEMETRY_TOTALS.V6;
	    }

	    switch (msg.opcode) 
	      {
	      case DNS_OP_QUERY:
		++TELEMETRY_CNTS.OpQuery;
		++TELEMETRY_TOTALS.OpQuery;
		break;
	      case DNS_OP_IQUERY:
		++TELEMETRY_CNTS.OpIQuery;
		++TELEMETRY_TOTALS.OpIQuery;
		break;
	      case DNS_OP_SERVER_STATUS:
		++TELEMETRY_CNTS.OpStatus;
		++TELEMETRY_TOTALS.OpStatus;
		break;
	      case 4:
		++TELEMETRY_CNTS.OpNotify;
		++TELEMETRY_TOTALS.OpNotify;
		break;
	      case 5:
		++TELEMETRY_CNTS.OpUpdate;
		++TELEMETRY_TOTALS.OpUpdate;
		break;
	      default:
		++TELEMETRY_CNTS.OpUnassigned;
		++TELEMETRY_TOTALS.OpUnassigned;
		break;
	      }
	    if (msg.RD) {
	      ++TELEMETRY_CNTS.RD;
	      ++TELEMETRY_TOTALS.RD;
	    }
	  }

	}

	if ( dns_t_message )
		{
		val_list* vl = new val_list();
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(is_query, TYPE_BOOL));
		vl->append(msg.BuildHdrVal());
		vl->append(new Val(len, TYPE_COUNT));
		analyzer->ConnectionEvent(dns_t_message, vl);
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

	if ( ! ParseQuestions(&msg, data, len, msg_start) )
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
	  /*
	val_list* vl = new val_list;

	vl->append(analyzer->BuildConnVal());
	vl->append(msg->BuildHdrVal());
	analyzer->ConnectionEvent(dns_end, vl);
	  */
	  return 1;
	}

int DNS_Telemetry_Interpreter::ParseQuestions(DNS_Telemetry_MsgInfo* msg,
				const u_char*& data, int& len,
				const u_char* msg_start)
	{
	int n = msg->qdcount;

	if ( n == 0 )
		{
		// Generate event here because we won't go into ParseQuestion.
		EventHandlerPtr dns_event =
			msg->rcode == DNS_CODE_OK ?
				dns_t_query_reply : dns_t_rejected;
		BroString* question_name = new BroString("<no query>");
		SendReplyOrRejectEvent(msg, dns_event, data, len, question_name);
		return 1;
		}

	while ( n > 0 && ParseQuestion(msg, data, len, msg_start) )
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

double dns_network_log_next = 0.0;
double dns_network_first = 0.0;
double dns_network_last = 0.0;
double dns_log_last = 0.0;
int dns_log_addr = 0;

declare(PDict,int);
PDict(int) telemetry_anyrd_counts;
PDict(int) telemetry_client_stats;

declare(PDict,QnameStats);
PDict(QnameStats) telemetry_qname_stats;

declare(PDict,ZoneStats);
PDict(ZoneStats) telemetry_zone_stats;

void DNS_Telemetry_DumpAnyRDStats() {

  fprintf(stderr,"\n-- ANY+RD STATS %d --\nat,ip,query,cnt\n", telemetry_anyrd_counts.Length());
  IterCookie* c = telemetry_anyrd_counts.InitForIteration();
  HashKey* k;
  int* val;
  while ((val = telemetry_anyrd_counts.NextEntry(k, c)))
    {
      char* key =  (char*)k->Key();
      char seps[] = "|";
      char* ip = strtok(key, seps );
      char* qname = strtok( NULL, seps);
      fprintf(stderr,"%f,%s,%s,%d\n", network_time,ip,qname,*val);
    }
  telemetry_anyrd_counts.Clear();
}

void DNS_Telemetry_DumpClientStats() {

  fprintf(stderr,"\n-- CLIENT STATS %d --\nat,ip,cnt\n", telemetry_client_stats.Length());
  IterCookie* client_c = telemetry_client_stats.InitForIteration();
  HashKey* client_k;
  int* client_v;
  while ((client_v = telemetry_client_stats.NextEntry(client_k, client_c)))
    {
      char* key =  (char*)client_k->Key();
      fprintf(stderr,"%f,%s,%d\n", network_time,key,*client_v);
    }
  telemetry_client_stats.Clear();
}

void DNS_Telemetry_DumpQnameStats() {

  fprintf(stderr,"\n-- QNAME STATS %d --\nts,qname,cnt,A,AAAA,CNAME,MX,SOA,TXT,PTR,SRV,NS,other\n", telemetry_qname_stats.Length());
  IterCookie* qname_cookie = telemetry_qname_stats.InitForIteration();
  HashKey* qname_k;
  QnameStats* qname_v;
  while ((qname_v = telemetry_qname_stats.NextEntry(qname_k, qname_cookie)))
    {
      char* key =  (char*)qname_k->Key();
      fprintf(stderr,"%f,%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n", network_time,key,qname_v->cnt,qname_v->A, qname_v->AAAA, qname_v->CNAME, qname_v->MX, qname_v->SOA, qname_v->TXT,qname_v->PTR,qname_v->SRV,qname_v->NS,qname_v->other);
    }
  // Do we need to free each entry (not key) as we iterate?
  telemetry_qname_stats.Clear();
}

void DNS_Telemetry_DumpZoneStats() {

  fprintf(stderr,"\n-- ZONE STATS %d --\nts,qname,cnt,A,AAAA,CNAME,MX,SOA,TXT,PTR,SRV,NS,other,DO,RD,NOERROR,REFUSED,NXDOMAIN\n", telemetry_zone_stats.Length());
  IterCookie* zone_cookie = telemetry_zone_stats.InitForIteration();
  HashKey* zone_k;
  ZoneStats* zv;
  while ((zv = telemetry_zone_stats.NextEntry(zone_k, zone_cookie)))
    {
      fprintf(stderr,"%f,%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n", network_time,zv->key,zv->cnt,zv->A, zv->AAAA, zv->CNAME, zv->MX, zv->SOA, zv->TXT,zv->PTR,zv->SRV,zv->NS,zv->other,zv->DO,zv->RD,zv->NOERROR,zv->REFUSED,zv->NXDOMAIN);
    }
  // Do we need to free each entry (not key) as we iterate?
  telemetry_zone_stats.Clear();

}


void DNS_Telemetry_DumpTotals() {
	  fprintf(stderr,"\n-- TOTAL COUNTS --\nat,request,rejected,reply,non_dns_request,ANY_RD,ANY,A,AAAA,NS,CNAME,PTR,SOA,MX,TXT,SRV,other,TCP,UDP,TSIG,EDNS,RD,DO,CD,V4,V6,OpQuery,OpIQuery,OpStatus,OpNotify,OpUpdate,OpUnassigned,noerror,formerr,servfail,nxdomain,notimpl,refused\n");
	  fprintf(stderr,"%f,%d,%d,%d,%d,",
		  network_time,TELEMETRY_TOTALS.request, TELEMETRY_TOTALS.rejected, TELEMETRY_TOTALS.reply, TELEMETRY_TOTALS.non_dns_request);
	  fprintf(stderr,"%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,",
		  TELEMETRY_TOTALS.ANY_RD, TELEMETRY_TOTALS.ANY, TELEMETRY_TOTALS.A, TELEMETRY_TOTALS.AAAA, TELEMETRY_TOTALS.NS, TELEMETRY_TOTALS.CNAME, TELEMETRY_TOTALS.PTR, TELEMETRY_TOTALS.SOA, TELEMETRY_TOTALS.MX, TELEMETRY_TOTALS.TXT, TELEMETRY_TOTALS.SRV, TELEMETRY_TOTALS.other);
	  fprintf(stderr,"%d,%d,%d,%d,%d,%d,%d,%d,%d,",
		  TELEMETRY_TOTALS.TCP, TELEMETRY_TOTALS.UDP, TELEMETRY_TOTALS.TSIG, TELEMETRY_TOTALS.EDNS, TELEMETRY_TOTALS.RD, TELEMETRY_TOTALS.DO, TELEMETRY_TOTALS.CD, TELEMETRY_TOTALS.V4, TELEMETRY_TOTALS.V6);
	  fprintf(stderr,"%d,%d,%d,%d,%d,%d,",
		  TELEMETRY_TOTALS.OpQuery, TELEMETRY_TOTALS.OpIQuery, TELEMETRY_TOTALS.OpStatus, TELEMETRY_TOTALS.OpNotify, TELEMETRY_TOTALS.OpUpdate, TELEMETRY_TOTALS.OpUnassigned);
	  fprintf(stderr,"%d,%d,%d,%d,%d,%d\n",
		  TELEMETRY_TOTALS.rcode_noerror, TELEMETRY_TOTALS.rcode_format_err, TELEMETRY_TOTALS.rcode_server_fail, TELEMETRY_TOTALS.rcode_nxdomain, TELEMETRY_TOTALS.rcode_not_impl, TELEMETRY_TOTALS.rcode_refused);
}

void DNS_Telemetry_DumpStats() {
  double now = current_time();
  double since = now - dns_log_last;
	  fprintf(stderr,"%f,%f,%f,%f,%d,%d,%d,%d,",
		  now, since,dns_network_last, dns_network_log_next, TELEMETRY_CNTS.request, TELEMETRY_CNTS.rejected, TELEMETRY_CNTS.reply, TELEMETRY_CNTS.non_dns_request);
	  fprintf(stderr,"%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,",
		  TELEMETRY_CNTS.ANY_RD, TELEMETRY_CNTS.ANY, TELEMETRY_CNTS.A, TELEMETRY_CNTS.AAAA, TELEMETRY_CNTS.NS, TELEMETRY_CNTS.CNAME, TELEMETRY_CNTS.PTR, TELEMETRY_CNTS.SOA, TELEMETRY_CNTS.MX, TELEMETRY_CNTS.TXT, TELEMETRY_CNTS.SRV, TELEMETRY_CNTS.other);
	  fprintf(stderr,"%d,%d,%d,%d,%d,%d,%d,%d,%d,",
		  TELEMETRY_CNTS.TCP, TELEMETRY_CNTS.UDP, TELEMETRY_CNTS.TSIG, TELEMETRY_CNTS.EDNS, TELEMETRY_CNTS.RD, TELEMETRY_CNTS.DO, TELEMETRY_CNTS.CD, TELEMETRY_CNTS.V4, TELEMETRY_CNTS.V6);
	  fprintf(stderr,"%d,%d,%d,%d,%d,%d,",
		  TELEMETRY_CNTS.OpQuery, TELEMETRY_CNTS.OpIQuery, TELEMETRY_CNTS.OpStatus, TELEMETRY_CNTS.OpNotify, TELEMETRY_CNTS.OpUpdate, TELEMETRY_CNTS.OpUnassigned);
	  fprintf(stderr,"%d,%d,%d,%d,%d,%d\n",
		  TELEMETRY_CNTS.rcode_noerror, TELEMETRY_CNTS.rcode_format_err, TELEMETRY_CNTS.rcode_server_fail, TELEMETRY_CNTS.rcode_nxdomain, TELEMETRY_CNTS.rcode_not_impl, TELEMETRY_CNTS.rcode_refused);

	  dns_log_last = now;
	  memset(&TELEMETRY_CNTS, 0, sizeof(CurCounts));
}

int DNS_Telemetry_Interpreter::ParseQuestion(DNS_Telemetry_MsgInfo* msg,
				const u_char*& data, int& len,
				const u_char* msg_start)
	{
	u_char name[513];
	int name_len = sizeof(name) - 1;

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start);
	if ( ! name_end )
		return 0;

	if ( len < int(sizeof(short)) * 2 )
		{
		analyzer->Weird("DNS_truncated_quest_too_short");
		return 0;
		}

	EventHandlerPtr dns_event = 0;

	ZoneStats* zv = 0;

	if (t_do_zone_stats) {
	  char zone_key[513];
	  sprintf(zone_key,"%s", name);
	  if (strstr(zone_key,"funnyboy2.com")) {
	    sprintf(zone_key,"funnyboy2.com");
	  } else if (strstr(zone_key,"funnyboy.com")) {
	    sprintf(zone_key,"funnyboy.com");
	  } else {
	    sprintf(zone_key, "other");
	  }
	  HashKey* zone_hash = new HashKey(zone_key);
	  zv = telemetry_zone_stats.Lookup(zone_hash);
	  if (!zv) {
	    zv = new ZoneStats();
	    zv->cnt = 0;
	    strcpy(zv->key, zone_key);
	    telemetry_zone_stats.Insert(zone_hash, zv);
	  }
	  delete zone_hash;
	}

	QnameStats* qname_stat = 0;
	if (t_do_qname_stats) {
	  char qname_key[513];
	  sprintf(qname_key, "%s", name);
	  HashKey* qname_hash = new HashKey(qname_key);
	  qname_stat = telemetry_qname_stats.Lookup(qname_hash);
	  if (!qname_stat) {
	    qname_stat = new QnameStats();
	    qname_stat->cnt = 0;
	    telemetry_qname_stats.Insert(qname_hash, qname_stat);
	  }
	  delete qname_hash;
	}

	if ( msg->QR == 0 ) {
	  dns_event = dns_t_request;

	  bool dump_log=false;
	  if (dns_network_last == 0) {
	    // fprintf(stderr, "Init network_last terminating=%d\n", terminating);
	    fprintf(stderr,"\n-- COUNTS/sec--\nat,since,from,to,request,rejected,reply,non_dns_request,ANY_RD,ANY,A,AAAA,NS,CNAME,PTR,SOA,MX,TXT,SRV,other,TCP,UDP,TSIG,EDNS,RD,DO,CD,V4,V6,OpQuery,OpIQuery,OpStatus,OpNotify,OpUpdate,OpUnassigned,noerror,formerr,servfail,nxdomain,notimpl,refused\n");
	    dns_network_last = network_time;
	    dns_network_first = network_time;
	    dns_log_last = current_time();
	    if (terminating) 
	      dump_log =true;
	    else
	      dns_network_log_next = dns_network_last + 1.0;
	  }
	  if (network_time > dns_network_log_next || dump_log) {
	    DNS_Telemetry_DumpStats();
	    dns_network_last = dns_network_log_next;
	    dns_network_log_next = dns_network_log_next + 1;
	  }

	  if (t_do_counts) {
	    ++TELEMETRY_CNTS.request;
	    ++TELEMETRY_TOTALS.request;
	  }
	  if (t_do_zone_stats) {
	    ++zv->cnt;
	  }
	  if (t_do_qname_stats) {
	    ++qname_stat->cnt;
	  }

	  const IPAddr& orig_addr = analyzer->Conn()->OrigAddr();
	  string sAddr = orig_addr.AsString();

	  if (t_do_client_stats) {
	    char client_key[50];
	    strcpy(client_key, sAddr.c_str()); 
	    HashKey* client_hash = new HashKey(client_key);
	    int* client_idx = telemetry_client_stats.Lookup(client_hash);
	    if (client_idx) {
	      ++(*client_idx);
	    } else {
	      telemetry_client_stats.Insert(client_hash, new int(1));
	    }
	    delete client_hash;
	  }

	  RR_Type qtype = RR_Type(ExtractShort(data, len));
	  if (t_do_counts) {
	    switch (qtype) 
	      {
	      case TYPE_A:
		++TELEMETRY_CNTS.A;
		++TELEMETRY_TOTALS.A;
		if (t_do_qname_stats)
		  ++qname_stat->A;
		if (t_do_zone_stats)
		  ++zv->A;
		break;
	      case TYPE_NS:
		++TELEMETRY_CNTS.NS;
		++TELEMETRY_TOTALS.NS;
		if (t_do_qname_stats)
		  ++qname_stat->NS;
		if (t_do_zone_stats)
		  ++zv->NS;
		break;
	      case TYPE_CNAME:
		++TELEMETRY_CNTS.CNAME;
		++TELEMETRY_TOTALS.CNAME;
		if (t_do_qname_stats)
		  ++qname_stat->CNAME;
		if (t_do_zone_stats)
		  ++zv->CNAME;
		break;
	      case TYPE_SOA:
		++TELEMETRY_CNTS.SOA;
		++TELEMETRY_TOTALS.SOA;
		if (t_do_qname_stats)
		  ++qname_stat->SOA;
		if (t_do_zone_stats)
		  ++zv->SOA;
		break;
	      case TYPE_PTR:
		++TELEMETRY_CNTS.PTR;
		++TELEMETRY_TOTALS.PTR;
		if (t_do_qname_stats)
		  ++qname_stat->PTR;
		if (t_do_zone_stats)
		  ++zv->PTR;
		break;
	      case TYPE_MX:
		++TELEMETRY_CNTS.MX;
		++TELEMETRY_TOTALS.MX;
		if (t_do_qname_stats)
		  ++qname_stat->MX;
		if (t_do_zone_stats)
		  ++zv->MX;
		break;
	      case TYPE_TXT:
		++TELEMETRY_CNTS.TXT;
		++TELEMETRY_TOTALS.TXT;
		if (t_do_qname_stats)
		  ++qname_stat->TXT;
		if (t_do_zone_stats)
		  ++zv->TXT;
		break;
	      case TYPE_AAAA:
		++TELEMETRY_CNTS.AAAA;
		++TELEMETRY_TOTALS.AAAA;
		if (t_do_qname_stats)
		  ++qname_stat->AAAA;
		if (t_do_zone_stats)
		  ++zv->AAAA;
		break;
	      case TYPE_SRV:
		++TELEMETRY_CNTS.SRV;
		++TELEMETRY_TOTALS.SRV;
		if (t_do_qname_stats)
		  ++qname_stat->SRV;
		if (t_do_zone_stats)
		  ++zv->SRV;
		break;
	      case TYPE_ALL:
		++TELEMETRY_CNTS.ANY;
		++TELEMETRY_TOTALS.ANY;
		if (t_do_qname_stats)
		  ++qname_stat->other;
		if (t_do_zone_stats)
		  ++zv->other;
		if (msg->RD) {
		  ++TELEMETRY_CNTS.ANY_RD;
		  ++TELEMETRY_TOTALS.ANY_RD;

		  if (t_do_anyrd_stats) {
		    char any_rd_key[560];
		    sprintf(any_rd_key, "%s|%s", sAddr.c_str(), name);
		    HashKey* anyrd_hash = new HashKey(any_rd_key);
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
		++TELEMETRY_CNTS.other;
		++TELEMETRY_TOTALS.other;
		if (t_do_qname_stats)
		  ++qname_stat->other;
		if (t_do_zone_stats)
		  ++zv->other;
		break;
	      }
	  }
	}
	else if ( msg->QR == 1 &&
		  msg->ancount == 0 && msg->nscount == 0 && msg->arcount == 0 ) {
		// Service rejected in some fashion, and it won't be reported
		// via a returned RR because there aren't any.
		dns_event = dns_t_rejected;
		if (t_do_counts) {
		  ++TELEMETRY_CNTS.rejected;
		  ++TELEMETRY_CNTS.rcode_refused;
		  ++TELEMETRY_TOTALS.rejected;
		  ++TELEMETRY_TOTALS.rcode_refused;
		}
		if (t_do_zone_stats)
		  ++zv->REFUSED;
	}
	else {
	  dns_event = dns_t_query_reply;
	  if (t_do_counts) {
	    ++TELEMETRY_CNTS.reply;
	    ++TELEMETRY_TOTALS.reply;
	    switch (msg->rcode) 
	      {
	      case DNS_CODE_OK:
		++TELEMETRY_CNTS.rcode_noerror;
		++TELEMETRY_TOTALS.rcode_noerror;
		if (t_do_zone_stats)
		  ++zv->NOERROR;
		break;
	      case DNS_CODE_FORMAT_ERR:
		++TELEMETRY_CNTS.rcode_format_err;
		++TELEMETRY_TOTALS.rcode_format_err;
		break;
	      case DNS_CODE_SERVER_FAIL:
		++TELEMETRY_CNTS.rcode_server_fail;
		++TELEMETRY_TOTALS.rcode_server_fail;
		break;
	      case DNS_CODE_NAME_ERR:
		++TELEMETRY_CNTS.rcode_nxdomain;
		++TELEMETRY_TOTALS.rcode_nxdomain;
		if (t_do_zone_stats)
		  ++zv->NXDOMAIN;
		break;
	      case DNS_CODE_NOT_IMPL:
		++TELEMETRY_CNTS.rcode_not_impl;
		++TELEMETRY_TOTALS.rcode_not_impl;
		break;
	      case DNS_CODE_REFUSED:
		++TELEMETRY_CNTS.rcode_refused;
		++TELEMETRY_TOTALS.rcode_refused;
		if (t_do_zone_stats)
		  ++zv->REFUSED;
		break;
	      }
	  }
	}

	if (msg->RD) {
	  if (t_do_zone_stats)
	    ++zv->RD;
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

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start);
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
					const u_char* msg_start)
	{
	u_char* name_start = name;

	while ( ExtractLabel(data, len, name, name_len, msg_start) )
		;

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

		u_char* name_end = ExtractName(recurse_data, recurse_max_len,
						name, name_len, msg_start);

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

	return 1;
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

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start);
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

	if (t_do_counts) {
	  ++TELEMETRY_CNTS.reply;
	  ++TELEMETRY_TOTALS.reply;
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

	u_char* mname_end = ExtractName(data, len, mname, mname_len, msg_start);
	if ( ! mname_end )
		return 0;

	u_char rname[513];
	int rname_len = sizeof(rname) - 1;

	u_char* rname_end = ExtractName(data, len, rname, rname_len, msg_start);
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

	//// 	if ( dns_SOA_reply && ! msg->skip_event )
	//// 		{
	//// 		val_list* vl = new val_list;
	//// 
	//// 		vl->append(analyzer->BuildConnVal());
	//// 		vl->append(msg->BuildHdrVal());
	//// 		vl->append(msg->BuildAnswerVal());
	//// 
	//// 		RecordVal* r = new RecordVal(dns_soa);
	//// 
	//// 		r->Assign(0, new StringVal(new BroString(mname, mname_end - mname, 1)));
	//// 		r->Assign(1, new StringVal(new BroString(rname, rname_end - rname, 1)));
	//// 		r->Assign(2, new Val(serial, TYPE_COUNT));
	//// 		r->Assign(3, new IntervalVal(double(refresh), Seconds));
	//// 		r->Assign(4, new IntervalVal(double(retry), Seconds));
	//// 		r->Assign(5, new IntervalVal(double(expire), Seconds));
	//// 		r->Assign(6, new IntervalVal(double(minimum), Seconds));
	//// 
	//// 		vl->append(r);
	//// 
	//// 		analyzer->ConnectionEvent(dns_SOA_reply, vl);
	//// 		}

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

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start);
	if ( ! name_end )
		return 0;

	if ( data - data_start != rdlength )
		analyzer->Weird("DNS_RR_length_mismatch");

	//// 	if ( dns_MX_reply && ! msg->skip_event )
	//// 		{
	//// 		val_list* vl = new val_list;
	//// 
	//// 		vl->append(analyzer->BuildConnVal());
	//// 		vl->append(msg->BuildHdrVal());
	//// 		vl->append(msg->BuildAnswerVal());
	//// 		vl->append(new StringVal(new BroString(name, name_end - name, 1)));
	//// 		vl->append(new Val(preference, TYPE_COUNT));
	//// 
	//// 		analyzer->ConnectionEvent(dns_MX_reply, vl);
	//// 		}

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

	u_char* name_end = ExtractName(data, len, name, name_len, msg_start);
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

	if ( dns_t_EDNS_addl && ! msg->skip_event )
		{
		val_list* vl = new val_list;

		vl->append(analyzer->BuildConnVal());
		vl->append(msg->BuildHdrVal());
		vl->append(msg->BuildEDNS_Val());
		analyzer->ConnectionEvent(dns_t_EDNS_addl, vl);
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

	u_char* alg_name_end =
		ExtractName(data, len, alg_name, alg_name_len, msg_start);

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

	analyzer->ConnectionEvent(dns_t_TSIG_addl, vl);

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

	//// 	if ( dns_A_reply && ! msg->skip_event )
	//// 		{
	//// 		val_list* vl = new val_list;
	//// 
	//// 		vl->append(analyzer->BuildConnVal());
	//// 		vl->append(msg->BuildHdrVal());
	//// 		vl->append(msg->BuildAnswerVal());
	//// 		vl->append(new AddrVal(htonl(addr)));
	//// 
	//// 		analyzer->ConnectionEvent(dns_A_reply, vl);
	//// 		}

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

	//// 	EventHandlerPtr event;
	//// 	if ( msg->atype == TYPE_AAAA )
	//// 		event = dns_AAAA_reply;
	//// 	else
	//// 		event = dns_A6_reply;
	//// 	if ( event && ! msg->skip_event )
	//// 		{
	//// 		val_list* vl = new val_list;
	//// 
	//// 		vl->append(analyzer->BuildConnVal());
	//// 		vl->append(msg->BuildHdrVal());
	//// 		vl->append(msg->BuildAnswerVal());
	//// 		vl->append(new AddrVal(addr));
	//// 		analyzer->ConnectionEvent(event, vl);
	//// 		}

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

	//// 	if ( dns_TXT_reply && ! msg->skip_event )
	//// 		{
	//// 		val_list* vl = new val_list;
	//// 
	//// 		vl->append(analyzer->BuildConnVal());
	//// 		vl->append(msg->BuildHdrVal());
	//// 		vl->append(msg->BuildAnswerVal());
	//// 		vl->append(new StringVal(name_len, name));
	//// 
	//// 		analyzer->ConnectionEvent(dns_TXT_reply, vl);
	//// 		}
	//// 	delete [] name;

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

	if (t_do_counts) {
	  if (DO) {
	    ++TELEMETRY_CNTS.DO;
	    ++TELEMETRY_TOTALS.DO;
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

bool dns_did_terminate = false;

Contents_DNS_Telemetry::~Contents_DNS_Telemetry()
	{
	  if (terminating && !dns_did_terminate) {
	    fprintf(stderr,"TERMINATING\n");
	    DNS_Telemetry_DumpStats();
	    dns_did_terminate = true;
	  }
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
	  /*
	  c_request = c_rejected = c_reply = c_non_dns_request = 0;
	  c_ANY_RD = 0;
	  c_ANY = 0;
	  c_A = 0;
	  c_AAAA = 0;
	  c_NS = 0;
	  c_CNAME = 0;
	  c_PTR = 0;
	  c_SOA = 0;
	  c_MX = 0;
	  c_TXT = 0;
	  c_SRV = 0;
	  c_other = 0;

	  c_TCP = 0;
	  c_UDP = 0;
	  c_TSIG = 0;
	  c_EDNS = 0;
	  c_RD = 0;
	  c_DO = 0;
	  c_CD = 0;
	  c_V4 = 0;
	  c_V6 = 0;

	  c_OpQuery = 0;
	  c_OpIQuery = 0;
	  c_OpStatus = 0;
	  c_OpNotify = 0;
	  c_OpUpdate = 0;
	  c_OpUnassigned = 0;

	  c_rcode_noerror = 0;
	  c_rcode_format_err = 0;
	  c_rcode_server_fail = 0;
	  c_rcode_nxdomain = 0;
	  c_rcode_not_impl = 0;
	  c_rcode_refused = 0;
	  */
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
		    if (t_do_counts) {
		      ++TELEMETRY_CNTS.non_dns_request;
		      ++TELEMETRY_TOTALS.non_dns_request;
		    }
		      if (non_dns_t_request )
			{
			val_list* vl = new val_list;
			vl->append(BuildConnVal());
			vl->append(new StringVal(len, (const char*) data));
			ConnectionEvent(non_dns_t_request, vl);
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
