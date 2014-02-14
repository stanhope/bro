##! Base DNS analysis script which tracks and logs DNS queries along with their responses.
##! 
##! Author: Phil Stanhope, @componentry, Jan 2014
##!
##! NOTE: Based on the original DNS script from Bro with some significant changes:
##!
##!	1) COUNTS - Exports a total counts file by RR type and other key attributes per request. 
##!	2) DETAILS - Creates a "dbind like" details for ONLY those zones specified. All other zones are ignored. N result lines for this file.
##!	3) ZONES - Creates a per zone QPS & RRType summary. N results based on total number of zones encountered while processing.
##!	4) HOSTNAMES - Creates a per zone QPS & RRType summary. N results based on total number of zones encountered while processing.
##!	5) CLIENTS - Creates a top 10 callers file.
##!	6) ANY_RD - Creates a top 10 callers file.
##!	7) PCAPS - Creates a tcpdump tracefile per rotation interval. Requires ManualTimer customization to BRO.
##!
##! CONFIG:
##!
##!	/etc/dbind/bro_dbind.cfg
##!	/etc/dbind/bro_zones.cfg
##!
##!     path_log_details
##!     path_log_hostnames
##!     path_log_zones
##!
##!     path_log_clients
##!     path_log_counts
##!     path_log_anyrd
##!
##! TODOS:
##!
##!     1) TSIG (S FLAG) support when building details flags

@load base/utils/queue
@load base/frameworks/logging

##! See https://github.com/anthonykasza/nxes for scripts to create suffixes file
@load ./public_suffixes.bro

module DBIND9;

redef dns_skip_all_addl F;
redef dns_skip_all_auth F;

redef LogAscii::separator ",";
redef LogAscii::unset_field "_";
redef LogAscii::output_to_stdout F;
redef LogAscii::include_meta T;
redef Log::manual_rotation_interval = 1min;
#redef Log::manual_rotation_interval = 15sec;

global do_aggregates=T;
global do_details=F;
global do_zone_counts=F;
global do_anyrd_counts=F;
global do_hostname_counts=F;
global do_client_counts=F;
global do_pcaps=F;
global log_all_zones=F;

const dns_ports = { 53/udp, 53/tcp };
redef likely_server_ports += { likely_server_ports };

type ZoneCounts: record {
     ts: double &log;
     key: string &log;
     total: count &log &default=0;
     ANY: count &log &default=0;
     A: count &log &default=0;
     AAAA: count &log &default=0;
     NS: count &log &default=0;
     SOA: count &log &default=0;
     SRV: count &log &default=0;
     TXT: count &log &default=0;
     MX: count &log &default=0;
     DO: count &log &default=0;
     RD: count &log &default=0;
     other: count &log &default=0;
};

## For tracking information about ANY+RD requests
type ANY_RD_Count: record {
     ts: double &log;
     ip: string &log;
     query: string &log;
     cnt: count &log &default = 0;
};

## For tracking information about ANY+RD requests
type HostCount: record {
     ts: double &log;
     q: string &log;
     cnt: count &log &default=0;
     A: count &log &default=0;
     AAAA: count &log &default=0;
     CNAME: count &log &default=0;
     MX: count &log &default=0;
     SOA: count &log &default=0;
     TXT: count &log &default=0;
     SRV: count &log &default=0;
     NS: count &log &default=0;
     other:count &log &default=0;
};

global zone_counts: table[string] of ZoneCounts;
global any_rd_counts: table[string] of ANY_RD_Count;
global host_counts: table[string] of HostCount;

global time_network_first:double=0;
global time_network_start:double=0;
global time_network_last:double=0;

global next_rotate:double = 0;
global hostname:string = gethostname();
global valid_hostnames:set[addr] = {10.151.43.122, [::1], 172.16.200.69, 127.0.0.1};

type ConfigRecord: record {
    counts: bool;
    details: bool;
    zones: bool;
    anyrd: bool;
    hostnames: bool;
    pcaps: bool;
    clients: bool;
    max_clients: count;
};

type ZoneIdx: record {
    zone:string;
};

type ConfigIdx: record {
    ts: time;
};

global config: table[time] of ConfigRecord = table();
global zones_to_log: set[string];
global current_config_val: ConfigRecord;
global current_config_idx: ConfigIdx;

global last_count_time:double = 0;
global config_loaded:bool = F;
global zones_loaded:bool = F;

global path_log_details = "/var/log/dyn/dns/qps_telemetry/details";
global path_log_zones = "/var/log/dyn/dns/qps_telemetry/zones";
global path_log_hostnames = "/var/log/dyn/dns/qps_telemetry/hostnames";
global path_log_clients = "/var/log/dyn/dns/ops_telemetry/clients";
global path_log_counts = "/var/log/dyn/dns/ops_telemetry/counts";
global path_log_anyrd = "/var/log/dyn/dns/ops_telemetry/anyrd";
global path_log_pcaps = "/var/log/dyn/pcaps/trace";

global path_config_dbind = "/etc/dbind/bro_dbind.cfg";
global path_config_zones = "/etc/dbind/bro_zones.cfg";

export {
	const PTR = 12;  ##< RR TYPE value for a domain name pointer.
	const EDNS = 41; ##< An OPT RR TYPE value described by EDNS.
	const ANY = 255; ##< A QTYPE value describing a request for all records.

	## Mapping of DNS query type codes to human readable string
	## representation.
	const query_types = {
		[1] = "A", [2] = "NS", [3] = "MD", [4] = "MF",
		[5] = "CNAME", [6] = "SOA", [7] = "MB", [8] = "MG",
		[9] = "MR", [10] = "NULL", [11] = "WKS", [PTR] = "PTR",
		[13] = "HINFO", [14] = "MINFO", [15] = "MX", [16] = "TXT",
		[17] = "RP", [18] = "AFSDB", [19] = "X25", [20] = "ISDN",
		[21] = "RT", [22] = "NSAP", [23] = "NSAP-PTR", [24] = "SIG",
		[25] = "KEY", [26] = "PX" , [27] = "GPOS", [28] = "AAAA",
		[29] = "LOC", [30] = "EID", [31] = "NIMLOC", [32] = "NB",
		[33] = "SRV", [34] = "ATMA", [35] = "NAPTR", [36] = "KX",
		[37] = "CERT", [38] = "A6", [39] = "DNAME", [40] = "SINK",
	 	[EDNS] = "EDNS", [42] = "APL", [43] = "DS", [44] = "SINK",
		[45] = "SSHFP", [46] = "RRSIG", [47] = "NSEC", [48] = "DNSKEY",
		[49] = "DHCID", [99] = "SPF", [100] = "DINFO", [101] = "UID",
		[102] = "GID", [103] = "UNSPEC", [249] = "TKEY", [250] = "TSIG",
		[251] = "IXFR", [252] = "AXFR", [253] = "MAILB", [254] = "MAILA",
		[32768] = "TA", [32769] = "DLV",
		[ANY] = "ANY",
	} &default = function(n: count): string { return fmt("query-%d", n); };

	## Errors used for non-TSIG/EDNS types.
	const base_errors = {
		[0] = "NOERROR",        # No Error
				[1] = "FORMERR",        # Format Error
		[2] = "SERVFAIL",       # Server Failure
		[3] = "NXDOMAIN",       # Non-Existent Domain
		[4] = "NOTIMP",         # Not Implemented
		[5] = "REFUSED",        # Query Refused
		[6] = "YXDOMAIN",       # Name Exists when it should not
		[7] = "YXRRSET",        # RR Set Exists when it should not
		[8] = "NXRRSet",        # RR Set that should exist does not
		[9] = "NOTAUTH",        # Server Not Authoritative for zone
		[10] = "NOTZONE",       # Name not contained in zone
		[11] = "unassigned-11", # available for assignment
		[12] = "unassigned-12", # available for assignment
		[13] = "unassigned-13", # available for assignment
		[14] = "unassigned-14", # available for assignment
		[15] = "unassigned-15", # available for assignment
		[16] = "BADVERS",       # for EDNS, collision w/ TSIG
		[17] = "BADKEY",        # Key not recognized
		[18] = "BADTIME",       # Signature out of time window
		[19] = "BADMODE",       # Bad TKEY Mode
		[20] = "BADNAME",       # Duplicate key name
		[21] = "BADALG",        # Algorithm not supported
		[22] = "BADTRUNC",      # draft-ietf-dnsext-tsig-sha-05.txt
		[3842] = "BADSIG",      # 16 <= number collision with EDNS(16);
		                        # this is a translation from TSIG(16)
	} &default = function(n: count): string { return fmt("rcode-%d", n); };

	## This deciphers EDNS Z field values.
	const edns_zfield = {
		[0]     = "NOVALUE",    # regular entry
		[32768] = "DNS_SEC_OK", # accepts DNS Sec RRs
	} &default="?";

	## Possible values of the CLASS field in resource records or QCLASS
	## field in query messages.
	const classes = {
		[1]   = "C_INTERNET",
		[2]   = "C_CSNET",
		[3]   = "C_CHAOS",
		[4]   = "C_HESOD",
		[254] = "C_NONE",
		[255] = "C_ANY",
	} &default = function(n: count): string { return fmt("qclass-%d", n); };


	## The DBIND9 logging stream identifier.
	redef enum Log::ID += { ZONE_COUNTS, DETAILS, HOSTNAMES, COUNTS, ANY_RD_COUNTS, CLIENT_COUNTS };

	## The record type which contains the column fields of the DNS log.
	type Info: record {
		## The earliest time at which a DNS protocol message over the associated connection is observed.
		ts:            time               &log;

		## A unique identifier of the connection over which DNS messages
		## are being transferred.
                uid:           string             &log;
		#uid:           string;

		## The connection's 4-tuple of endpoint addresses/ports.
		id:            conn_id            ;


		## The transport layer protocol of the connection.
		proto:         transport_proto    ;

		## A 16-bit identifier assigned by the program that generated
		## the DNS query.  Also used in responses to match up replies to
		## outstanding queries.
		trans_id:      count              &optional;

		## The domain name that is the subject of the DNS query.
		query:         string             &log &optional;
		## The QCLASS value specifying the class of the query.
		qclass:        count              &optional;

		## A descriptive name for the class of the query.
		qclass_name:   string             &optional;

		## A QTYPE value specifying the type of the query.
		qtype:         count              &optional;

		## A descriptive name for the type of the query.
		qtype_name:    string             &log &optional;

		## The Authoritative Answer bit for response messages specifies
		## that the responding name server is an authority for the
		## domain name in the question section.
		AA:            bool               &default=F;

		## The Truncation bit specifies that the message was truncated.
		TC:            bool               &default=F;

		## The Recursion Desired bit in a request message indicates that
		## the client wants recursive service for this query.
		RD:            bool               &default=F;

		## The Recursion Available bit in a response message indicates
		## that the name server supports recursive queries.
		RA:            bool               &default=F;

		## A reserved field that is currently supposed to be zero in all
		## queries and responses.
		Z:             count              &default=0;

		## The set of resource descriptions in the query answer.
		answers:       vector of string   &optional;

		## The caching intervals of the associated RRs described by the
		## *answers* field.
		TTLs:          vector of interval &optional;

		## This value indicates if this request/response pair is ready
		## to be logged.
		ready:         bool            &default=F;

		## The total number of resource records in a reply message's
		## answer section.
		total_answers: count           &optional;
		## The total number of resource records in a reply message's
		## answer, authority, and additional sections.
		total_replies: count           &optional;

		## V4 flag
		V4: bool &default=T;

		## DBIND style flags (See description at top of this file);
		flags: string &log;

		## The response code value in DNS response messages.
		rcode:         count              &log &optional;

		## A descriptive name for the response code value.
		rcode_name:    string             &optional;


		## EDNS bufsize
		bufsize: count &log &default=0;

		## EDNS
		EDNS: bool &default=F;
		EDNS_Version: count &default=0;

		## DO
		DO: bool &default=F;

 
		## Check Disabled
		CD: bool &default=F;

		## TTL for answer
		TTL: count &log;
		
		## Request Length
		reqlen: count &log &default=0;

		## Response Length
		rsplen: count &log;

		## Responder as string
		resp: string &log;

		hostname: string &log;
		mid: count &log;
		client: string &log;
                tlz: string &default="";
                opcode: count &log;
	};


	## The record type which contains the column fields of the DNS Counts log.
	type Counts: record {

	ts:            time               &log &default=network_time();
	tss:string &default="";
	request: count &log &default=0;
	rejected: count &log &default=0;
	reply: count &log &default=0;
	non_dns_request: count &log &default=0;
	ANY_RD: count &log &default=0;
	ANY: count &log &default=0;
	A: count &log &default=0;
	AAAA: count &log &default=0;
	A6: count &log &default=0;
	NS: count &log &default=0;
	CNAME: count &log &default=0;
	PTR: count &log &default=0;
	SOA: count &log &default=0;
	MX: count &log &default=0;
	TXT: count &log &default=0;
	SRV: count &log &default=0;
	other: count &log &default=0;
	TCP: count &log &default=0;
	UDP: count &log &default=0;
	TSIG: count &log &default=0;
	EDNS: count &log &default=0;
	RD: count &log &default=0;
	DO: count &log &default=0;
	CD: count &log &default=0;
	V4: count &log &default=0;
	V6: count &log &default=0;

        OpQuery: count &log &default=0;
        OpIQuery: count &log &default=0;
        OpStatus: count &log &default=0;
        OpNotify: count &log &default=0;
        OpUpdate: count &log &default=0;
        OpUnassigned: count &log &default=0;

	rcode_NOERROR: count &log &default=0;
	rcode_FORMERROR: count &log &default=0;
	rcode_SERVFAIL: count &log &default=0;
	rcode_NXDOMAIN: count &log &default=0;
	rcode_NOTIMP: count &log &default=0;
	rcode_REFUSED: count &log &default=0;
	rcode_YXDOMAIN: count &log &default=0;
	rcode_YXRRSET: count &log &default=0;
	rcode_NXRRSET: count &log &default=0;
	rcode_NOTAUTH: count &log &default=0;
	rcode_NOTZONE: count &log &default=0;
	rcode_other: count &log &default=0;
	logged: count &log &default=0;
	};

	global CNTS: Counts;

	## An event that can be handled to access the :bro:type:`DBIND9::Info`
	## record as it is sent to the logging framework.
	global log_dns: event(rec: Info);

	## This is called by the specific dns_*_reply events with a "reply"
	## which may not represent the full data available from the resource
	## record, but it's generally considered a summarization of the
	## responses.
	##
	## c: The connection record for which to fill in DNS reply data.
	##
	## msg: The DNS message header information for the response.
	##
	## ans: The general information of a RR response.
	##
	## reply: The specific response information according to RR type/class.
	global do_reply: event(c: connection, msg: dns_msg, ans: dns_answer, reply: string);

	## A hook that is called whenever a session is being set.
	## This can be used if additional initialization logic needs to happen
	## when creating a new session value.
	##
	## c: The connection involved in the new session.
	## 
	## msg: The DNS message header information.
	##
	## is_query: Indicator for if this is being called for a query or a response.
	global set_session_hook: hook(c: connection, msg: dns_msg, is_query: bool, len: count);

	## A record type which tracks the status of DNS queries for a given
	## :bro:type:`connection`.
	type State: record {
		## Indexed by query id, returns Info record corresponding to
		## query/response which haven't completed yet.
		pending: table[count] of Queue::Queue;

		## This is the list of DNS responses that have completed based
		## on the number of responses declared and the number received.
		## The contents of the set are transaction IDs.
		finished_answers: set[count];
	};

	# fully qualified domain name type
        type fqdn: record {
                # subdomains following a domain, indexed by their left to right order
                subs: table[count] of string &optional;
                # the domain immediately below the tld
                domain: string &optional;
                # the top level domain according to the suffixes table
                tld: string;
        };
}

redef record connection += {
	dns:       Info  &optional;
	dns_state: State &optional;
};

type ClientCount: record {
 ts: double &log &default=0.0;
 ip: addr &log;
 cnt: count &log &default=1;
};

global client_counts_start:count = 0;
global client_counts_idx:table[addr] of count;
global client_counts:vector of ClientCount;
global client_counts_max:count = 10;

function client_count_add(ip:addr) : bool
{
    if (ip in client_counts_idx) {
	++(client_counts[client_counts_idx[ip]]$cnt);
	return T;
    }
    client_counts_idx[ip] = ++client_counts_start;
    client_counts[client_counts_idx[ip]] = ClientCount($ip = ip, $cnt = 1);
    return F;
}

function client_count_sorter(a:ClientCount, b:ClientCount):int {
	 if (a$cnt < b$cnt) return 0;
	 return -1;
}

function tldr(s: string): string
{
        if ( (/\./ !in s) || (s in suffixes) )
                return s;

        return tldr( split1(s, /\./)[2] );
}

function log_zone_counts(ts:double)
{
    if (do_zone_counts) {
	local len:int = length(zone_counts);
	if (length(zone_counts) > 1) {
	    for(key in zone_counts) {
		local info: ZoneCounts;
		info = zone_counts[key];
		info$key = key;
		info$ts = ts;
		Log::write_at(ts, DBIND9::ZONE_COUNTS, info);	
	    }
	} else {
	    local item: ZoneCounts;
	    item$ts = ts;
	    Log::write_at(ts, DBIND9::ZONE_COUNTS, item);	
	}
	clear_table(zone_counts);
    }
}

function qualify_me(s: string): fqdn
{
    local return_me: fqdn;
    local tld: string = tldr(s);
    local subs_domain: string = sub( sub_bytes( s, 0, (|s| - |tld|)) , /\.$/, "");
    local tmp: table[count] of string = split(subs_domain, /\./);

    return_me$tld = tld;
    return_me$domain = tmp[ |tmp| ];
    delete tmp[ |tmp| ];
    return_me$subs = tmp;
    return return_me;
}

## Dump the HOSTNAME counts data
function log_hostname_counts(ts:double) {
    if (do_hostname_counts) {
	if (length(host_counts) >0) {
	    for(host_key in host_counts) {
		local info: HostCount = host_counts[host_key];
		info$ts = ts;
		Log::write_at(ts,DBIND9::HOSTNAMES, info);
	    }
	    clear_table(host_counts);
	} else {
	    local item: HostCount;
	    item$ts = ts;
	    Log::write_at(ts,DBIND9::HOSTNAMES, item);
	}
    }
}

function log_anyrd_counts(ts:double) {
    if (do_anyrd_counts) {
        ## Dump the ANY+RD counts data
	if (length(any_rd_counts) > 0) {
	    for(any_rd_key in any_rd_counts) {
		local info: ANY_RD_Count = any_rd_counts[any_rd_key];
		info$ts = ts;
		Log::write_at(ts, DBIND9::ANY_RD_COUNTS, info);
	    }
	    clear_table(any_rd_counts);
	} else {
	    local item: ANY_RD_Count;
	    item$ts = ts;
	    Log::write_at(ts, DBIND9::ANY_RD_COUNTS, item);
	}
    }
}

function log_client_counts(ts:double) {
  if (do_client_counts) {
    if (length(client_counts) > 0) {
      sort(client_counts, client_count_sorter);
      for (item in client_counts) {
	local info = client_counts[item];
	info$ts = ts;
	Log::write_at(ts, DBIND9::CLIENT_COUNTS, info);
	if (item+1 == client_counts_max)
	  break;
      }
      client_counts_start = 0;
      client_counts = vector();
      client_counts_idx = table();
    } else {
      local empty_item: ClientCount;
      empty_item$ts = ts;
      empty_item$cnt = 0;
      Log::write_at(ts, DBIND9::CLIENT_COUNTS, empty_item);
    }
  }
}

global c_request:count = 0;

## Dump the global counts data
function log_aggregates(ts:double) {
    if (do_aggregates) {
	if (ts == last_count_time) {
	    return;
	}
	last_count_time = ts;
	local ts_time:time = double_to_time(ts);

	CNTS$ts = ts_time;
#	CNTS$tss = strftime("%y%m%d_%H%M%S", ts_time);
	Log::write_at(ts, DBIND9::COUNTS, CNTS);
	print fmt("log %f reqs=%d", ts, CNTS$request);

        ## Clear the counters. Would be better to store them in a record and simply create a new record
 	CNTS$request = 0;
 	CNTS$rejected = 0;
 	CNTS$reply = 0;
 	CNTS$non_dns_request = 0;
 	CNTS$ANY_RD = 0;
 	CNTS$ANY = 0;
 	CNTS$A = 0;
 	CNTS$AAAA = 0;
 	CNTS$A6 = 0;
 	CNTS$NS = 0;
 	CNTS$CNAME = 0;
 	CNTS$PTR = 0;
 	CNTS$SOA = 0;
 	CNTS$MX = 0;
 	CNTS$TXT = 0;
 	CNTS$SRV = 0;
 	CNTS$other = 0;
 	CNTS$EDNS = 0;
 	CNTS$TSIG = 0;
 	CNTS$TCP = 0;
 	CNTS$UDP = 0;
 	CNTS$RD = 0;
 	CNTS$DO = 0;
 	CNTS$CD = 0;
 	CNTS$V4 = 0;
 	CNTS$V6 = 0;

 	CNTS$OpQuery = 0;
 	CNTS$OpIQuery = 0;
 	CNTS$OpStatus = 0;
 	CNTS$OpNotify = 0;
 	CNTS$OpUpdate = 0;
 	CNTS$OpUnassigned = 0;

 	CNTS$rcode_NOERROR = 0;
 	CNTS$rcode_FORMERROR = 0;
 	CNTS$rcode_SERVFAIL = 0;
 	CNTS$rcode_NXDOMAIN = 0;
 	CNTS$rcode_NOTIMP = 0;
 	CNTS$rcode_REFUSED = 0;
 	CNTS$rcode_YXDOMAIN = 0;
 	CNTS$rcode_YXRRSET = 0;
 	CNTS$rcode_NXRRSET = 0;
 	CNTS$rcode_NOTAUTH = 0;
 	CNTS$rcode_NOTZONE = 0;
 	CNTS$rcode_other = 0;
 	CNTS$logged = 0;

    }
}


# Override default timer callback so we can do whatever we need to
# Return false and the timer will not be re-instantiated automatically
function Log::default_manual_timer_callback(info: Log::ManualTimerInfo) : bool
{
    local idle:double = info$start - time_network_last;
    print fmt("timer_callback start=%f t=%f is_expire=%d last=%f next_rotate=%f idle=%f", info$start, info$t, info$is_expire, time_network_last, next_rotate, idle);
    if (info$start >= next_rotate) {
	local ts:double = floor(time_network_last);
	if (idle < info$timer_interval) {
	    log_aggregates(ts);
	    idle -= 1;
	    ts += 1;
	}
	if (do_aggregates) {
	  if (idle >= 1) {
	    local blanks_after:vector of int={};
	    resize_and_clear(blanks_after, double_to_count(idle));
	    for (blank in blanks_after) {
	      local item: Counts;
	      item$ts = double_to_time(ts);
	      item$tss = strftime("%y%m%d_%H%M%S", item$ts);
	      Log::write_at(ts, DBIND9::COUNTS, item);
	      ts += 1;
	    }
	  }
	}
	log_zone_counts(next_rotate-1);
	log_anyrd_counts(next_rotate-1);
	log_hostname_counts(next_rotate-1);
	log_client_counts(next_rotate-1);
	time_network_last = next_rotate;

	if (do_pcaps) {
	    local open_time:time = pkt_dumper_open(path_log_pcaps);
	    local new_name:string = fmt("%s.%s-%06f", path_log_pcaps, open_time, network_time());
	    local rinfo:rotate_info = rotate_file_to_name(path_log_pcaps, new_name, info$is_expire);
	    print fmt("Rotated %s", rinfo);
	}
	next_rotate += info$timer_interval;
    }	
    return T;
}

function init_manual_rotate(ts:time):double { 
    local delta:double = 0;
    if (next_rotate == 0) {
	local now:double = time_to_double(ts);
	local time_now:time = double_to_time(now);
	time_network_first = now;
	time_network_last = now;
	delta = interval_to_double(calc_next_rotate_from(time_now, Log::manual_rotation_interval));
	next_rotate = now+delta;
	Log::install_manual_timer(next_rotate, interval_to_double(Log::manual_rotation_interval));
    }
    return delta;
}

# To track when the system does a rotation
function custom_rotate(info: Log::RotationInfo) : bool
{
    print fmt("rotate_callback next=%f %s", next_rotate, info);
    return T;
}

function my_default_rotation_postprocessor(info:Log::RotationInfo) :bool {
    print "my_default_rotation_postprocessor";
    return T;
}

event config_change(description: Input::TableDescription, tpe: Input::Event, left: ConfigIdx, right: ConfigRecord) {
#    print fmt("tpe=%s %s old=%s new=%s", tpe, left, right, config[left$ts]);
    current_config_val = config[left$ts];
    current_config_idx = left;
    local item:ConfigRecord = config[left$ts];
    if (tpe == Input::EVENT_NEW || tpe == Input::EVENT_CHANGED) {
	do_aggregates = item$counts;
	do_details = item$details;
	do_zone_counts = item$zones;
	do_anyrd_counts = item$anyrd;
	do_hostname_counts = item$hostnames;
	do_pcaps = item$pcaps;
	do_client_counts = item$clients;
	client_counts_max = item$max_clients;
        local cur_trace_file = pkt_dumper_file();
	if (!do_pcaps) {
	    if (cur_trace_file != "") {
		print "Closed existing packet dumper. Decide if we should rotate as well.";
		pkt_dumper_close(path_log_pcaps);
	    }
	} else {
	    if (cur_trace_file == "") {
		pkt_dumper_init(path_log_pcaps);
	    }
	}
    }
}

function CreateLogStream(id: Log::ID, config: Log::Stream, path:string) {
  Log::create_stream(id, config);
  Log::remove_default_filter(id);
  Log::add_filter(id, [$name=path, $path=path, $postprocessor=custom_rotate]);
# If we want only CSV single header line, specify the 'tsv' option
#  Log::add_filter(id, [$name=path, $path=path, $postprocessor=custom_rotate, $config=table(["tsv"] = "T")]);
}

event Input::end_of_data(name: string, source: string)
{
    if (name == path_config_zones) {
	print fmt("%s loaded @ %s", path_config_zones, current_time());
	zones_loaded = T;
	print zones_to_log;
    } else if (name == path_config_dbind) {
	print fmt("%s loaded @ %s [%s]: %s%s", path_config_dbind, current_time(), name, current_config_idx, current_config_val);
	config_loaded = T;
    }
    if (zones_loaded && config_loaded) {
#       CreateLogStream(DBIND9::DETAILS, [$columns=Info], path_log_details);
#       CreateLogStream(DBIND9::ZONE_COUNTS, [$columns=ZoneCounts], path_log_zones);
#       CreateLogStream(DBIND9::HOSTNAMES, [$columns=HostCount], path_log_hostnames);
#       CreateLogStream(DBIND9::CLIENT_COUNTS, [$columns=ClientCount], path_log_clients);
#       CreateLogStream(DBIND9::COUNTS, [$columns=Counts], path_log_counts);
#       CreateLogStream(DBIND9::ANY_RD_COUNTS, [$columns=ANY_RD_Count], path_log_anyrd);
      if (do_details || do_zone_counts || do_hostname_counts || do_client_counts || do_anyrd_counts || do_aggregates)
	Analyzer::register_for_ports(Analyzer::ANALYZER_DNS, dns_ports);
    }
}

event bro_init() &priority=5
{
  if (do_details) CreateLogStream(DBIND9::DETAILS, [$columns=Info], path_log_details);
  if (do_zone_counts) CreateLogStream(DBIND9::ZONE_COUNTS, [$columns=ZoneCounts], path_log_zones);
  if (do_hostname_counts) CreateLogStream(DBIND9::HOSTNAMES, [$columns=HostCount], path_log_hostnames);
  if (do_client_counts) CreateLogStream(DBIND9::CLIENT_COUNTS, [$columns=ClientCount], path_log_clients);
  if (do_aggregates) CreateLogStream(DBIND9::COUNTS, [$columns=Counts], path_log_counts);
  if (do_anyrd_counts) CreateLogStream(DBIND9::ANY_RD_COUNTS, [$columns=ANY_RD_Count], path_log_anyrd);

    if (reading_live_traffic()) {
        pkt_dumper_set(path_log_pcaps);
        local delta:double = init_manual_rotate(current_time());
	print fmt("BRO_INIT clock=%f net=%f reading_live=%d reading_traces=%d tracing=%d rotate_in=%f next_rotate=%f trace=%s", time_to_double(current_time()), time_to_double(network_time()), reading_live_traffic(), reading_traces(), do_pcaps, delta, next_rotate, path_log_pcaps);
	log_all_zones = F;
	Input::add_table([$source=path_config_dbind, $name=path_config_dbind, $idx=ConfigIdx, $val=ConfigRecord, $destination=config, $ev=config_change, $mode=Input::REREAD]);
	Input::add_table([$source=path_config_zones, $name=path_config_zones, $idx=ZoneIdx, $destination=zones_to_log, $mode=Input::REREAD]);
    } else {
      do_pcaps = F;
      log_all_zones = F;
      if (do_details || do_zone_counts || do_hostname_counts || do_client_counts || do_anyrd_counts || do_aggregates)
	Analyzer::register_for_ports(Analyzer::ANALYZER_DNS, dns_ports);
    }
}

event bro_done()
{
    dns_dump_counters();
    dns_dump_totals();
	
    print fmt("bro_done clock=%f net=%f rotate=%f first=%f last=%f len=%d", current_time(), network_time(),next_rotate, time_network_first, time_network_last, length(zone_counts));
}

function new_session(c: connection, trans_id: count): Info
{
    local info: Info;
    info$ts       = network_time();
#	info$uid      = c$uid;
    info$uid      = strftime("%y%m%d_%H%M%S", info$ts);
    info$id       = c$id;
    info$proto    = get_conn_transport_proto(c$id);
    info$trans_id = trans_id;
    
    info$resp = fmt("%s", c$id$resp_h);
    info$client = fmt("%s",c$id$orig_h);
    info$flags = "";

    # This needs to be based on the host that delivered the response -- which might be the same box as the processor.
    info$hostname = hostname;

    if (time_network_start == 0) {
	time_network_start = floor(time_to_double(info$ts))+1;
	time_network_last = time_network_start;
    } else {
	local now:double = floor(time_to_double(info$ts));
	time_network_last = now;
	local delta:double = now - time_network_start+1;	
	if (delta >= 1.0) {
  	    log_aggregates(time_network_start-1);
	    local blanks:vector of int={};
	    resize_and_clear(blanks, double_to_count(delta)-1);
	    local ts:double = floor(time_network_start);
	    for (blank in blanks) {
		local counts: Counts;
		counts$ts = double_to_time(ts);
		counts$tss = strftime("%y%m%d_%H%M%S", counts$ts);
		Log::write_at(ts, DBIND9::COUNTS, counts);
		ts += 1;
	    }
	    time_network_start = now+1;
	}
    }

    if (c$orig$flow_label != 0) {
	info$V4 = F;
++CNTS$V6;
    } else {
++CNTS$V4;
    }
    
    if (do_client_counts) {
	client_count_add(c$id$orig_h);
    }

    return info;
}

function build_dbind_flags_and_log(info: Info) {
    # Build DBIND style flags, see => http://jpmens.net/2011/02/22/bind-querylog-know-your-flags/
    # TODO: S flag (signed response requested)
    if (log_all_zones || info$tlz in zones_to_log) {
++CNTS$logged;
	if (info$RD) 
	    info$flags = "+";
	else 
	    info$flags = "-";
	
	if (info$EDNS) {
	    info$flags += "E";
++CNTS$EDNS;
	}
	if (info$proto == tcp) info$flags += "T";
	if (info$DO) { 
	    info$flags += "D";
++CNTS$DO;
	}
	if (info$CD) info$flags += "C";
	Log::write_at(time_to_double(info$ts), DBIND9::DETAILS, info);
    }
}

hook set_session_hook(c: connection, msg: dns_msg, is_query: bool, len: count) &priority=1
	{

	if ( ! c?$dns_state )
		{
		local state: State;
		c$dns_state = state;
		}

	if ( msg$id !in c$dns_state$pending )
		c$dns_state$pending[msg$id] = Queue::init();
	
	local info: DBIND9::Info;

	# If this is either a query or this is the reply but
	# no Info records are in the queue (we missed the query?)
	# we need to create an Info record and put it in the queue.  
	if ( is_query ||
	     Queue::len(c$dns_state$pending[msg$id]) == 0 )
		{
		info = new_session(c, msg$id);
		info$mid=msg$id;
		Queue::put(c$dns_state$pending[msg$id], info);
		}

	if ( is_query ) {
		# If this is a query, assign the newly created info variable
		# so that the world looks correct to anything else handling
		# this query.
		info$reqlen = len;
		c$dns = info;
	}
	else {
		# Peek at the next item in the queue for this trans_id and 
		# assign it to c$dns since this is a response.
		c$dns = Queue::peek(c$dns_state$pending[msg$id]);
	}

	if ( ! is_query )
	    {
		c$dns$rcode = msg$rcode;
		c$dns$rcode_name = base_errors[msg$rcode];
		c$dns$rsplen = len;

		if (msg$rcode != 0) {
		    if (msg$rcode == 0)
++CNTS$rcode_NOERROR;
		    else if (msg$rcode == 2)
++CNTS$rcode_SERVFAIL;
		    else if (msg$rcode == 3)
++CNTS$rcode_NXDOMAIN;
		    else if (msg$rcode == 4) 
++CNTS$rcode_NOTIMP;
		    else if (msg$rcode == 5) 
++CNTS$rcode_REFUSED;
		    else if (msg$rcode == 6) 
++CNTS$rcode_YXDOMAIN;
		    else if (msg$rcode == 7) 
++CNTS$rcode_YXRRSET;
		    else if (msg$rcode == 8) 
++CNTS$rcode_NXRRSET;
		    else if (msg$rcode == 9) 
++CNTS$rcode_NOTAUTH;
		    else if (msg$rcode == 10) 
++CNTS$rcode_NOTZONE;
		    else
++CNTS$rcode_other;

		    if (do_details) {
			build_dbind_flags_and_log(c$dns);
		    }
# This record is logged and no longer pending.
 		    Queue::get(c$dns_state$pending[c$dns$trans_id]);
 		    delete c$dns;
		} else {
++CNTS$rcode_NOERROR;

		    if ( ! c$dns?$total_answers )
			c$dns$total_answers = msg$num_answers;

		    if ( c$dns?$total_replies &&
			 c$dns$total_replies != msg$num_answers + msg$num_addl + msg$num_auth )
		    {
			event conn_weird("dns_changed_number_of_responses", c,
			                 fmt("The declared number of responses changed from %d to %d",
			                     c$dns$total_replies,
			                     msg$num_answers + msg$num_addl + msg$num_auth));
		    }
		    else
		    {
# Store the total number of responses expected from the first reply.
			c$dns$total_replies = msg$num_answers + msg$num_addl + msg$num_auth;
		    }
		}
	    } else {

    c$dns$opcode = msg$opcode;
    if (msg$opcode == 0) {
++CNTS$OpQuery;
    } else if (msg$opcode == 1) {
++CNTS$OpIQuery;
    } else if (msg$opcode == 2) {
++CNTS$OpStatus;
    } else if (msg$opcode == 4) {
++CNTS$OpNotify;
    } else if (msg$opcode == 5) {
++CNTS$OpUpdate;
    } else {
++CNTS$OpUnassigned;
    }

	    }
	}

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count) &priority=5
	{
	    if (c$id$resp_h !in valid_hostnames) return;
#	    init_manual_rotate(network_time());
	    hook set_session_hook(c, msg, is_orig, len);
	}

event DBIND9::do_reply(c: connection, msg: dns_msg, ans: dns_answer, reply: string) &priority=5
	{
	    if (c$id$resp_h !in valid_hostnames) return;
	if ( ans$answer_type == DNS_ANS )
		{
		if ( ! c?$dns )
			{
#			event conn_weird("dns_unmatched_reply", c, "");
			hook set_session_hook(c, msg, F, 0);
			}
		c$dns$AA    = msg$AA;
		c$dns$RA    = msg$RA;
		c$dns$TTL   = to_count(fmt("%.0f", interval_to_double(ans$TTL)));

		if ( reply != "" )
			{
			if ( ! c$dns?$answers )
				c$dns$answers = vector();
			c$dns$answers[|c$dns$answers|] = reply;

			if ( ! c$dns?$TTLs )
				c$dns$TTLs = vector();
			c$dns$TTLs[|c$dns$TTLs|] = ans$TTL;
			}

		if ( c$dns?$answers && c$dns?$total_answers &&
		     |c$dns$answers| == c$dns$total_answers )
			{
			# Indicate this request/reply pair is ready to be logged.
			c$dns$ready = T;

			    if (do_details) {
				build_dbind_flags_and_log(c$dns);
			    }
                        # This record is logged and no longer pending.
 			Queue::get(c$dns_state$pending[c$dns$trans_id]);
 			delete c$dns;

			}
		}
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=5
	{
	    if (c$id$resp_h !in valid_hostnames) return;

# print fmt("dns_request %s", network_time());
++CNTS$request;
	    c$dns$RD = msg$RD;

	    local any_rd: bool = F;
            if (msg$RD) {
		if (qtype == ANY) {
++CNTS$ANY;
		    any_rd = T;	
		}
	    }

	    if (msg$Z==1) {
		c$dns$CD = T; 
++CNTS$CD;
	    }

	    if (c$dns$proto == tcp) 
	    	    ++CNTS$TCP;
	    else 
	    	    ++CNTS$UDP;


	    local tmp_fqdn: fqdn = qualify_me(query);
	    local tlz: string = fmt("%s.%s", tmp_fqdn$domain, tmp_fqdn$tld);
	    local host_count_item:HostCount;

	    c$dns$TC          = msg$TC;
	    c$dns$qclass      = qclass;
	    c$dns$qclass_name = classes[qclass];
	    c$dns$qtype       = qtype;
	    c$dns$qtype_name  = query_types[qtype];
	    c$dns$Z           = msg$Z;
	    c$dns$tlz         = tlz;

	    if (do_zone_counts) {
		local zone_info: ZoneCounts;
		if (tlz in zone_counts) {
		    zone_info = zone_counts[tlz];
		    ++zone_info$total;
		} else {
		    zone_info$total = 1;
		}
		zone_counts[tlz] = zone_info;
	    }
	    
	    if (do_hostname_counts) {
		if (query in host_counts) {
		    host_count_item = host_counts[query];
		    ++host_count_item$cnt;
		} else {
		    host_count_item$q = query;
		    host_count_item$cnt = 1;
		    host_counts[query] = host_count_item;
		}
	    }

	    if (do_anyrd_counts) {
		if (any_rd) {
		    local client_key:string = fmt("%s", c$id$orig_h);
		    local any_rd_key:string = fmt("%s%s", c$id$orig_h,query);
		    if (any_rd_key in any_rd_counts) {
			local any_rd_info_existing:ANY_RD_Count = any_rd_counts[any_rd_key];
			++any_rd_info_existing$cnt;
		    } else {
			local any_rd_info:ANY_RD_Count;
			any_rd_info$cnt = 1;
			any_rd_info$query = query;
			any_rd_info$ip = client_key;
			any_rd_counts[any_rd_key] = any_rd_info;
		    }
		}
	    }

            ## Count what we found
            if (qtype == 28) {
                ++CNTS$AAAA;
		++zone_info$AAAA;
		if (do_hostname_counts) ++host_count_item$AAAA;
	    } else if (qtype == ANY) {
                ++CNTS$ANY;
		++zone_info$ANY;
		if (do_hostname_counts) ++host_count_item$other;
	    } else if (qtype == 1) {
                ++CNTS$A;
		++zone_info$A;
		if (do_hostname_counts) ++host_count_item$A;
	    } else if (qtype == 15) {
                ++CNTS$MX;
		++zone_info$MX;
		if (do_hostname_counts) ++host_count_item$MX;
	    } else if (qtype == 2) {
                ++CNTS$NS;
		++zone_info$NS;
		if (do_hostname_counts) ++host_count_item$NS;
	    } else if (qtype == 6) {
                ++CNTS$SOA;
		++zone_info$SOA;
		if (do_hostname_counts) ++host_count_item$SOA;
	    } else if (qtype == 16) {
                ++CNTS$TXT;
		++zone_info$TXT;
		if (do_hostname_counts) ++host_count_item$TXT;
	    } else if (qtype == 33) {
                ++CNTS$SRV;
		++zone_info$SRV;
		if (do_hostname_counts) ++host_count_item$SRV;
	    } else if (qtype == 38) {
                ++CNTS$A6;
		++zone_info$other;
		if (do_hostname_counts) ++host_count_item$other;
	    } else if (qtype == 5) {
                ++CNTS$CNAME;
		++zone_info$other;
		if (do_hostname_counts) ++host_count_item$CNAME;
	    } else {
                ++CNTS$other;
		++zone_info$other;
		if (do_hostname_counts) ++host_count_item$other;
            }

            # Decode netbios name queries
            # Note: Ignoring the name type for now.  Not sure if this should be worked into the query/response in some fashion.
	    if ( c$id$resp_p == 137/udp )
		query = decode_netbios_name(query);
	    c$dns$query = query;

 	}

event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    ++CNTS$reply;
}

event dns_EDNS_addl(c: connection, msg: dns_msg, ans: dns_edns_additional)
{
        c$dns$bufsize = ans$payload_size;
	c$dns$EDNS = T;
    if (ans$DO) {
    	c$dns$DO = T;
	c$dns$EDNS_Version = ans$version;
    }
}

event dns_TSIG_addl(c: connection, msg: dns_msg, ans: dns_tsig_additional)
{
    print fmt("Processing dns_TSIG_addl");
    ++CNTS$TSIG;
}

event dns_rejected(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=5
{
    ++CNTS$rejected;
}

# If Bro is expiring state, we should go ahead and log all unlogged
# request/response pairs now.
event connection_state_remove(c: connection) &priority=-5
{
    if ( ! c?$dns_state )
	return;

    for ( trans_id in c$dns_state$pending )
    {
	local infos: vector of Info;
	Queue::get_vector(c$dns_state$pending[trans_id], infos);
	for ( i in infos )
	{
	    local info: Info = infos[i];
	    if (do_details)
		build_dbind_flags_and_log(info);
	}
    }
}

