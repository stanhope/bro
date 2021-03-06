##! Base DNS analysis script which tracks and logs DNS queries along with their responses.
##! 
##! Author: Phil Stanhope, @componentry, Feb 2014
##!

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

global do_counts=T;
global do_anyrd=F;
global do_clients=F;
global do_details=T;
global do_details_statsd=F;
global do_details_redis=F;
global do_zones=T;
global do_owners=T;
global do_qnames=F;
global do_pcaps=F;
global do_log_all=F;
global sample_rate:count=1;

const dns_ports = { 53/udp, 53/tcp };
global valid_hostnames:set[addr] = {10.151.43.122, [::1], 172.16.200.69, 127.0.0.1};

global time_network_first:double=0;
global time_network_start:double=0;
global time_network_last:double=0;
global next_rotate:double = 0;

type ConfigRecord: record {
    counts: bool;
    details: bool;
    zones: bool;
    owners: bool;
    anyrd: bool;
    qnames: bool;
    pcaps: bool;
    clients: bool;
    rate: count;
    log_all: bool;
    statsd: bool;
    redis: bool;
};

type ConfigIdx: record {
    ts: time;
};

global config: table[time] of ConfigRecord = table();

global path_log_details = "/var/log/dyn/qps/details";
global path_log_zones = "/var/log/dyn/qps/zones";
global path_log_owners = "/var/log/dyn/qps/owners";
global path_log_qnames = "/var/log/dyn/qps/qnames";
global path_log_clients = "/var/log/dyn/ops/clients";
global path_log_counts = "/var/log/dyn/ops/counts";
global path_log_anyrd = "/var/log/dyn/ops/anyrd";
global path_log_pcaps = "/var/log/dyn/pcaps/trace";
global path_config_dbind = "/etc/dbind/bro_dns_telemetry.cfg";
global path_config_zones = "/etc/dbind/bro_zones.cfg";

redef enum Log::ID += { ZONES, OWNERS, QNAMES, COUNTS, ANYRD, CLIENTS, COUNTS_CUSTOM_1, COUNTS_CUSTOM_2, COUNTS_CUSTOM_3 };

function Log::default_manual_timer_callback(info: Log::ManualTimerInfo) : bool
{
  local idle:double = info$start - time_network_last;
 # print fmt("timer_callback start=%f t=%f is_expire=%d last=%f next_rotate=%f idle=%f", info$start, info$t, info$is_expire, time_network_last, next_rotate, idle);
  local ts:double = info$t;
  local rotating:bool = F;
  if (info$is_expire || info$start >= next_rotate) {
    rotating = T;
  }
  dns_telemetry_fire_counts(ts);
  if (rotating) {
    ts = next_rotate-1;
    dns_telemetry_fire_anyrd(ts);
    dns_telemetry_fire_clients(ts);
    dns_telemetry_fire_zones(ts);
    #dns_telemetry_fire_owners(ts);
    dns_telemetry_fire_qnames(ts);
    dns_telemetry_fire_details(ts, info$is_expire);
    if (do_pcaps) {
      local open_time:time = pkt_dumper_open(path_log_pcaps);
      local new_name:string = fmt("%s.%s-%06f", path_log_pcaps, open_time, network_time());
      local rinfo:rotate_info = rotate_file_to_name(path_log_pcaps, new_name, info$is_expire);
    }
    next_rotate += interval_to_double(Log::manual_rotation_interval);
  }
  if (info$is_expire) 
    dns_telemetry_fire_totals(ts);
  return T;
}

function init_manual_rotate(ts:time):double { 
  local delta_rotate:double = 0;
  local delta_1sec:double = 0;
  if (next_rotate == 0) {
    local now:double = time_to_double(ts);
    local time_now:time = double_to_time(now);
    time_network_first = now;
    time_network_last = now;
    delta_rotate = interval_to_double(calc_next_rotate_from(time_now, Log::manual_rotation_interval));
    local ival:interval = 1sec;
    delta_1sec = interval_to_double(calc_next_rotate_from(time_now, ival));
    next_rotate = now+delta_rotate;
    Log::install_manual_timer(now+delta_1sec, interval_to_double(ival));
    print fmt("%f init.rotate next=%f delta_rotate=%f delta_1sec=%f",current_time(), next_rotate,delta_rotate, delta_1sec);
  }
  return delta_rotate;
}

event config_change(description: Input::TableDescription, tpe: Input::Event, left: ConfigIdx, right: ConfigRecord) {
    local item:ConfigRecord = config[left$ts];
    if (tpe == Input::EVENT_NEW || tpe == Input::EVENT_CHANGED) {
	do_counts = item$counts;
	do_anyrd = item$anyrd;
	do_clients = item$clients;
	do_details = item$details;
	do_details_statsd = item$statsd;
	do_details_redis = item$redis;;
	do_zones = item$zones;
	do_owners = item$owners;
	do_qnames = item$qnames;
	do_pcaps = item$pcaps;
	do_log_all = item$log_all;
	sample_rate = item$rate;
        local cur_trace_file = pkt_dumper_file();
	if (!do_pcaps) {
	    if (cur_trace_file != "") {
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
  Log::add_filter(id, [$name=path, $path=path, $config=table(["tsv"] = "T",["escape"] = "F")]);
}

global first_time_init:bool = T;

event Input::end_of_data(name: string, source: string)
{
    print fmt("%f config loaded details=%d zones=%d owners=%d anyrd=%d clients=%d counts=%d statsd=%d redis=%drate=%0.5f", current_time(), do_details, do_zones, do_owners, do_anyrd, do_clients, do_counts, do_details_statsd, do_details_redis, 1.0/sample_rate);
    dns_telemetry_set_do_details(do_details);
    dns_telemetry_set_do_zones(do_zones);
    dns_telemetry_set_do_owners(do_owners);
    dns_telemetry_set_do_anyrd(do_anyrd);
    dns_telemetry_set_do_qnames(do_qnames);
    dns_telemetry_set_do_clients(do_clients);
    dns_telemetry_set_do_counts(do_counts);
    dns_telemetry_set_do_totals(T);
    dns_telemetry_set_sample_rate(sample_rate);
    dns_telemetry_set_do_log_all(do_log_all);
    dns_telemetry_set_do_details_statsd(do_details_statsd);
    dns_telemetry_set_do_details_redis(do_details_redis);

    if (first_time_init) {
        dns_telemetry_load_anchor_map(path_config_zones, path_log_details);
    }
    
    if (do_details || do_zones || do_qnames || do_clients || do_anyrd || do_counts || do_log_all || do_details_statsd || do_details_redis)
        local delta:double = init_manual_rotate(current_time());
    local now:double = time_to_double(current_time());
    if (first_time_init) {
        first_time_init = F;
        print fmt("%f init.complete reading_live=%d pcaps=%d", now, reading_live_traffic(), do_pcaps);
    	Analyzer::register_for_ports(Analyzer::ANALYZER_DNS_TELEMETRY, dns_ports);
    }
}

event bro_init()
{
    print fmt("%f init.start", time_to_double(current_time()));
    CreateLogStream(DBIND9::COUNTS, [$columns=dns_telemetry_counts], path_log_counts);
    CreateLogStream(DBIND9::CLIENTS, [$columns=dns_telemetry_client_stats], path_log_clients);
    CreateLogStream(DBIND9::ANYRD, [$columns=dns_telemetry_anyrd_stats], path_log_anyrd);
    CreateLogStream(DBIND9::ZONES, [$columns=dns_telemetry_zone_stats], path_log_zones);
    CreateLogStream(DBIND9::OWNERS, [$columns=dns_telemetry_owner_stats], path_log_owners);
    CreateLogStream(DBIND9::QNAMES, [$columns=dns_telemetry_qname_stats], path_log_qnames);

    CreateLogStream(DBIND9::COUNTS_CUSTOM_1, [$columns=dns_telemetry_counts], path_log_counts+"-O-000001");
    CreateLogStream(DBIND9::COUNTS_CUSTOM_2, [$columns=dns_telemetry_counts], path_log_counts+"-O-000002");
    CreateLogStream(DBIND9::COUNTS_CUSTOM_3, [$columns=dns_telemetry_counts], path_log_counts+"-O-000003");

    if (reading_live_traffic()) {
        pkt_dumper_set(path_log_pcaps);
	# Load the config table. Successful loading of this will initiate analyzer and start processing
	Input::add_table([$source=path_config_dbind, $name=path_config_dbind, $idx=ConfigIdx, $val=ConfigRecord, $destination=config, $ev=config_change, $mode=Input::REREAD]);
    } else {
	do_pcaps = F;
    }
}

event bro_done()
{
    print fmt("%f bro_done net=%f rotate=%f first=%f last=%f", current_time(), network_time(),next_rotate, time_network_first, time_network_last);
}

global header_emit:bool = F;

event dns_telemetry_count(info:dns_telemetry_counts) {
    if (!header_emit) {
	print "";
	print "ts network_time lag - request,reply,rejected,logged, tcp,udp,A,AAAA, MBsec,MBin,MBout,MBsec,rate, T2R_min,T2R_max,T2R_avg,A_T2R_min,A_T2R_max,A_T2R_avg,NX_T2R_min,NX_T2R_max,NX_T2R_avg,CNAME_T2R_min,CNAME_T2R_max,CNAME_T2R_avg,ANY_T2R_min,ANY_T2R_max,ANY_T2R_avg,PTR_T2R_min,PTR_T2R_max,PTR_T2R_avg";
	header_emit = T;
    }
    if (info$owner == 0) {
#      print fmt("%s", info);
      print fmt("%f %s %f - %d,%d,%d,%d, T-%d,U-%d,A-%d,AAAA-%d ,%05.2f,%05.2f,%05.2f,%0.2f, %d,%d,%d, %d,%d,%d, %d,%d,%d, %d,%d,%d, %d,%d,%d, %d,%d,%d",info$ts, strftime("%H%M%S", double_to_time(info$ts)), info$lag, info$request,info$reply,info$rejected,info$logged,info$TCP,info$UDP,info$A,info$AAAA,info$MBin,info$MBout,info$MBsec,info$rate,info$T2R_min,info$T2R_max,info$T2R_avg, info$A_T2R_min, info$A_T2R_max, info$A_T2R_avg,info$NX_T2R_min, info$NX_T2R_max, info$NX_T2R_avg,info$CNAME_T2R_min, info$CNAME_T2R_max, info$CNAME_T2R_avg,info$ANY_T2R_min, info$ANY_T2R_max, info$ANY_T2R_avg, info$PTR_T2R_min, info$PTR_T2R_max, info$PTR_T2R_avg);
      Log::write_at(info$ts, DBIND9::COUNTS, info);
    } else if (info$owner == 1) {
#       print fmt("custom_stat %s", info);
      Log::write_at(info$ts, DBIND9::COUNTS_CUSTOM_1, info);
    }
       
}

event dns_telemetry_totals(info:dns_telemetry_counts) {
    print fmt("event.dns_telemetry_totals %s", info);      
}

event dns_telemetry_anyrd_info(info:dns_telemetry_anyrd_stats) {
    Log::write_at(info$ts, DBIND9::ANYRD, info);
}

event dns_telemetry_client_info(info:dns_telemetry_client_stats) {
    Log::write_at(info$ts, DBIND9::CLIENTS, info);
}

event dns_telemetry_zone_info(info:dns_telemetry_zone_stats) {
    Log::write_at(info$ts, DBIND9::ZONES, info);
}

event dns_telemetry_owner_info(info:dns_telemetry_owner_stats) {
    Log::write_at(info$ts, DBIND9::OWNERS, info);
}

event dns_telemetry_qname_info(info:dns_telemetry_qname_stats) {
    Log::write_at(info$ts, DBIND9::QNAMES, info);
}


