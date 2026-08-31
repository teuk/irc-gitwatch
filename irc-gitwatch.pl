#!/usr/bin/env perl
use strict;
use warnings;
use utf8;

use Digest::SHA qw(hmac_sha256_hex sha256_hex);
use Encode qw(encode decode FB_CROAK);
use HTTP::Tiny;
use IO::Select;
use IO::Handle ();
use IO::Socket::INET;
use IO::Socket::SSL qw(SSL_VERIFY_PEER);
use JSON::PP qw(decode_json encode_json);
use MIME::Base64 qw(encode_base64);
use Fcntl qw(O_WRONLY O_CREAT O_EXCL);
use Time::HiRes qw(time sleep alarm);
use Time::Local qw(timegm);

binmode STDOUT, ':encoding(UTF-8)' or die "STDOUT UTF-8: $!";
binmode STDERR, ':encoding(UTF-8)' or die "STDERR UTF-8: $!";
$SIG{PIPE}='IGNORE'; # A proxy/client disconnect must never kill the daemon.

use constant VERSION          => '0.30';
use constant APP_NAME         => 'IRC GitWatch';
use constant API_VERSION      => '2026-03-10';
use constant MAX_IRC_BYTES    => 370;
use constant MAX_PENDING      => 200;
use constant MAX_EVENT_IDS    => 800;
use constant MAX_DELIVERIES   => 1500;
use constant MAX_FINGERPRINTS => 1500;
use constant MAX_RSS_IDS      => 1000;
use constant MAX_TRAFFIC_DAYS => 400;
use constant MAX_ACCOUNT_DAYS => 400;
use constant MAX_CI_RUNS      => 500;
use constant MAX_CI_DAYS      => 30;

# ── Configuration ─────────────────────────────────────────────────────────────
sub env_text { my ($k,$d)=@_; my $v=exists $ENV{$k}?$ENV{$k}:$d; $v//=q{}; $v=~s/^\s+|\s+$//g; $v }
sub env_int  { my ($k,$d,$min,$max)=@_; my $v=env_text($k,$d); $v=$d unless $v=~/^\d+$/; $v=int($v); $v=$min if defined($min)&&$v<$min; $v=$max if defined($max)&&$v>$max; $v }
sub env_bool { my ($k,$d)=@_; lc(env_text($k,$d?'1':'0')) =~ /^(?:0|no|false|off)$/ ? 0 : 1 }

my %CFG=(
 repo              => env_text('GITHUB_REPO','teuk/irc-gitwatch'),
 token             => env_text('GITHUB_TOKEN',''),
 state_file        => env_text('GITHUB_STATE_FILE','/var/lib/irc-gitwatch/state.json'),
 state_backup      => env_bool('STATE_BACKUP_ENABLED',1),
 poll_enabled      => env_bool('GITHUB_POLL_ENABLED',1),
 reconcile         => env_int('GITHUB_RECONCILE_SECONDS',300,60,86400),
 events_max_pages  => env_int('GITHUB_EVENTS_MAX_PAGES',3,1,5),
 http_proxy        => env_text('GITHUB_HTTP_PROXY',''),

 hook_secret       => env_text('GITHUB_WEBHOOK_SECRET',''),
 hook_bind         => env_text('GITHUB_WEBHOOK_BIND','127.0.0.1'),
 hook_port         => env_int('GITHUB_WEBHOOK_PORT',9510,1,65535),
 hook_path         => env_text('GITHUB_WEBHOOK_PATH','/githubhook'),
 hook_root_alias   => env_bool('GITHUB_WEBHOOK_ROOT_ALIAS',1),
 hook_max          => env_int('GITHUB_WEBHOOK_MAX_BODY',2_000_000,1024,25_000_000),

 epiknet_enabled   => env_bool('EPIKNET_ENABLED',0),
 irc_host          => env_text('IRC_HOST','irc.epiknet.org'),
 irc_port          => env_int('IRC_PORT',6697,1,65535),
 irc_channel       => env_text('IRC_CHANNEL','#irc-gitwatch'),
 irc_nick          => env_text('IRC_NICK','gitwatch'),
 irc_user          => env_text('IRC_USER',env_text('IRC_NICK','gitwatch')),
 irc_realname      => env_text('IRC_REALNAME','IRC GitWatch'),
 irc_colors        => env_bool('IRC_COLORS',1),
 startup_announce  => env_bool('IRC_STARTUP_ANNOUNCE',1),
 send_interval     => env_int('IRC_SEND_INTERVAL_MS',800,250,5000)/1000,
 icon_mode         => lc(env_text('IRC_ICON_MODE','compat')),

 rss_enabled       => env_bool('RSS_ENABLED',0),
 rss_url           => env_text('RSS_URL',''),
 rss_interval      => env_int('RSS_POLL_SECONDS',120,60,86400),
 rss_max_items     => env_int('RSS_MAX_ITEMS',50,1,200),

 actions_enabled   => env_bool('GITHUB_ACTIONS_ENABLED',1),
 actions_idle      => env_int('GITHUB_ACTIONS_IDLE_SECONDS',120,60,3600),
 actions_fast      => env_int('GITHUB_ACTIONS_FAST_SECONDS',30,15,600),
 actions_fast_win  => env_int('GITHUB_ACTIONS_FAST_WINDOW_SECONDS',900,120,3600),
 actions_per_page  => env_int('GITHUB_ACTIONS_PER_PAGE',20,5,100),
 actions_max_pages => env_int('GITHUB_ACTIONS_MAX_PAGES',3,1,5),
 actions_fail_only => env_bool('GITHUB_ACTIONS_FAILURES_ONLY',1),
 actions_show_jobs => env_bool('GITHUB_ACTIONS_SHOW_JOBS',0),
 actions_recovery  => env_bool('GITHUB_ACTIONS_RECOVERY',1),
 actions_enrich    => env_bool('GITHUB_ACTIONS_ENRICH_FAILURES',1),
 actions_job_max   => env_int('GITHUB_ACTIONS_FAILED_JOBS_MAX',3,1,10),
 actions_slow      => env_int('GITHUB_ACTIONS_SLOW_SECONDS',0,0,86400),
 actions_running_max=>env_int('GITHUB_ACTIONS_RUNNING_MAX',5,1,10),
 actions_expect    => env_int('GITHUB_ACTIONS_EXPECT_AFTER_PUSH_SECONDS',0,0,86400),
 actions_expect_max=>env_int('GITHUB_ACTIONS_EXPECT_MAX',20,1,100),
 actions_expect_branches=>env_text('GITHUB_ACTIONS_EXPECT_BRANCHES',''),
 actions_flaky_window=>env_int('GITHUB_ACTIONS_FLAKY_WINDOW_SECONDS',0,0,86400),
 actions_flaky_transitions=>env_int('GITHUB_ACTIONS_FLAKY_TRANSITIONS',3,2,10),

 traffic_enabled   => env_bool('GITHUB_TRAFFIC_ENABLED',1),
 traffic_interval  => env_int('GITHUB_TRAFFIC_SECONDS',3600,300,86400),
 traffic_top       => env_int('GITHUB_TRAFFIC_TOP',5,1,10),

 account           => env_text('GITHUB_ACCOUNT',''),
 account_enabled   => env_bool('GITHUB_ACCOUNT_ENABLED',1),
 account_interval  => env_int('GITHUB_ACCOUNT_SECONDS',900,300,86400),
 account_max_pages => env_int('GITHUB_ACCOUNT_MAX_PAGES',3,1,10),
 account_top       => env_int('GITHUB_ACCOUNT_TOP',6,3,20),
 account_stale_days=> env_int('GITHUB_ACCOUNT_STALE_DAYS',180,30,3650),
 account_changes_max=>env_int('GITHUB_ACCOUNT_CHANGES_MAX',100,20,500),

 history_max       => env_int('ACTIVITY_HISTORY_MAX',20,5,100),
 history_show      => env_int('ACTIVITY_HISTORY_SHOW',5,1,10),
 broadcast_audit_max=>env_int('BROADCAST_AUDIT_MAX',30,5,100),
 metrics_enabled   => env_bool('METRICS_ENABLED',1),
 dashboard_poll     => env_int('DASHBOARD_POLL_SECONDS',3,1,60),
 dashboard_hidden   => env_int('DASHBOARD_HIDDEN_POLL_SECONDS',20,5,300),
 dashboard_timeout  => env_int('DASHBOARD_FETCH_TIMEOUT_SECONDS',4,1,20),
 dashboard_public_url=>env_text('DASHBOARD_PUBLIC_URL',''),

 cmd_cooldown      => env_int('IRC_COMMAND_COOLDOWN_MS',750,0,10000)/1000,
 reconnect_max     => env_int('IRC_RECONNECT_MAX_SECONDS',300,30,3600),
 irc_idle_ping     => env_int('IRC_IDLE_PING_SECONDS',300,0,3600),
 irc_pong_timeout  => env_int('IRC_PONG_TIMEOUT_SECONDS',60,10,300),
 rate_safety       => env_int('GITHUB_RATE_SAFETY_SECONDS',2,0,60),
 secondary_max     => env_int('GITHUB_SECONDARY_BACKOFF_MAX_SECONDS',900,60,3600),
 http_read_timeout => env_int('HTTP_READ_TIMEOUT_SECONDS',5,1,10),
 health_queue_warn => env_int('HEALTH_QUEUE_WARN',150,1,MAX_PENDING),
 ops_alerts        => env_bool('OPS_ALERTS_ENABLED',0),
 ops_debounce      => env_int('OPS_ALERTS_DEBOUNCE_SECONDS',60,10,3600),

 libera_enabled    => env_bool('LIBERA_ENABLED',0),
 libera_host       => env_text('LIBERA_HOST','irc.libera.chat'),
 libera_port       => env_int('LIBERA_PORT',6697,1,65535),
 libera_channel    => env_text('LIBERA_CHANNEL',env_text('IRC_CHANNEL','#irc-gitwatch')),
 libera_nick       => env_text('LIBERA_NICK',env_text('IRC_NICK','gitwatch')),
 libera_user       => env_text('LIBERA_USER',env_text('IRC_USER',env_text('IRC_NICK','gitwatch'))),
 libera_realname   => env_text('LIBERA_REALNAME','IRC GitWatch'),
 libera_sasl_account=> env_text('LIBERA_SASL_ACCOUNT',''),
 libera_sasl_password=>env_text('LIBERA_SASL_PASSWORD',''),
 libera_require_sasl=> env_bool('LIBERA_REQUIRE_SASL',1),

 undernet_enabled  => env_bool('UNDERNET_ENABLED',0),
 undernet_host     => env_text('UNDERNET_HOST','irc.undernet.org'),
 undernet_port     => env_int('UNDERNET_PORT',6667,1,65535),
 undernet_tls      => env_bool('UNDERNET_TLS',0),
 undernet_nick     => env_text('UNDERNET_NICK',env_text('IRC_NICK','gitwatch')),
 undernet_user     => env_text('UNDERNET_USER',env_text('IRC_USER',env_text('IRC_NICK','gitwatch'))),
 undernet_realname => env_text('UNDERNET_REALNAME','IRC GitWatch'),
 undernet_teuk     => env_text('UNDERNET_CHANNEL_PRIMARY',env_text('UNDERNET_CHANNEL_TEUK','#irc-gitwatch')),
 undernet_teuk_key => env_text('UNDERNET_CHANNEL_PRIMARY_KEY',env_text('UNDERNET_CHANNEL_TEUK_KEY','')),
 undernet_miaw     => env_text('UNDERNET_CHANNEL_SECONDARY',env_text('UNDERNET_CHANNEL_MIAW','#irc-gitwatch-ops')),
 undernet_join_retry=> env_int('UNDERNET_JOIN_RETRY_SECONDS',60,15,3600),
 undernet_connect_timeout=>env_int('UNDERNET_CONNECT_TIMEOUT_SECONDS',5,2,30),
 undernet_register_timeout=>env_int('UNDERNET_REGISTER_TIMEOUT_SECONDS',12,5,60),
);
$CFG{hook_path}='/'.$CFG{hook_path} unless $CFG{hook_path}=~m{^/};
my($repo_owner)=split m{/},$CFG{repo},2;
$CFG{account}=lc($CFG{account} ne''?$CFG{account}:($repo_owner||''));
$CFG{api_url}="https://api.github.com/repos/$CFG{repo}/events?per_page=100";
$CFG{actions_url}="https://api.github.com/repos/$CFG{repo}/actions/runs?per_page=$CFG{actions_per_page}";
$CFG{traffic_base}="https://api.github.com/repos/$CFG{repo}/traffic";
$CFG{account_url}="https://api.github.com/users/$CFG{account}/repos?type=owner&sort=updated&direction=desc&per_page=100";

sub config_errors {
 my @e;
 push @e,'GITHUB_REPO must look like owner/repository' unless $CFG{repo}=~m{^[^/\s]+/[^/\s]+$};
 push @e,'GITHUB_ACCOUNT must be a valid GitHub username' if $CFG{account_enabled}&&$CFG{account}!~/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
 push @e,'IRC_CHANNEL must start with #' if $CFG{epiknet_enabled}&&$CFG{irc_channel}!~/^#/;
 push @e,'IRC_NICK must not contain whitespace' if $CFG{epiknet_enabled}&&$CFG{irc_nick}=~/\s/;
 push @e,'GITHUB_STATE_FILE must be absolute' unless $CFG{state_file}=~m{^/};
 push @e,'GITHUB_WEBHOOK_PATH must start with /' unless $CFG{hook_path}=~m{^/};
 push @e,'DASHBOARD_PUBLIC_URL must be http:// or https://' if $CFG{dashboard_public_url} ne''&&$CFG{dashboard_public_url}!~m{^https?://}i;
 push @e,'GITHUB_HTTP_PROXY must be http:// or https://' if $CFG{http_proxy} ne'' && $CFG{http_proxy}!~m{^https?://}i;
 push @e,'RSS_URL must be http:// or https://' if $CFG{rss_enabled} && $CFG{rss_url}!~m{^https?://}i;
 push @e,'IRC_ICON_MODE must be compat, emoji or ascii' unless $CFG{icon_mode}=~/^(?:compat|emoji|ascii)$/;
 push @e,'LIBERA_CHANNEL must start with #' if $CFG{libera_enabled} && $CFG{libera_channel}!~/^#/;
 push @e,'LIBERA_NICK must not contain whitespace' if $CFG{libera_enabled} && $CFG{libera_nick}=~/\s/;
 push @e,'LIBERA_SASL_ACCOUNT and LIBERA_SASL_PASSWORD must be set together' if $CFG{libera_enabled} && (($CFG{libera_sasl_account}eq'') != ($CFG{libera_sasl_password}eq''));
 push @e,'UNDERNET_CHANNEL_PRIMARY must start with #' if $CFG{undernet_enabled} && $CFG{undernet_teuk}!~/^#/;
 push @e,'UNDERNET_CHANNEL_SECONDARY must start with #' if $CFG{undernet_enabled} && $CFG{undernet_miaw}!~/^#/;
 push @e,'UNDERNET channels must be different' if $CFG{undernet_enabled} && lc($CFG{undernet_teuk}) eq lc($CFG{undernet_miaw});
 push @e,'UNDERNET_NICK must not contain whitespace' if $CFG{undernet_enabled} && $CFG{undernet_nick}=~/\s/;
 push @e,'UNDERNET_CHANNEL_PRIMARY_KEY must not contain whitespace' if $CFG{undernet_enabled} && $CFG{undernet_teuk_key}=~/\s/;
 @e;
}
sub config_check { my @e=config_errors(); logmsg('ERROR',$_) for @e; logmsg('INFO','Configuration check: OK') unless @e; @e?1:0 }

# ── Process state ─────────────────────────────────────────────────────────────
my %STATS=map {($_=>0)} qw(hook_received hook_valid hook_sent hook_dupe hook_invalid hook_suppressed hook_bad_signature hook_missing_headers hook_bad_json hook_wrong_repo hook_read_rejected hook_disabled_requests http_requests http_bad_requests http_chunked_requests http_expect_continue hook_root_alias_hits dashboard_api_requests dashboard_api_errors poll_runs poll_pages poll_gap poll_new poll_sent poll_not_modified poll_errors actions_polls actions_pages actions_gap actions_new actions_sent actions_not_modified actions_errors actions_failures actions_success actions_recoveries actions_enriched actions_enrich_skipped actions_slow_alerts actions_missing_alerts actions_expect_cleared actions_flaky_alerts traffic_cycles traffic_requests traffic_errors traffic_forbidden account_polls account_pages account_not_modified account_errors account_repos_seen account_changes_detected broadcast_enqueued broadcast_completed broadcast_delivery_attempts broadcast_delivery_failures queue_dropped queue_partial_dropped rate_limit_hits irc_epiknet_sent irc_libera_sent irc_undernet_sent irc_undernet_teuk_sent irc_undernet_miaw_sent irc_epiknet_reconnects irc_libera_reconnects irc_undernet_reconnects irc_heartbeat_pings irc_heartbeat_timeouts irc_join_retries irc_join_rejects http_listener_starts command_throttled state_backups state_recoveries state_save_errors ops_degraded_alerts ops_recovery_alerts rss_polls rss_new rss_sent rss_not_modified rss_unchanged rss_errors);
my %STATE=(etag=>'',event_seen=>{},deliveries=>{},fingerprints=>{},pending=>[],history=>[],broadcast_seq=>0,broadcast_history=>[],delivery_stats=>{},last_hook_ok=>0,last_hook_event=>'',last_hook_reject_reason=>'',last_hook_reject_at=>0,last_event_text=>'',last_event_source=>'',last_event_at=>0,actions_seen=>{},actions_etag=>'',last_actions_ok=>0,last_action_name=>'',last_action_conclusion=>'',last_action_url=>'',last_action_at=>0,ci_bad_state=>{},ci_running=>{},ci_slow_seen=>{},ci_expected=>{},ci_sha_seen=>{},ci_flap_state=>{},ci_enrich_pending=>[],ci_run_history=>[],traffic_clones=>{},traffic_views=>{},traffic_referrers=>[],traffic_paths=>[],traffic_history=>{},last_traffic_ok=>0,account_etag=>'',account_repos=>[],account_history=>{},account_changes=>[],last_account_ok=>0,rss_seen=>{},rss_etag=>'',rss_modified=>'',last_rss_ok=>0,last_rss_title=>'',last_rss_link=>'',rss_id_version=>0,rss_text_version=>0,rss_digest=>'',stats_version=>0,ops_health_key=>'',ops_health_since=>0,ops_health_alerted=>0,ops_degraded_announced=>0);
my %RUN=(
 started=>time, stopping=>0,
 listener=>undef,http_listener_error=>'',http_listener_started=>0,next_http_retry=>0,http_last_at=>0,http_last_method=>'',http_last_path=>'',http_last_status=>0,
 token=>$CFG{token}, auth_state=>$CFG{token} ne''?'unchecked':'anonymous', auth_login=>'', auth_events=>'unchecked', auth_actions=>'unchecked', auth_error=>'',
 rate_limit=>'?',rate_remaining=>'?',rate_reset=>'?',rate_block_until=>0,rate_block_reason=>'',rate_secondary_streak=>0,last_api_ok=>0,last_api_error=>'',poll_min=>60,next_poll=>time+3,events_scan=>undef,
 actions_next=>time+10,actions_fast_until=>0,actions_error=>'',actions_auth_mode=>'unchecked',actions_error_streak=>0,actions_scan=>undef,cmd_last=>{},
 traffic_next=>time+20,traffic_stage=>0,traffic_cycle=>{},traffic_error=>'',traffic_permission=>'waiting',traffic_render_error=>'',
 account_next=>time+35,account_error=>'',account_scan=>undef,
 rss_next=>time+5,rss_error=>'',rss_failures=>0,rss_dirty=>0,maintenance_cursor=>0,state_loaded_from=>'none',state_last_saved=>0,state_last_error=>'',
);


my @NETS=(
 {
  id=>'epiknet',label=>'EpiKnet',enabled=>$CFG{epiknet_enabled},tls=>1,
  host=>$CFG{irc_host},port=>$CFG{irc_port},channel=>$CFG{irc_channel},
  channels=>[{name=>$CFG{irc_channel},key=>'',label=>'primary',joined=>0,next_join=>0,join_error=>'',startup_sent=>0}],
  nick=>$CFG{irc_nick},user=>$CFG{irc_user},realname=>$CFG{irc_realname},
  sasl_account=>'',sasl_password=>'',require_sasl=>0,sasl_state=>'off',
  socket=>undef,buf=>'',up=>0,next_reconnect=>0,next_send=>0,startup_sent=>0,reconnect_delay=>10,last_rx=>0,last_join=>0,last_ping=>0,pong_deadline=>0,ping_token=>'',send_cursor=>0,
 },
 {
  id=>'libera',label=>'Libera',enabled=>$CFG{libera_enabled},tls=>1,
  host=>$CFG{libera_host},port=>$CFG{libera_port},channel=>$CFG{libera_channel},
  channels=>[{name=>$CFG{libera_channel},key=>'',label=>'primary',joined=>0,next_join=>0,join_error=>'',startup_sent=>0}],
  nick=>$CFG{libera_nick},user=>$CFG{libera_user},realname=>$CFG{libera_realname},
  sasl_account=>$CFG{libera_sasl_account},sasl_password=>$CFG{libera_sasl_password},require_sasl=>$CFG{libera_require_sasl},
  sasl_state=>'off',socket=>undef,buf=>'',up=>0,next_reconnect=>0,next_send=>0,startup_sent=>0,reconnect_delay=>10,last_rx=>0,last_join=>0,last_ping=>0,pong_deadline=>0,ping_token=>'',send_cursor=>0,
 },
 {
  id=>'undernet',label=>'Undernet',enabled=>$CFG{undernet_enabled},tls=>$CFG{undernet_tls},fast_registration=>1,
  host=>$CFG{undernet_host},port=>$CFG{undernet_port},channel=>$CFG{undernet_teuk},
  channels=>[
   {name=>$CFG{undernet_teuk},key=>$CFG{undernet_teuk_key},label=>'primary',joined=>0,next_join=>0,join_error=>'',startup_sent=>0},
   {name=>$CFG{undernet_miaw},key=>'',label=>'secondary',joined=>0,next_join=>0,join_error=>'',startup_sent=>0},
  ],
  nick=>$CFG{undernet_nick},user=>$CFG{undernet_user},realname=>$CFG{undernet_realname},
  sasl_account=>'',sasl_password=>'',require_sasl=>0,sasl_state=>'off',
  socket=>undef,buf=>'',up=>0,next_reconnect=>0,next_send=>0,startup_sent=>0,reconnect_delay=>10,last_rx=>0,last_join=>0,last_ping=>0,pong_deadline=>0,ping_token=>'',send_cursor=>0,
 },
);
my %NET=map{($_->{id}=>$_)}@NETS;
sub enabled_nets { grep{$_->{enabled}}@NETS }
sub online_nets  { grep{$_->{enabled}&&$_->{up}&&$_->{socket}}@NETS }
sub net_channels {
 my($net)=@_;return()unless$net;
 return @{$net->{channels}} if ref($net->{channels})eq'ARRAY'&&@{$net->{channels}};
 ({name=>$net->{channel},key=>'',label=>$net->{channel}});
}
sub delivery_target_id {
 my($net,$channel)=@_;my@c=net_channels($net);
 return$net->{id} if@c<=1;
 $net->{id}.':'.lc(clean($channel||''));
}
sub target_metric_key {
 my($net,$channel)=@_;my@c=net_channels($net);return$net->{id} if@c<=1;
 my$k=lc(clean($channel||''));$k=~s/^[#&]+//;$k=~s/[^a-z0-9]+/_/g;$k=~s/^_+|_+$//g;
 $net->{id}.'_'.$k;
}
sub enabled_targets {
 my@out;for my$net(enabled_nets()){for my$ch(net_channels($net)){push@out,{net=>$net,channel=>$ch->{name},key=>$ch->{key}||'',id=>delivery_target_id($net,$ch->{name}),metric=>target_metric_key($net,$ch->{name})}}}
 @out;
}
sub target_by_id {
 my($id)=@_;$id=clean($id||'');for my$t(enabled_targets()){return$t if$t->{id}eq$id}undef;
}
sub current_target_ids { map{$_->{id}}enabled_targets() }
sub ensure_item_targets {
 my($item)=@_;return[]unless$item&&ref($item)eq'HASH';
 if(ref($item->{targets})ne'ARRAY'||!@{$item->{targets}}){
  $item->{targets}=[current_target_ids()];
 }
 my%enabled=map{($_=>1)}current_target_ids();
 my%seen;my@active=grep{$enabled{$_}&&!$seen{$_}++}map{clean($_)}@{$item->{targets}};
 $item->{targets}=\@active;\@active;
}
sub item_target_ids {
 my($item)=@_;my$a=ensure_item_targets($item);@$a;
}
sub broadcast_event_id {
 my($src,$text,$now)=@_;$STATE{broadcast_seq}=int($STATE{broadcast_seq}||0)+1;
 'b'.$STATE{broadcast_seq}.'-'.int(($now||time)*1000).'-'.substr(sha256_hex(encode('UTF-8',join("\x1f",$src||'',plain_irc($text||''),$STATE{broadcast_seq}))),0,8);
}
sub record_broadcast_enqueue {
 my($item)=@_;return 0 unless$item&&ref($item)eq'HASH';
 my%targets=map{($_=>int($item->{delivered}{$_}||0))}item_target_ids($item);
 push@{$STATE{broadcast_history}},{
  id=>$item->{id}||'',source=>clean($item->{source}||'unknown'),created=>int($item->{created}||time),
  text=>short(plain_irc($item->{text}||''),220),targets=>\%targets,status=>'pending',
 };
 splice@{$STATE{broadcast_history}},0,@{$STATE{broadcast_history}}-$CFG{broadcast_audit_max}
  if@{$STATE{broadcast_history}}>$CFG{broadcast_audit_max};
 1;
}
sub broadcast_history_entry {
 my($id)=@_;return unless$id;for my$h(reverse@{$STATE{broadcast_history}}){return$h if ref($h)eq'HASH'&&($h->{id}||'')eq$id}undef;
}
sub note_broadcast_delivery {
 my($item,$target_id,$at)=@_;return 0 unless$item&&$target_id;$at=int($at||time);
 my$d=$STATE{delivery_stats}{$target_id};$d={}unless ref($d)eq'HASH';
 $d->{sent}=int($d->{sent}||0)+1;$d->{last_at}=$at;$d->{last_event_id}=$item->{id}||'';
 $STATE{delivery_stats}{$target_id}=$d;
 my$h=broadcast_history_entry($item->{id});
 if($h){$h->{targets}={}unless ref($h->{targets})eq'HASH';$h->{targets}{$target_id}=$at}
 1;
}
sub note_broadcast_complete {
 my($item)=@_;return 0 unless$item;
 my$h=broadcast_history_entry($item->{id});if($h){$h->{status}='complete';$h->{completed_at}=int(time)}
 $STATS{broadcast_completed}++;1;
}
sub note_broadcast_dropped {
 my($item)=@_;return 0 unless$item;
 my$h=broadcast_history_entry($item->{id});if($h){$h->{status}='dropped';$h->{completed_at}=int(time)}
 1;
}
sub broadcast_target_snapshot {
 my$q=queue_snapshot();my@rows;
 for my$t(enabled_targets()){
  my$c=channel_config($t->{net},$t->{channel});my$d=$STATE{delivery_stats}{$t->{id}}; $d={}unless ref($d)eq'HASH';
  push@rows,{
   id=>$t->{id},network=>$t->{net}{id},label=>$t->{net}{label},channel=>$t->{channel},
   online=>$t->{net}{up}?1:0,joined=>$c&&$c->{joined}?1:0,
   sent=>int($d->{sent}||0),last_at=>int($d->{last_at}||0),
   pending=>int($q->{$t->{metric}}||0),oldest_at=>int($q->{$t->{metric}.'_oldest_at'}||0),
  };
 }
 @rows;
}
sub broadcast_payload {
 my@targets=broadcast_target_snapshot();my@recent=reverse@{$STATE{broadcast_history}};
 splice@recent,5 if@recent>5;
 +{
  configured_targets=>scalar(@targets),pending_events=>scalar(@{$STATE{pending}}),
  enqueued=>$STATS{broadcast_enqueued},completed=>$STATS{broadcast_completed},
  delivery_attempts=>$STATS{broadcast_delivery_attempts},delivery_failures=>$STATS{broadcast_delivery_failures},
  targets=>\@targets,recent=>[map{{%$_,targets=>ref($_->{targets})eq'HASH'?{%{$_->{targets}}}:{}}}@recent],
 };
}
sub all_networks_delivered {
 my($item)=@_;my@ids=item_target_ids($item);return 1 unless@ids;
 for my$id(@ids){return 0 unless$item->{delivered}{$id}}
 1;
}
sub irc_summary {
 join(', ',map{my@c=net_channels($_);$_->{label}.'='.($_->{up}?'online':'offline').'['.join(',',map{$_->{name}}@c).']'}enabled_nets());
}
sub channel_config {
 my($net,$name)=@_;return unless$net;
 for my$c(net_channels($net)){return$c if lc($c->{name})eq lc(clean($name||''))}
 undef;
}
sub join_command {
 my($net,$ch)=@_;my$c=ref($ch)eq'HASH'?$ch:channel_config($net,$ch);return q{}unless$c;
 my$line='JOIN '.$c->{name};$line.=' '.$c->{key} if defined($c->{key})&&$c->{key}ne'';$line;
}
sub channel_joined {
 my($net,$name)=@_;my$c=channel_config($net,$name);$c&&$c->{joined}?1:0;
}
sub mark_channel_joined {
 my($net,$name)=@_;my$c=channel_config($net,$name);return 0 unless$c;
 my$changed=!$c->{joined};$c->{joined}=1;$c->{next_join}=0;$c->{join_error}='';$changed;
}
sub mark_channel_down {
 my($net,$name,$why)=@_;my$c=channel_config($net,$name);return 0 unless$c;
 $c->{joined}=0;$c->{join_error}=clean($why||'not joined');
 $c->{next_join}=time+($net->{id}eq'undernet'?$CFG{undernet_join_retry}:10);
 $c->{startup_sent}=0;1;
}
sub joined_channels {
 my($net)=@_;grep{$_->{joined}}net_channels($net);
}
sub rejoin_channels_once {
 my$now=time;
 for my$net(online_nets()){
  for my$ch(net_channels($net)){
   next if$ch->{joined};next if$ch->{next_join}&&$now<$ch->{next_join};
   my$j=join_command($net,$ch);next if$j eq'';
   if(irc_raw($net,$j)){
    $ch->{next_join}=$now+($net->{id}eq'undernet'?$CFG{undernet_join_retry}:10);
    $STATS{irc_join_retries}++;return 1;
   }
   return 1;
  }
 }
 0;
}

my %HTTP_OPT=(agent=>'irc-gitwatch/'.VERSION,timeout=>15,verify_SSL=>1);
if($CFG{http_proxy}=~m{^https?://}i){$HTTP_OPT{proxy}=$CFG{http_proxy}}
else{@HTTP_OPT{qw(proxy http_proxy https_proxy)}=(undef,undef,undef);$HTTP_OPT{no_proxy}=[]}
my $HTTP=HTTP::Tiny->new(%HTTP_OPT);

# ── Logging / IRC style ───────────────────────────────────────────────────────
sub logmsg { my($lvl,$s)=@_; $s//=q{}; $s=~s/[\r\n]+/ /g; print STDERR '['.uc($lvl||'INFO')."] $s\n" }
my($B,$C,$R)=("\x02","\x03","\x0f");
sub paint { my($n,$s)=@_; $CFG{irc_colors}?$C.sprintf('%02d',$n).$s.$R:$s }
sub bold  { my($s)=@_; $CFG{irc_colors}?$B.$s.$B:$s }

my%ICON=(
 compat=>{
  github=>'★',push=>'↑',issue=>'!',comment=>'>',pr=>'+',review=>'✓',release=>'★',
  create=>'+',delete=>'×',fork=>'↗',star=>'★',discussion=>'@',workflow=>'⚙',ci=>'!',
  check=>'✓',status=>'●',deploy=>'↑',repo=>'◆',wiki=>'W',pin=>'•',protect=>'§',
  label=>'#',milestone=>'◇',member=>'@',pages=>'☁',merge=>'⇄',generic=>'•',
  forum=>'◆',health=>'✓',auth=>'@',latest=>'>',rate=>'%',stats=>'≡',webhook=>'⌁',
  events=>'≡',link=>'→',refresh=>'↻',queue=>'=',time=>'~',api=>'A',shield=>'✓',
 },
 emoji=>{
  github=>'🪄',push=>'🪄',issue=>'🧩',comment=>'💬',pr=>'🧙',review=>'🔍',release=>'🏆',
  create=>'🌱',delete=>'🔥',fork=>'🦉',star=>'⭐',discussion=>'🗣',workflow=>'⚙',ci=>'✗',
  check=>'🧪',status=>'🚦',deploy=>'🚀',repo=>'🏰',wiki=>'📚',pin=>'📌',protect=>'🛡',
  label=>'🏷',milestone=>'🎯',member=>'👤',pages=>'🌐',merge=>'🔀',generic=>'🔔',
  forum=>'📰',health=>'✓',auth=>'🔐',latest=>'🔮',rate=>'⏳',stats=>'📊',webhook=>'🔗',
  events=>'🧭',link=>'🔗',refresh=>'🔄',queue=>'📨',time=>'⏱',api=>'🌐',shield=>'✓',
 },
 ascii=>{
  github=>'*',push=>'>',issue=>'!',comment=>'>',pr=>'+',review=>'+',release=>'*',
  create=>'+',delete=>'-',fork=>'>',star=>'*',discussion=>'@',workflow=>'#',ci=>'!',
  check=>'+',status=>'*',deploy=>'>',repo=>'#',wiki=>'W',pin=>'*',protect=>'!',
  label=>'#',milestone=>'*',member=>'@',pages=>'@',merge=>'>',generic=>'*',
  forum=>'F',health=>'+',auth=>'A',latest=>'>',rate=>'%',stats=>'#',webhook=>'W',
  events=>'E',link=>'>',refresh=>'R',queue=>'Q',time=>'T',api=>'A',shield=>'+',
 },
);
sub icon { my($k)=@_;$ICON{$CFG{icon_mode}}{$k}//$ICON{compat}{$k}//'*' }
sub tag  { paint(11,bold('GitHub')) }
sub sep  { paint(14,' · ') }

sub clean {
 my($s)=@_;$s//=q{};
 # Strip IRC control bytes plus invisible bidi/formatting controls that can make
 # repository/feed titles misleading in a public channel.
 $s=~s/[\x00-\x1f\x7f]+/ /g;
 $s=~s/[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2069}\x{FEFF}]//g;
 $s=~s/\s+/ /g;$s=~s/^\s+|\s+$//g;$s
}
sub mojibake_score {
 my($s)=@_;$s//=q{};
 my$n=0;$n++ while$s=~/(?:Ã|Â|â|ð|ï¿½)/g;$n;
}
sub repair_mojibake {
 my($s)=@_;return q{} unless defined$s;return$s unless mojibake_score($s);
 my$best=$s;my$best_score=mojibake_score($s);
 # Old state files may contain UTF-8 bytes decoded either as Windows-1252
 # (printable smart punctuation) or byte-for-byte Latin-1 (C1 controls).
 for my$encoding('Windows-1252','ISO-8859-1'){
  my$copy=$s;my$bytes=eval{encode($encoding,$copy,FB_CROAK)};next if$@;
  my$candidate=eval{decode('UTF-8',$bytes,FB_CROAK)};next if$@;
  my$score=mojibake_score($candidate);if($score<$best_score){$best=$candidate;$best_score=$score}
 }
 $best;
}
sub plain_irc {
 my($s)=@_;$s=repair_mojibake($s//q{});
 $s=~s/\x03(?:\d{1,2}(?:,\d{1,2})?)?//g;
 $s=~s/[\x02\x0f\x16\x1d\x1f]//g;
 clean($s);
}
sub repair_activity_text {
 my($s,$source)=@_;$s=plain_irc($s//q{});
 # Some pre-v0.27 activity rows were already saved after their UTF-8
 # continuation bytes had been discarded. Repair only those recognizable,
 # lossy legacy display forms; leave every other string untouched.
 if($s=~s/^â[^\p{L}\p{N}\s}]*(?=\s+GitHub:)/↑/){$s=~s/(^|\s)â[^\p{L}\p{N}\s}]*(?=\s+https?:\/\/)/$1—/g}
 elsif($s=~s/^â[^\p{L}\p{N}\s}]*(?=\s+Forum:)/◆/){$s=~s/(^|\s)â[^\p{L}\p{N}\s}]*(?=\s|$)/$1—/g}
 $s;
}
sub irc_content {
 my($s)=@_;$s=clean(repair_mojibake($s//q{}));
 if($CFG{icon_mode} eq'compat'){
  # Keep normal Unicode text (e.g. French accents), but remove modern emoji /
  # ZWJ presentation sequences that are frequently unsupported by IRC clients.
  $s=~s/[\x{10000}-\x{10FFFF}]//g;
  $s=~s/[\x{FE0E}\x{FE0F}\x{200D}]//g;
  $s=~s/\s+/ /g;$s=~s/^\s+|\s+$//g;
 }
 $s;
}
sub irc_short { my($s,$n)=@_;$s=irc_content($s);length($s)>$n?substr($s,0,$n-1).'…':$s }
sub short { my($s,$n)=@_; $s=clean($s); length($s)>$n?substr($s,0,$n-1).'…':$s }
sub byte_limit { my($s,$n)=@_; chop($s) while length(encode('UTF-8',$s))>$n; $s }
sub maxn { $_[0]>$_[1]?$_[0]:$_[1] }
sub age {
 my($t)=@_; return'never' unless$t; my$s=int(time-$t);
 return"${s}s ago" if$s<60; return int($s/60).'m ago' if$s<3600; return int($s/3600).'h ago' if$s<86400; int($s/86400).'d ago';
}
sub uptime {
 my$s=int(time-$RUN{started}); my$d=int($s/86400);$s%=86400;my$h=int($s/3600);$s%=3600;my$m=int($s/60);$s%=60;
 ($d?"${d}d ":'').($h?"${h}h ":'').($m?"${m}m ":'')."${s}s";
}
sub iso8601_epoch {
 my($s)=@_;$s=clean($s//q{});
 return 0 unless$s=~/^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d+)?Z$/;
 my($y,$mo,$d,$h,$mi,$se)=($1,$2,$3,$4,$5,$6);
 my$t=eval{timegm($se,$mi,$h,$d,$mo-1,$y)};
 defined($t)&&!$@?$t:0;
}
sub duration_text {
 my($s)=@_;$s=int($s||0);$s=0 if$s<0;
 return"${s}s"if$s<60;return int($s/60).'m'if$s<3600;
 return int($s/3600).'h '.int(($s%3600)/60).'m'if$s<86400;
 int($s/86400).'d '.int(($s%86400)/3600).'h';
}
sub utc_date { my($t)=@_;my@g=gmtime($t||time);sprintf('%04d-%02d-%02d',$g[5]+1900,$g[4]+1,$g[3]) }

sub api_state { !$CFG{poll_enabled}?'off':!github_rest_allowed()?'limited':$RUN{last_api_error}?'error':$RUN{last_api_ok}?'online':'waiting' }
sub rss_state { !$CFG{rss_enabled}?'off':$RUN{rss_error}?'error':$STATE{last_rss_ok}?'online':'waiting' }
sub webhook_state { $CFG{hook_secret}eq''?'off':$STATE{last_hook_ok}?'live':'listening' }
sub state_color_num { $_[0] eq'online'||$_[0] eq'live'?3:$_[0] eq'error'?4:$_[0] eq'off'?14:8 }

sub account_normalize_repo {
 my($r)=@_;return unless$r&&ref($r)eq'HASH';
 my$full=clean($r->{full_name}//'');my$name=clean($r->{name}//'');
 my$owner=clean(ref($r->{owner})eq'HASH'?($r->{owner}{login}//''):($r->{owner_login}//''));$owner=$1 if$owner eq''&&$full=~m{^([^/]+)/};
 return if lc($owner)ne lc($CFG{account})||$r->{private}||$name eq''||lc($full)ne lc($CFG{account}.'/'.$name);
 my$license=ref($r->{license})eq'HASH'?clean($r->{license}{spdx_id}//''):clean($r->{license}//'');
 $license=''if$license eq'NOASSERTION';
 my@topics=ref($r->{topics})eq'ARRAY'?map{short($_,50)}grep{defined&&!ref($_)&&length clean($_)}@{$r->{topics}}:();
 splice@topics,20 if@topics>20;
 +{id=>int($r->{id}||0),name=>$name,full_name=>$full,
  html_url=>"https://github.com/$full",description=>short($r->{description}//'',300),
  homepage=>(clean($r->{homepage}//'')=~m{^https?://}i?clean($r->{homepage}):''),language=>short($r->{language}//'',60),default_branch=>short($r->{default_branch}//'',100),
  archived=>$r->{archived}?1:0,disabled=>$r->{disabled}?1:0,fork=>$r->{fork}?1:0,
  stars=>int($r->{stargazers_count}//$r->{stars}//0),forks=>int($r->{forks_count}//$r->{forks}//0),
  open_issues=>int($r->{open_issues_count}//$r->{open_issues}//0),size=>int($r->{size}||0),
  created_at=>clean($r->{created_at}//''),updated_at=>clean($r->{updated_at}//''),pushed_at=>clean($r->{pushed_at}//''),
  license=>$license,topics=>\@topics};
}

# ── Persistent state ─────────────────────────────────────────────────────────
sub cap_hash {
 my($h,$max)=@_; return if keys(%$h)<=$max;
 my@k=sort{($h->{$b}||0)<=>($h->{$a}||0)}keys%$h; my%keep=map{($_=>1)}@k[0..$max-1]; delete$h->{$_} for grep{!$keep{$_}}keys%$h;
}
sub normalize_ci_history_entry {
 my($x)=@_;return unless ref($x)eq'HASH';
 my$id=int($x->{id}||0);my$attempt=int($x->{attempt}||1);$attempt=1 if$attempt<1;my$at=int($x->{at}||$x->{completed_at}||0);
 my$conclusion=lc(clean($x->{conclusion}||''));return unless$id>0&&$at>0&&$conclusion ne'';
 my$workflow_id=int($x->{workflow_id}||0);my$name=short($x->{name}||'GitHub Actions',120);my$branch=short($x->{branch}||'repository',120);
 my$scope=($workflow_id>0?'id:'.$workflow_id:'name:'.lc($name))."\x1f".lc($branch);my$duration=int($x->{duration}||0);$duration=0 if$duration<0;
 +{key=>join(':',$id,$attempt,$conclusion),id=>$id,attempt=>$attempt,workflow_id=>$workflow_id,scope=>$scope,
   name=>$name,branch=>$branch,conclusion=>$conclusion,at=>$at,started_at=>int($x->{started_at}||0),
   duration=>$duration,sha=>short($x->{sha}||'',64),url=>clean($x->{url}||'')};
}
sub prune_state {
 my$n=time;
 delete$STATE{event_seen}{$_} for grep{!$STATE{event_seen}{$_}||$STATE{event_seen}{$_}<$n-30*86400}keys%{$STATE{event_seen}};
 delete$STATE{deliveries}{$_} for grep{!$STATE{deliveries}{$_}||$STATE{deliveries}{$_}<$n-7*86400}keys%{$STATE{deliveries}};
 delete$STATE{fingerprints}{$_} for grep{!$STATE{fingerprints}{$_}||$STATE{fingerprints}{$_}<$n-2*86400}keys%{$STATE{fingerprints}};
 delete$STATE{rss_seen}{$_} for grep{!$STATE{rss_seen}{$_}||$STATE{rss_seen}{$_}<$n-90*86400}keys%{$STATE{rss_seen}};
 delete$STATE{actions_seen}{$_} for grep{!$STATE{actions_seen}{$_}||$STATE{actions_seen}{$_}<$n-30*86400}keys%{$STATE{actions_seen}};
 for my$k(keys%{$STATE{ci_bad_state}}){
  my$v=$STATE{ci_bad_state}{$k};delete$STATE{ci_bad_state}{$k} if ref($v)ne'HASH'||!$v->{at}||$v->{at}<$n-30*86400;
 }
 for my$k(keys%{$STATE{ci_running}}){
  my$v=$STATE{ci_running}{$k};delete$STATE{ci_running}{$k} if ref($v)ne'HASH'||!$v->{last_seen}||$v->{last_seen}<$n-7*86400;
 }
 for my$sha(keys%{$STATE{ci_expected}}){
  my$v=$STATE{ci_expected}{$sha};delete$STATE{ci_expected}{$sha} if ref($v)ne'HASH'||!$v->{at}||$v->{at}<$n-7*86400;
 }
 delete$STATE{ci_sha_seen}{$_} for grep{!$STATE{ci_sha_seen}{$_}||$STATE{ci_sha_seen}{$_}<$n-7*86400}keys%{$STATE{ci_sha_seen}};
 delete$STATE{ci_slow_seen}{$_} for grep{!$STATE{ci_slow_seen}{$_}||$STATE{ci_slow_seen}{$_}<$n-7*86400}keys%{$STATE{ci_slow_seen}};
 for my$k(keys%{$STATE{ci_flap_state}}){
  my$v=$STATE{ci_flap_state}{$k};delete$STATE{ci_flap_state}{$k} if ref($v)ne'HASH'||!$v->{last_at}||$v->{last_at}<$n-7*86400;
 }
 my%ci_seen;my@ci=sort{($a->{at}||0)<=>($b->{at}||0)}grep{defined&&!$ci_seen{$_->{key}}++}
  map{normalize_ci_history_entry($_)}@{$STATE{ci_run_history}};
 @ci=grep{$_->{at}>=$n-MAX_CI_DAYS*86400}@ci;
 splice@ci,0,@ci-MAX_CI_RUNS if@ci>MAX_CI_RUNS;$STATE{ci_run_history}=\@ci;
 for my$d(keys%{$STATE{traffic_history}}){
  my$v=$STATE{traffic_history}{$d};delete$STATE{traffic_history}{$d} unless$d=~/^\d{4}-\d\d-\d\d$/&&ref($v)eq'HASH';
 }
 my@traffic_days=sort keys%{$STATE{traffic_history}};
 if(@traffic_days>MAX_TRAFFIC_DAYS){delete$STATE{traffic_history}{$_} for@traffic_days[0..@traffic_days-MAX_TRAFFIC_DAYS-1]}
 for my$d(keys%{$STATE{account_history}}){my$v=$STATE{account_history}{$d};delete$STATE{account_history}{$d}unless$d=~/^\d{4}-\d\d-\d\d$/&&ref($v)eq'HASH'}
 my@account_days=sort keys%{$STATE{account_history}};
 if(@account_days>MAX_ACCOUNT_DAYS){delete$STATE{account_history}{$_}for@account_days[0..@account_days-MAX_ACCOUNT_DAYS-1]}
 splice@{$STATE{account_changes}},0,@{$STATE{account_changes}}-$CFG{account_changes_max}if@{$STATE{account_changes}}>$CFG{account_changes_max};
 splice @{$STATE{history}},0,@{$STATE{history}}-$CFG{history_max} if@{$STATE{history}}>$CFG{history_max};
 splice @{$STATE{broadcast_history}},0,@{$STATE{broadcast_history}}-$CFG{broadcast_audit_max} if@{$STATE{broadcast_history}}>$CFG{broadcast_audit_max};
 cap_hash($STATE{event_seen},MAX_EVENT_IDS); cap_hash($STATE{deliveries},MAX_DELIVERIES); cap_hash($STATE{fingerprints},MAX_FINGERPRINTS); cap_hash($STATE{rss_seen},MAX_RSS_IDS); cap_hash($STATE{actions_seen},MAX_EVENT_IDS);
 if(@{$STATE{pending}}>MAX_PENDING){splice @{$STATE{pending}},0,@{$STATE{pending}}-MAX_PENDING}
 splice @{$STATE{ci_enrich_pending}},20 if @{$STATE{ci_enrich_pending}}>20;
}
sub state_backup_path { $CFG{state_file}.'.bak' }
sub read_state_document {
 my($path)=@_;return(undef,undef,'missing') unless defined$path&&-f$path;
 open my$fh,'<:raw',$path or return(undef,undef,'open: '.clean($!));local$/;my$raw=<$fh>;close$fh;
 my$d=eval{decode_json($raw)};return(undef,$raw,'invalid JSON') unless$d&&ref($d)eq'HASH';
 ($d,$raw,'');
}
sub write_raw_atomic_0600 {
 my($path,$raw)=@_;my$tmp="$path.tmp.$$\.".int(time*1000);
 sysopen(my$fh,$tmp,O_WRONLY|O_CREAT|O_EXCL,0600)or return(0,'create: '.clean($!));binmode$fh,':raw';
 my$ok=eval{print{$fh}$raw or die"write: $!";$fh->flush or die"flush: $!";eval{$fh->sync};close$fh or die"close: $!";1};
 if(!$ok){my$e=clean($@||$!);close$fh;unlink$tmp;return(0,$e)}
 rename$tmp,$path or do{my$e=clean($!);unlink$tmp;return(0,"rename: $e")};(1,'');
}
sub backup_current_state {
 return 1 unless$CFG{state_backup};return 1 unless-f$CFG{state_file};
 my($d,$raw,$err)=read_state_document($CFG{state_file});
 if(!$d){logmsg('WARN',"State backup skipped: primary $err");return 0}
 my($ok,$why)=write_raw_atomic_0600(state_backup_path(),$raw);
 if($ok){$STATS{state_backups}++;return 1}
 logmsg('WARN',"Cannot update state backup: $why");0;
}
sub state_status {
 my($p,undef,$pe)=read_state_document($CFG{state_file});my($b,undef,$be)=read_state_document(state_backup_path());
 +{primary=>$p?'ok':$pe,backup=>$b?'ok':$be,loaded_from=>$RUN{state_loaded_from}||'none',last_saved=>$RUN{state_last_saved}||0,last_error=>$RUN{state_last_error}||'',primary_version=>$p?int($p->{state_version}||0):0,backup_version=>$b?int($b->{state_version}||0):0};
}
sub state_check_cli {
 my$s=state_status();my$primary=$s->{primary}eq'ok';my$backup=$s->{backup}eq'ok';
 print APP_NAME.' '.VERSION." state check\n";
 print 'primary='.$s->{primary}.($s->{primary_version}?" v$s->{primary_version}":'')."\n";
 print 'backup='.$s->{backup}.($s->{backup_version}?" v$s->{backup_version}":'')."\n";
 return 0 if$primary;return 2 if$backup;1;
}
sub load_state {
 my($d,undef,$err)=read_state_document($CFG{state_file});my$source='primary';my$recovered=0;
 if(!$d&&$CFG{state_backup}){my($bd,undef,$berr)=read_state_document(state_backup_path());if($bd){$d=$bd;$source='backup';$recovered=1;logmsg('WARN',"Primary state $err; recovered from backup")}elsif($err ne'missing'||$berr ne'missing'){logmsg('WARN',"State unavailable: primary $err; backup $berr")}}
 return unless$d&&ref($d)eq'HASH';
 $RUN{state_loaded_from}=$source;$RUN{state_last_saved}=int($d->{saved_at}||0);
 $STATE{etag}=$d->{etag}//'';
 my$ev=$d->{event_seen}//$d->{seen_event}//$d->{seen};
 if(ref($ev)eq'HASH'){$STATE{event_seen}={%$ev}} elsif(ref($ev)eq'ARRAY'){my$n=time;$STATE{event_seen}={map{($_=>$n)}grep{defined&&length}@$ev}}
 for my$pair([deliveries=>qw(deliveries seen_delivery)],[fingerprints=>qw(fingerprints fingerprint)]){
  my($dst,@src)=@$pair; for my$k(@src){if(ref($d->{$k})eq'HASH'){$STATE{$dst}={%{$d->{$k}}};last}}
 }
 $STATE{broadcast_seq}=int($d->{broadcast_seq}||0);
 if(ref($d->{pending})eq'ARRAY'){
  my@q;for my$i(@{$d->{pending}}){
   my$item;
   if(!ref($i)){$item={text=>repair_mojibake($i),source=>'legacy',created=>int(time),delivered=>{},counted=>0}}
   elsif(ref($i)eq'HASH'&&defined$i->{text}){
    $item={text=>repair_mojibake($i->{text}),source=>$i->{source}||'legacy',created=>int($i->{created}||time),
     delivered=>ref($i->{delivered})eq'HASH'?{%{$i->{delivered}}}:{},counted=>$i->{counted}?1:0,
     id=>clean($i->{id}||''),targets=>ref($i->{targets})eq'ARRAY'?[map{clean($_)}@{$i->{targets}}]:[]};
   }
   next unless$item;$item->{id}=broadcast_event_id($item->{source},$item->{text},$item->{created}) if($item->{id}//'')eq'';
   ensure_item_targets($item);push@q,$item;
  }
  splice@q,MAX_PENDING if@q>MAX_PENDING;$STATE{pending}=\@q;
 }
 if(ref($d->{broadcast_history})eq'ARRAY'){
  my@b;for my$h(@{$d->{broadcast_history}}){next unless ref($h)eq'HASH'&&defined$h->{id};
   push@b,{id=>clean($h->{id}),source=>clean($h->{source}||'unknown'),created=>int($h->{created}||0),completed_at=>int($h->{completed_at}||0),
    text=>short(plain_irc($h->{text}||''),220),status=>clean($h->{status}||'pending'),targets=>ref($h->{targets})eq'HASH'?{%{$h->{targets}}}:{}};
  } splice@b,0,@b-$CFG{broadcast_audit_max} if@b>$CFG{broadcast_audit_max};$STATE{broadcast_history}=\@b;
 }
 $STATE{delivery_stats}={%{$d->{delivery_stats}}} if ref($d->{delivery_stats})eq'HASH';
 if(!@{$STATE{broadcast_history}}&&@{$STATE{pending}}){record_broadcast_enqueue($_) for@{$STATE{pending}}}
 if(ref($d->{history})eq'ARRAY'){
  my@h;
  for my$i(@{$d->{history}}){
   next unless ref($i)eq'HASH'&&defined$i->{text};
   push@h,{text=>plain_irc(repair_mojibake($i->{text})),source=>clean($i->{source}||'legacy'),at=>int($i->{at}||0)};
  }
  splice@h,0,@h-$CFG{history_max} if@h>$CFG{history_max};$STATE{history}=\@h;
 }
 if(ref($d->{stats})eq'HASH'){$STATS{$_}=int($d->{stats}{$_}||0) for keys%STATS}
 $STATE{last_hook_ok}=int($d->{last_hook_ok}||0);$STATE{last_hook_event}=clean($d->{last_hook_event}//'');$STATE{last_hook_reject_reason}=clean($d->{last_hook_reject_reason}//'');$STATE{last_hook_reject_at}=int($d->{last_hook_reject_at}||0);
 $STATE{last_event_text}=repair_mojibake($d->{last_event_text}//'');$STATE{last_event_source}=clean($d->{last_event_source}//'');
 $STATE{last_event_at}=int($d->{last_event_at}||0);
 $STATE{actions_seen}={%{$d->{actions_seen}}} if ref($d->{actions_seen})eq'HASH';
 $STATE{actions_etag}=$d->{actions_etag}//'';$STATE{last_actions_ok}=int($d->{last_actions_ok}||0);
 $STATE{last_action_name}=clean($d->{last_action_name}//'');$STATE{last_action_conclusion}=clean($d->{last_action_conclusion}//'');
 $STATE{last_action_url}=clean($d->{last_action_url}//'');$STATE{last_action_at}=int($d->{last_action_at}||0);
 $STATE{ci_bad_state}={%{$d->{ci_bad_state}}} if ref($d->{ci_bad_state})eq'HASH';
 $STATE{ci_running}={%{$d->{ci_running}}} if ref($d->{ci_running})eq'HASH';
 $STATE{ci_slow_seen}={%{$d->{ci_slow_seen}}} if ref($d->{ci_slow_seen})eq'HASH';
 $STATE{ci_expected}={%{$d->{ci_expected}}} if ref($d->{ci_expected})eq'HASH';
 $STATE{ci_sha_seen}={%{$d->{ci_sha_seen}}} if ref($d->{ci_sha_seen})eq'HASH';
 $STATE{ci_flap_state}={%{$d->{ci_flap_state}}} if ref($d->{ci_flap_state})eq'HASH';
 if(ref($d->{ci_run_history})eq'ARRAY'){
  my%seen;my@runs=sort{($a->{at}||0)<=>($b->{at}||0)}grep{defined&&!$seen{$_->{key}}++}
   map{normalize_ci_history_entry($_)}@{$d->{ci_run_history}};
  splice@runs,0,@runs-MAX_CI_RUNS if@runs>MAX_CI_RUNS;$STATE{ci_run_history}=\@runs;
 }
 $STATE{traffic_clones}={%{$d->{traffic_clones}}} if ref($d->{traffic_clones})eq'HASH';
 $STATE{traffic_views}={%{$d->{traffic_views}}} if ref($d->{traffic_views})eq'HASH';
 $STATE{traffic_referrers}=[map{{%$_}}@{$d->{traffic_referrers}}] if ref($d->{traffic_referrers})eq'ARRAY';
 $STATE{traffic_paths}=[map{{%$_}}@{$d->{traffic_paths}}] if ref($d->{traffic_paths})eq'ARRAY';
 if(ref($d->{traffic_history})eq'HASH'){
  my%h;for my$date(keys%{$d->{traffic_history}}){my$v=$d->{traffic_history}{$date};next unless$date=~/^\d{4}-\d\d-\d\d$/&&ref($v)eq'HASH';$h{$date}={date=>$date,map{($_=>int($v->{$_}||0))}qw(clones clone_uniques views view_uniques)}}$STATE{traffic_history}=\%h;
 }elsif(ref($d->{traffic_history})eq'ARRAY'){
  my%h;for my$v(@{$d->{traffic_history}}){next unless ref($v)eq'HASH';my$date=clean($v->{date}||'');next unless$date=~/^\d{4}-\d\d-\d\d$/;$h{$date}={date=>$date,map{($_=>int($v->{$_}||0))}qw(clones clone_uniques views view_uniques)}}$STATE{traffic_history}=\%h;
 }
 $STATE{last_traffic_ok}=int($d->{last_traffic_ok}||0);
 traffic_merge_history();
 $STATE{account_etag}=clean($d->{account_etag}//'');
 if(ref($d->{account_repos})eq'ARRAY'){
  my@repos=grep{defined}map{account_normalize_repo($_)}@{$d->{account_repos}};$STATE{account_repos}=\@repos;
 }
 if(ref($d->{account_history})eq'HASH'){
  my%h;for my$date(keys%{$d->{account_history}}){my$v=$d->{account_history}{$date};next unless$date=~/^\d{4}-\d\d-\d\d$/&&ref($v)eq'HASH';$h{$date}={date=>$date,map{($_=>int($v->{$_}||0))}qw(repositories maintained active_30d archived stale stars forks open_issues)}}$STATE{account_history}=\%h;
 }
 if(ref($d->{account_changes})eq'ARRAY'){
  my@c;for my$x(@{$d->{account_changes}}){next unless ref($x)eq'HASH';my$repo=clean($x->{repo}||'');my$kind=clean($x->{kind}||'');next unless$repo=~m{^\Q$CFG{account}\E/[^/]+$}i&&$kind=~/^(?:added|removed|archived|unarchived|pushed|stars|forks|open_issues)$/;push@c,{at=>int($x->{at}||0),repo=>$repo,kind=>$kind,from=>short($x->{from}//'',120),to=>short($x->{to}//'',120)}}
  splice@c,0,@c-$CFG{account_changes_max}if@c>$CFG{account_changes_max};$STATE{account_changes}=\@c;
 }
 $STATE{last_account_ok}=int($d->{last_account_ok}||0);
 if(ref($d->{ci_enrich_pending})eq'ARRAY'){
  my@q=grep{ref($_)eq'HASH'&&ref($_->{event})eq'HASH'}@{$d->{ci_enrich_pending}};
  splice@q,20 if@q>20;$STATE{ci_enrich_pending}=\@q;
 }
 $STATE{rss_seen}={%{$d->{rss_seen}}} if ref($d->{rss_seen})eq'HASH';
 $STATE{rss_etag}=$d->{rss_etag}//'';$STATE{rss_modified}=$d->{rss_modified}//'';
 $STATE{last_rss_ok}=int($d->{last_rss_ok}||0);$STATE{last_rss_title}=clean(repair_mojibake($d->{last_rss_title}//''));$STATE{last_rss_link}=clean($d->{last_rss_link}//'');
 $STATE{rss_id_version}=int($d->{rss_id_version}||0);$STATE{rss_text_version}=int($d->{rss_text_version}||0);
 $STATE{rss_digest}=clean($d->{rss_digest}//'');$STATE{stats_version}=int($d->{stats_version}||0);
 $STATE{ops_health_key}=clean($d->{ops_health_key}//'');$STATE{ops_health_since}=int($d->{ops_health_since}||0);$STATE{ops_health_alerted}=$d->{ops_health_alerted}?1:0;$STATE{ops_degraded_announced}=$d->{ops_degraded_announced}?1:0;
 $STATS{state_recoveries}++ if$recovered;

 # poll_new did not exist in early persistent stats. Every old poll_sent was
 # necessarily a newly announced fallback event, so this is a conservative
 # migration that makes historical counters coherent without resetting them.
 if($STATE{stats_version}<3){
  $STATS{poll_new}=$STATS{poll_sent} if$STATS{poll_new}<$STATS{poll_sent};
  $STATE{stats_version}=3;
 }
}
sub save_state {
 prune_state();my$saved=int(time);
 my$tmp="$CFG{state_file}.tmp.$$\.".int(time*1000);
 sysopen(my$fh,$tmp,O_WRONLY|O_CREAT|O_EXCL,0600) or do{$STATS{state_save_errors}++;$RUN{state_last_error}=clean($!);logmsg('WARN',"Cannot create state temp: $!");return 0};
 binmode $fh,':raw';
 my$ok=eval{
  print{$fh}encode_json({state_version=>11,version=>VERSION,saved_at=>$saved,%STATE,stats=>\%STATS}) or die"write: $!";
  $fh->flush or die"flush: $!";my$sync_ok=eval{$fh->sync};logmsg('WARN',"State fsync unavailable: ".clean($@||$!)) if !$sync_ok;
  close$fh or die"close: $!";1
 };
 if(!$ok){my$e=clean($@||$!);close$fh;unlink$tmp;$STATS{state_save_errors}++;$RUN{state_last_error}=$e;logmsg('WARN',"Cannot write state: $e");return 0}
 backup_current_state() if$CFG{state_backup};
 if(!rename$tmp,$CFG{state_file}){my$e=clean($!);unlink$tmp;$STATS{state_save_errors}++;$RUN{state_last_error}=$e;logmsg('WARN',"Cannot replace state: $e");return 0}
 $RUN{state_last_saved}=$saved;$RUN{state_loaded_from}='primary';$RUN{state_last_error}='';1;
}

# ── Event privacy / identity ─────────────────────────────────────────────────
my%PRIVATE_EVENT=map{($_=>1)}qw(code_scanning_alert dependabot_alert repository_vulnerability_alert secret_scanning_alert secret_scanning_alert_location secret_scanning_scan security_advisory security_and_analysis);
sub public_event { !$PRIVATE_EVENT{$_[0]} }
sub fingerprint {
 my($e)=@_;my$k=$e->{kind}//'generic';my$r=$e->{repo}//$CFG{repo};my@p;
 @p=($k,$r,$e->{ref},$e->{sha}) if$k eq'push';
 @p=($k,$r,$e->{id}) if!@p&&$k=~/^(?:issue_comment|review_comment|discussion_comment|commit_comment)$/;
 @p=($k,$r,$e->{action},$e->{actor}) if!@p&&$k eq'star';
 @p=($k,$r,$e->{action},$e->{number},$e->{id}) if!@p&&$k=~/^(?:issue|pr|discussion)$/;
 @p=($k,$r,$e->{id},$e->{attempt}) if!@p&&$k eq'ci_slow';
 @p=($k,$r,$e->{sha},$e->{ref}) if!@p&&$k eq'ci_missing';
 @p=($k,$r,$e->{scope},$e->{alert_at}) if!@p&&$k eq'ci_flaky';
 @p=($k,$r,$e->{action},$e->{id},$e->{attempt},$e->{conclusion}) if!@p&&$k=~/^(?:review|ci|workflow|workflow_job|check_run|check_suite|deployment|deployment_status)$/;
 @p=($k,$r,$e->{action},$e->{ref}) if!@p&&$k=~/^(?:create|delete|branch_protection)$/;
 @p=($k,$r,$e->{id},$e->{action}) if!@p&&defined($e->{id})&&$e->{id} ne'';
 @p=($k,$r,$e->{action},$e->{actor},$e->{number},$e->{ref},$e->{sha}) unless@p;
 sha256_hex(join("\x1f",map{clean($_//'')}@p));
}

# ── Event normalization ──────────────────────────────────────────────────────
sub object_event {
 my($kind,$action,$repo,$actor,$o,%x)=@_;
 +{kind=>$kind,action=>$action,repo=>$repo,actor=>$actor,
   number=>defined$x{number}?$o->{$x{number}}:undef,
   title=>defined$x{title}?$o->{$x{title}}:undef,
   id=>defined$x{id}?($o->{$x{id}}//$o->{id}):$o->{id},
   url=>defined$x{url}?$o->{$x{url}}:undef};
}
sub normalize_hook {
 my($name,$p)=@_;my$a=$p->{sender}{login}//'someone';my$r=$p->{repository}{full_name}//$CFG{repo};my$act=$p->{action}//'';
 return{kind=>'ping',repo=>$r,actor=>$a,title=>$p->{zen}//'pong'}if$name eq'ping';
 if($name eq'push'){(my$ref=$p->{ref}//'')=~s{^refs/heads/}{};my@c=@{$p->{commits}||[]};my$h=$p->{head_commit}||{};my$sha=$p->{after}||$h->{id}||'';return{kind=>'push',repo=>$r,actor=>$p->{pusher}{name}||$a,ref=>$ref,sha=>$sha,count=>defined$p->{size}?int$p->{size}:scalar@c,forced=>$p->{forced}?1:0,title=>$h->{message}||(@c?$c[-1]{message}:''),url=>$sha?"https://github.com/$r/commit/$sha":"https://github.com/$r"}}
 if($name eq'issues'){my$o=$p->{issue}||{};my$e=object_event('issue',$act,$r,$a,$o,number=>'number',title=>'title',id=>'updated_at',url=>'html_url');$e->{id}//=$o->{id};return$e}
 if($name eq'issue_comment'){my$o=$p->{issue}||{};my$c=$p->{comment}||{};return{kind=>'issue_comment',action=>$act,repo=>$r,actor=>$a,number=>$o->{number},title=>$o->{title},id=>$c->{id},url=>$c->{html_url}||$o->{html_url}}}
 if($name eq'pull_request'){my$o=$p->{pull_request}||{};my$x=$act;$x='merged'if$x eq'closed'&&$o->{merged};return{kind=>'pr',action=>$x,repo=>$r,actor=>$a,number=>$o->{number}||$p->{number},title=>$o->{title},id=>$o->{updated_at}||$o->{id},url=>$o->{html_url}}}
 if($name=~/^pull_request_review(?:_comment|_thread)?$/){my$pr=$p->{pull_request}||{};my$o=$name eq'pull_request_review'?($p->{review}||{}):$name eq'pull_request_review_comment'?($p->{comment}||{}):($p->{thread}||{});my$k=$name eq'pull_request_review'?'review':$name eq'pull_request_review_comment'?'review_comment':'review_thread';return{kind=>$k,action=>$name eq'pull_request_review'?($o->{state}||$act):$act,repo=>$r,actor=>$a,number=>$pr->{number},title=>$pr->{title},id=>$o->{id}||$pr->{updated_at},url=>$o->{html_url}||$pr->{html_url}}}
 if($name eq'release'){my$o=$p->{release}||{};return{kind=>'release',action=>$act,repo=>$r,actor=>$a,title=>$o->{name}||$o->{tag_name},ref=>$o->{tag_name},id=>$o->{id},url=>$o->{html_url}}}
 if($name eq'create'||$name eq'delete'){return{kind=>$name,action=>$p->{ref_type}||'ref',repo=>$r,actor=>$a,ref=>$p->{ref}||'',url=>"https://github.com/$r"}}
 if($name eq'fork'){my$o=$p->{forkee}||{};return{kind=>'fork',repo=>$r,actor=>$a,id=>$o->{full_name}||$o->{id},title=>$o->{full_name},url=>$o->{html_url}}}
 if($name eq'star'){return{kind=>'star',action=>$act,repo=>$r,actor=>$a,id=>$a,url=>"https://github.com/$r/stargazers"}}
 if($name eq'discussion'){my$o=$p->{discussion}||{};return{kind=>'discussion',action=>$act,repo=>$r,actor=>$a,number=>$o->{number},title=>$o->{title},id=>$o->{updated_at}||$o->{id},url=>$o->{html_url}}}
 if($name eq'discussion_comment'){my$d=$p->{discussion}||{};my$c=$p->{comment}||{};return{kind=>'discussion_comment',action=>$act,repo=>$r,actor=>$a,number=>$d->{number},title=>$d->{title},id=>$c->{id},url=>$c->{html_url}||$d->{html_url}}}
 if($name=~/^workflow_(?:run|job)$/){my$o=$p->{$name}||{};return{kind=>$name eq'workflow_run'?'ci':'workflow_job',action=>$act,repo=>$r,actor=>$a,title=>$o->{name},workflow_id=>$o->{workflow_id}||$p->{workflow}{id},detail=>$o->{display_title}||'',ref=>$o->{head_branch},sha=>$o->{head_sha}||'',id=>$o->{id},attempt=>int($o->{run_attempt}||1),status=>$o->{status}||$act,started_at=>iso8601_epoch($o->{run_started_at}||$o->{created_at}||''),completed_at=>iso8601_epoch($o->{updated_at}||''),conclusion=>$o->{conclusion},event=>$o->{event}||'',url=>$o->{html_url}}}
 if($name=~/^check_(?:run|suite)$/){my$o=$p->{$name}||{};return{kind=>$name,action=>$act,repo=>$r,actor=>$a,title=>$name eq'check_run'?$o->{name}:'check suite',ref=>$o->{head_branch}||$o->{check_suite}{head_branch},id=>$o->{id},conclusion=>$o->{conclusion},url=>$o->{html_url}||"https://github.com/$r/actions"}}
 if($name eq'status'){return{kind=>'commit_status',action=>$p->{state}||$act,repo=>$r,actor=>$a,title=>$p->{context}||'commit status',sha=>$p->{sha},id=>join(':',$p->{sha}//'',$p->{context}//'',$p->{state}//''),url=>$p->{target_url}||"https://github.com/$r/commits"}}
 if($name eq'deployment'){my$o=$p->{deployment}||{};return{kind=>'deployment',action=>$act||'created',repo=>$r,actor=>$a,title=>$o->{environment}||'deployment',ref=>$o->{ref},id=>$o->{id},url=>"https://github.com/$r/deployments"}}
 if($name eq'deployment_status'){my$o=$p->{deployment_status}||{};my$d=$p->{deployment}||{};return{kind=>'deployment_status',action=>$o->{state}||$act,repo=>$r,actor=>$a,title=>$o->{environment}||$d->{environment}||'deployment',ref=>$d->{ref},id=>$o->{id},conclusion=>$o->{state},url=>$o->{environment_url}||$o->{target_url}||"https://github.com/$r/deployments"}}
 if($name eq'repository'){my$o=$p->{repository}||{};return{kind=>'repository',action=>$act,repo=>$r,actor=>$a,id=>$o->{updated_at}||$o->{id},title=>$o->{description},url=>$o->{html_url}}}
 if($name eq'commit_comment'){my$o=$p->{comment}||{};return{kind=>'commit_comment',action=>$act,repo=>$r,actor=>$a,id=>$o->{id},url=>$o->{html_url}}}
 if($name eq'branch_protection_rule'){my$o=$p->{rule}||{};return{kind=>'branch_protection',action=>$act,repo=>$r,actor=>$a,ref=>$o->{name}||$o->{pattern}||'rule',id=>$o->{id},url=>"https://github.com/$r/settings/branches"}}
 if($name eq'label'){my$o=$p->{label}||{};return{kind=>'label',action=>$act,repo=>$r,actor=>$a,title=>$o->{name},id=>$o->{id},url=>"https://github.com/$r/labels"}}
 if($name eq'milestone'){my$o=$p->{milestone}||{};return{kind=>'milestone',action=>$act,repo=>$r,actor=>$a,number=>$o->{number},title=>$o->{title},id=>$o->{id},url=>$o->{html_url}||"https://github.com/$r/milestones"}}
 if($name eq'member'){my$o=$p->{member}||{};return{kind=>'member',action=>$act,repo=>$r,actor=>$a,title=>$o->{login},id=>$o->{id},url=>"https://github.com/$r"}}
 if($name eq'page_build'){my$o=$p->{build}||{};return{kind=>'pages',action=>$o->{status}||$act,repo=>$r,actor=>$a,title=>'GitHub Pages',id=>$o->{id},url=>"https://github.com/$r/deployments"}}
 if($name eq'public'){return{kind=>'public',action=>'public',repo=>$r,actor=>$a,id=>$p->{repository}{id},url=>$p->{repository}{html_url}||"https://github.com/$r"}}
 if($name eq'merge_group'){my$o=$p->{merge_group}||{};return{kind=>'merge_group',action=>$act,repo=>$r,actor=>$a,ref=>$o->{head_ref},sha=>$o->{head_sha},id=>$o->{head_sha},url=>"https://github.com/$r/pulls"}}
 {kind=>'generic',action=>$act,repo=>$r,actor=>$a,id=>$name,title=>$name,url=>"https://github.com/$r"};
}
sub normalize_poll {
 my($e)=@_;my$t=$e->{type}//'';my$p=$e->{payload}||{};my$r=$e->{repo}{name}||$CFG{repo};my$a=$e->{actor}{login}||'someone';
 if($t eq'PushEvent'){(my$ref=$p->{ref}//'')=~s{^refs/heads/}{};my@c=@{$p->{commits}||[]};my$n=defined$p->{distinct_size}?int$p->{distinct_size}:defined$p->{size}?int$p->{size}:scalar@c;my$sha=$p->{head}||(@c?$c[-1]{sha}:'');return{kind=>'push',repo=>$r,actor=>$a,ref=>$ref,sha=>$sha,count=>$n,title=>@c?$c[-1]{message}:'',url=>$sha?"https://github.com/$r/commit/$sha":"https://github.com/$r"}}
 if($t eq'IssuesEvent'){my$o=$p->{issue}||{};return{kind=>'issue',action=>$p->{action}||'',repo=>$r,actor=>$a,number=>$o->{number},title=>$o->{title},id=>$o->{updated_at}||$o->{id},url=>$o->{html_url}}}
 if($t eq'IssueCommentEvent'){my$o=$p->{issue}||{};my$c=$p->{comment}||{};return{kind=>'issue_comment',action=>$p->{action}||'',repo=>$r,actor=>$a,number=>$o->{number},title=>$o->{title},id=>$c->{id},url=>$c->{html_url}||$o->{html_url}}}
 if($t eq'PullRequestEvent'){my$o=$p->{pull_request}||{};my$x=$p->{action}||'';$x='merged'if$x eq'closed'&&$o->{merged};return{kind=>'pr',action=>$x,repo=>$r,actor=>$a,number=>$o->{number}||$p->{number},title=>$o->{title},id=>$o->{updated_at}||$o->{id},url=>$o->{html_url}}}
 if($t eq'PullRequestReviewEvent'){my$pr=$p->{pull_request}||{};my$o=$p->{review}||{};return{kind=>'review',action=>$o->{state}||$p->{action}||'',repo=>$r,actor=>$a,number=>$pr->{number},title=>$pr->{title},id=>$o->{id},url=>$o->{html_url}||$pr->{html_url}}}
 if($t eq'ReleaseEvent'){my$o=$p->{release}||{};return{kind=>'release',action=>$p->{action}||'',repo=>$r,actor=>$a,ref=>$o->{tag_name},title=>$o->{name}||$o->{tag_name},id=>$o->{id},url=>$o->{html_url}}}
 if($t eq'CreateEvent'||$t eq'DeleteEvent'){return{kind=>$t eq'CreateEvent'?'create':'delete',action=>$p->{ref_type}||'ref',repo=>$r,actor=>$a,ref=>$p->{ref}||'',url=>"https://github.com/$r"}}
 if($t eq'ForkEvent'){my$o=$p->{forkee}||{};return{kind=>'fork',repo=>$r,actor=>$a,id=>$o->{full_name}||$o->{id},title=>$o->{full_name},url=>$o->{html_url}}}
 return{kind=>'star',action=>'created',repo=>$r,actor=>$a,id=>$a,url=>"https://github.com/$r/stargazers"}if$t eq'WatchEvent';
 return{kind=>'wiki',repo=>$r,actor=>$a,id=>$e->{id},url=>"https://github.com/$r/wiki"}if$t eq'GollumEvent';
 if($t eq'CommitCommentEvent'){my$o=$p->{comment}||{};return{kind=>'commit_comment',repo=>$r,actor=>$a,id=>$o->{id},url=>$o->{html_url}}}
 {kind=>'generic',repo=>$r,actor=>$a,id=>$e->{id},title=>$t,url=>"https://github.com/$r"};
}

# ── Event display ────────────────────────────────────────────────────────────
sub state_color { my($s)=@_; $s eq'success'?paint(3,$s):$s=~/^(?:failure|error)$/?paint(4,$s):paint(14,$s||'updated') }
sub numbered { my($icon,$e,$noun,$color)=@_;my$a=paint(7,bold(irc_content($e->{actor}||'someone')));my$t=irc_short($e->{title},105);$icon.' '.tag().": $a ".paint($color,irc_content($e->{action})||'updated')." $noun ".paint(10,'#'.($e->{number}//'?')).($t?" — $t":'')." — ".clean($e->{url}||"https://github.com/$CFG{repo}") }
sub format_event {
 my($e)=@_;my$k=$e->{kind}||'generic';my$a=paint(7,bold(irc_content($e->{actor}||'someone')));my$u=clean($e->{url}||"https://github.com/$CFG{repo}");my$t=irc_short($e->{title},105);my$x=irc_content($e->{action});
 if($k eq'push'){my$n=int($e->{count}||0);my$ref=paint(10,irc_content($e->{ref}||'repository'));my$force=$e->{forced}?' '.paint(4,'[force]'):'';if($n){return icon('push').' '.tag().": $a ".paint(3,'pushed')." $n commit".($n==1?'':'s')." to $ref$force".($t?" — $t":'')." — $u"}my$sha=$e->{sha}?paint(14,substr(clean($e->{sha}),0,7)):'';return icon('push').' '.tag().": $a ".paint(3,'updated')." $ref".($sha?" @ $sha":'')."$force".($t?" — $t":'')." — $u"}
 return numbered(icon('issue'),$e,'issue',3)if$k eq'issue'; if($k eq'issue_comment'){my$e2={%$e,action=>'commented'};return numbered(icon('comment'),$e2,'on issue',3)} return numbered(icon('pr'),$e,'PR',6)if$k eq'pr';
 if($k eq'review_comment'){my$e2={%$e,action=>'commented'};return numbered(icon('comment'),$e2,'on PR',6)}
 return numbered(icon('review'),$e,$k eq'review_thread'?'review thread on PR':'PR',6)if$k=~/^(?:review|review_thread)$/;
 return icon('release').' '.tag().": $a ".paint(3,$x||'published').' release '.paint(10,irc_content($e->{ref}||$t||'?'))." — $u"if$k eq'release';
 if($k eq'create'||$k eq'delete'){return icon($k eq'create'?'create':'delete').' '.tag().": $a ".paint($k eq'create'?3:4,$k eq'create'?'created':'deleted').' '.clean($x||'ref').' '.paint(10,irc_content($e->{ref}||'?'))." — $u"}
 return icon('fork').' '.tag().": $a ".paint(3,'forked').' the repository'.($t?' as '.paint(10,$t):'')." — $u"if$k eq'fork';
 return icon('star').' '.tag().": $a ".($x eq'deleted'?paint(14,'unstarred'):paint(8,'starred')).' '.paint(10,$e->{repo}||$CFG{repo})." — $u"if$k eq'star';
 return numbered(icon('discussion'),$e,$k eq'discussion_comment'?'discussion comment':'discussion',6)if$k=~/^discussion(?:_comment)?$/;
 if($k eq'ci_flaky'){my$ref=$e->{ref}?paint(10,irc_content($e->{ref})):'repository';my$n=int($e->{transitions}||0);my$win=duration_text(int($e->{window}||0));return icon('ci').' '.paint(8,bold('CI FLAKY')).': '.paint(10,$t||'GitHub Actions').' — '.paint(8,$n.' state changes').' in '.$win.' on '.$ref." — $u"}
 if($k eq'ci_slow'){my$ref=$e->{ref}?paint(10,irc_content($e->{ref})):'repository';my$dur=duration_text(time-int($e->{started_at}||time));my$sha=$e->{sha}?paint(14,substr(clean($e->{sha}),0,7)):'';return icon('ci').' '.paint(8,bold('CI SLOW')).': '.paint(10,$t||'GitHub Actions').' — running '.paint(8,$dur).' on '.$ref.($sha?" @ $sha":'')." — $u"}
 if($k eq'ci_missing'){my$ref=$e->{ref}?paint(10,irc_content($e->{ref})):'repository';my$dur=duration_text(time-int($e->{started_at}||time));my$sha=$e->{sha}?paint(14,substr(clean($e->{sha}),0,7)):'';return icon('ci').' '.paint(4,bold('CI MISSING')).': no workflow seen after '.paint(4,$dur).' on '.$ref.($sha?" @ $sha":'')." — $u"}
 if($k eq'ci'){my$c=lc(clean($e->{conclusion})||'unknown');my$bad=ci_bad($c);my$recovery=$e->{recovery}?1:0;my$state=$recovery?paint(3,'RECOVERED'):paint($bad?4:3,uc($c));my$ref=$e->{ref}?paint(10,irc_content($e->{ref})):'repository';my$sha=$e->{sha}?paint(14,substr(clean($e->{sha}),0,7)):'';my$d=irc_short($e->{detail}||'',85);my$jobs=$e->{failed_jobs}?' — jobs: '.paint(4,irc_short($e->{failed_jobs},80)):'';my$attempt=int($e->{attempt}||1)>1?' — attempt '.paint(8,int($e->{attempt})) :'';my$dur='';if($e->{started_at}&&$e->{completed_at}&&$e->{completed_at}>=$e->{started_at}){$dur=' — '.paint(14,duration_text($e->{completed_at}-$e->{started_at}))}return icon('ci').' '.paint($bad?4:3,bold('CI')).': '.paint(10,$t||'GitHub Actions').' — '.$state.' on '.$ref.($sha?" @ $sha":'').$attempt.$dur.($d&&$d ne$t?" — $d":'').$jobs." — $u"}
 if($k=~/^(?:workflow|workflow_job)$/){return icon('workflow').' '.tag().': workflow '.paint(10,$t||'?').' — '.state_color(clean($e->{conclusion})||$x).($e->{ref}?' on '.paint(10,irc_content($e->{ref})):'')." — $u"}
 if($k=~/^check_(?:run|suite)$/){return icon('check').' '.tag().': '.paint(10,$t||'check').' — '.state_color(clean($e->{conclusion})||$x).($e->{ref}?' on '.paint(10,irc_content($e->{ref})):'')." — $u"}
 if($k eq'commit_status'){return icon('status').' '.tag().': '.paint(10,$t||'commit status').' — '.state_color($x).($e->{sha}?' @ '.paint(10,substr(clean($e->{sha}),0,7)):'')." — $u"}
 if($k=~/^deployment(?:_status)?$/){return icon('deploy').' '.tag().': '.paint(10,$t||'deployment').' — '.state_color($x||($k eq'deployment'?'created':'updated')).($e->{ref}?' on '.paint(10,irc_content($e->{ref})):'')." — $u"}
 return icon('repo').' '.tag().": $a ".paint(6,$x||'updated')." repository settings — $u"if$k eq'repository';
 return icon('wiki').' '.tag().": $a ".paint(6,'updated')." the wiki — $u"if$k eq'wiki';
 return icon('pin').' '.tag().": $a ".paint(6,'commented')." on a commit — $u"if$k eq'commit_comment';
 return icon('protect').' '.tag().": $a ".paint(6,$x||'updated').' branch protection '.paint(10,clean($e->{ref}||'rule'))." — $u"if$k eq'branch_protection';
 return icon('label').' '.tag().": $a ".paint(6,$x||'updated').' label '.paint(10,$t||'?')." — $u"if$k eq'label';
 return icon('milestone').' '.tag().": $a ".paint(6,$x||'updated').' milestone '.paint(10,$t||'?')." — $u"if$k eq'milestone';
 return icon('member').' '.tag().": $a ".paint(6,$x||'updated').' collaborator '.paint(10,$t||'?')." — $u"if$k eq'member';
 return icon('pages').' '.tag().': GitHub Pages — '.state_color($x)." — $u"if$k eq'pages';
 return icon('repo').' '.tag().": $a made ".paint(10,$e->{repo}||$CFG{repo})." public — $u"if$k eq'public';
 return icon('merge').' '.tag().": $a ".paint(6,$x||'updated').' merge group'.($e->{ref}?' '.paint(10,irc_content($e->{ref})):'')." — $u"if$k eq'merge_group';
 icon('generic').' '.tag().": $a triggered ".paint(10,irc_content($t||$k)).($x?" ($x)":'')." — $u";
}

# ── GitHub REST ──────────────────────────────────────────────────────────────
sub api_headers { my($token,$etag)=@_;my%h=(Accept=>'application/vnd.github+json','X-GitHub-Api-Version'=>API_VERSION);$h{Authorization}="Bearer $token"if defined$token&&$token ne'';$h{'If-None-Match'}=$STATE{etag}if$etag&&$STATE{etag}ne'';\%h }
sub update_rate { my($r)=@_;return unless$r&&ref$r eq'HASH';$RUN{rate_limit}=$r->{headers}{'x-ratelimit-limit'}//$RUN{rate_limit};$RUN{rate_remaining}=$r->{headers}{'x-ratelimit-remaining'}//$RUN{rate_remaining};$RUN{rate_reset}=$r->{headers}{'x-ratelimit-reset'}//$RUN{rate_reset} }
sub rate_limit_message {
 my($r)=@_;return q{} unless$r&&ref$r eq'HASH';
 my$body=$r->{content}//q{};my$d=eval{decode_json($body)};
 return clean($d->{message}//q{}) if$d&&ref$d eq'HASH';
 clean(substr($body,0,500));
}
sub note_github_success {
 my($r)=@_;return unless$r&&ref$r eq'HASH';
 my$s=int($r->{status}||0);
 $RUN{rate_secondary_streak}=0 if($s>=200&&$s<300)||$s==304;
}
sub note_rate_limit {
 my($r,$where,$quiet)=@_;return 0 unless$r&&ref$r eq'HASH';update_rate($r);
 my$now=time;my$until=0;my$why='';
 my$retry=$r->{headers}{'retry-after'};
 if(defined$retry&&$retry=~/^\d+$/&&int($retry)>0){
  $until=$now+int($retry)+$CFG{rate_safety};$why="Retry-After ${retry}s";
 }elsif(($RUN{rate_remaining}//'')=~/^0$/&&($RUN{rate_reset}//'')=~/^\d+$/&&$RUN{rate_reset}>$now){
  $until=int($RUN{rate_reset})+$CFG{rate_safety};$why='primary rate reset';
 }else{
  my$status=int($r->{status}||0);my$msg=lc(rate_limit_message($r));
  if($status==429||($status==403&&$msg=~/(?:secondary rate limit|rate limit|abuse)/)){
   my$n=++$RUN{rate_secondary_streak};$n=5 if$n>5;
   my$delay=60*(2**($n-1));$delay=$CFG{secondary_max} if$delay>$CFG{secondary_max};
   $until=$now+$delay+$CFG{rate_safety};$why="secondary rate limit backoff ${delay}s";
  }
 }
 return 0 unless$until>$now;
 $STATS{rate_limit_hits}++;
 if($until>$RUN{rate_block_until}){
  $RUN{rate_block_until}=$until;$RUN{rate_block_reason}=clean(($where||'GitHub').": $why");
  logmsg('WARN',"GitHub REST paused for ".int($until-$now)."s — $RUN{rate_block_reason}") unless$quiet;
 }
 int($until-$now);
}
sub github_rest_allowed {
 my$until=$RUN{rate_block_until}||0;
 if($until&&time>=$until){$RUN{rate_block_until}=0;$RUN{rate_block_reason}='';return 1}
 time>=$until;
}
sub github_limit_text { github_rest_allowed()?'ready':'paused '.rate_resume_text() }
sub auth_short { $RUN{auth_state}eq'verified'&&$RUN{auth_events}eq'ok'?'TOKEN OK':$RUN{auth_state}eq'rejected'?'TOKEN BAD':$RUN{auth_state}eq'anonymous'?'ANONYMOUS':$RUN{auth_state}eq'verified'?'TOKEN LIMITED':'AUTH ERROR' }
sub auth_check {
 $RUN{auth_error}='';$RUN{auth_login}='';$RUN{auth_events}='unchecked';$RUN{auth_actions}='unchecked';
 if($CFG{token}eq''){
  $RUN{auth_state}='anonymous';$RUN{token}='';$RUN{auth_events}='public';$RUN{auth_actions}='public';
  logmsg('INFO','GitHub auth: ANONYMOUS — token not configured; public fallbacks available');return 1
 }
 my$r=eval{$HTTP->get('https://api.github.com/user',{headers=>api_headers($CFG{token},0)})};
 if(!$r||ref$r ne'HASH'){
  $RUN{auth_state}='error';$RUN{auth_error}=$@||'request failed';$RUN{token}='';$RUN{auth_actions}='public';
  logmsg('WARN','GitHub auth check failed; anonymous fallback enabled');return 0
 }
 update_rate($r);
 if($r->{status}!=200){
  $RUN{auth_state}=$r->{status}==401?'rejected':'error';$RUN{auth_error}="HTTP $r->{status} $r->{reason}";
  $RUN{token}='';$RUN{auth_actions}='public';
  logmsg('WARN',"GitHub token rejected/check failed — $RUN{auth_error}; anonymous fallback enabled");return 0
 }
 my$u=eval{decode_json($r->{content})};
 $RUN{auth_login}=$u&&ref$u eq'HASH'?clean($u->{login}//''):'authenticated-user';
 $RUN{auth_login}||='authenticated-user';$RUN{auth_state}='verified';

 my$e=eval{$HTTP->get("https://api.github.com/repos/$CFG{repo}/events?per_page=1",{headers=>api_headers($CFG{token},0)})};
 if(!$e||ref$e ne'HASH'){
  $RUN{auth_events}='error';$RUN{token}='';$RUN{auth_actions}='public';
  logmsg('WARN',"GitHub token verified as $RUN{auth_login}, events probe failed; anonymous fallback enabled");return 0
 }
 update_rate($e);
 if($e->{status}!=200){
  $RUN{auth_events}="HTTP $e->{status} $e->{reason}";$RUN{token}='';$RUN{auth_actions}='public';
  logmsg('WARN',"GitHub token verified as $RUN{auth_login}, repo events denied; anonymous fallback enabled");return 0
 }
 $RUN{auth_events}='ok';$RUN{token}=$CFG{token};

 if($CFG{actions_enabled}){
  my$a=eval{$HTTP->get("https://api.github.com/repos/$CFG{repo}/actions/runs?per_page=1",{headers=>api_headers($CFG{token},0)})};
  if($a&&ref($a)eq'HASH'&&$a->{status}==200){
   update_rate($a);$RUN{auth_actions}='ok';$RUN{actions_auth_mode}='authenticated';
  }else{
   $RUN{auth_actions}=$a&&ref($a)eq'HASH'?"HTTP $a->{status} $a->{reason}":'error';
   $RUN{actions_auth_mode}='anonymous-fallback';
   logmsg('WARN',"GitHub token is valid but Actions probe is $RUN{auth_actions}; CI watcher will retry public access");
  }
 }else{$RUN{auth_actions}='off'}

 logmsg('INFO',"GitHub auth: TOKEN VERIFIED — login=$RUN{auth_login} — repo=$CFG{repo} — events=OK — actions=$RUN{auth_actions} — rate=$RUN{rate_remaining}/$RUN{rate_limit}");
 1;
}

sub next_link {
 my($r)=@_;return q{} unless$r&&ref$r eq'HASH';
 my$l=$r->{headers}{link}//q{};
 return$1 if$l=~/<([^>]+)>\s*;\s*rel="next"/i;
 q{};
}
sub fetch_events_page {
 my($url,$conditional)=@_;return unless github_rest_allowed();
 $STATS{poll_runs}++ if$conditional;$STATS{poll_pages}++;
 my$r=eval{$HTTP->get($url,{headers=>api_headers($RUN{token},$conditional?1:0)})};
 if(!$r||ref$r ne'HASH'){$RUN{last_api_error}=$@||'request failed';$STATS{poll_errors}++;return}
 my$limited=note_rate_limit($r,'Events');note_github_success($r) unless$limited;
 if($conditional){
  my$min=int($r->{headers}{'x-poll-interval'}||60);$RUN{poll_min}=$min<60?60:$min;
 }
 if($r->{status}==304){$RUN{last_api_error}='';$RUN{last_api_ok}=time;$STATS{poll_not_modified}++;return{items=>[],next=>'',not_modified=>1}}
 if(!$r->{success}){$RUN{last_api_error}="HTTP $r->{status} $r->{reason}";$STATS{poll_errors}++;return}
 my$ev=eval{decode_json($r->{content})};if(!$ev||ref$ev ne'ARRAY'){$RUN{last_api_error}='invalid JSON';$STATS{poll_errors}++;return}
 $STATE{etag}=$r->{headers}{etag}//$STATE{etag} if$conditional;
 $RUN{last_api_error}='';$RUN{last_api_ok}=time;
 {items=>$ev,next=>next_link($r),not_modified=>0};
}
sub process_events_batch {
 my($fresh,$ev)=@_;my%once;
 my@uniq=grep{!defined($_->{id})||!$once{$_->{id}}++}@$ev;$ev=\@uniq;
 if($$fresh){
  $STATE{event_seen}{$_->{id}}=time for grep{defined$_->{id}}@$ev;$$fresh=0;save_state();return 1;
 }
 my@new=grep{defined$_->{id}&&!$STATE{event_seen}{$_->{id}}}@$ev;$STATS{poll_new}+=scalar@new;
 for my$raw(reverse@new){
  my$n=normalize_poll($raw);kick_actions()if($n->{kind}||'')eq'push';my$f=fingerprint($n);
  if(!$STATE{fingerprints}{$f}){expect_ci_for_push($n)if($n->{kind}||'')eq'push';$STATE{fingerprints}{$f}=time;enqueue(format_event($n),'poll',1)}
  $STATE{event_seen}{$raw->{id}}=time;
 }
 $STATE{event_seen}{$_->{id}}=time for grep{defined$_->{id}}@$ev;save_state();1;
}
sub reconcile {
 my($fresh)=@_;return 0 unless$CFG{poll_enabled}&&time>=$RUN{next_poll}&&github_rest_allowed()&&!$RUN{events_scan};
 my$res=fetch_events_page($CFG{api_url},1);$RUN{next_poll}=time+maxn($CFG{reconcile},$RUN{poll_min});return 1 unless$res;
 return 1 if$res->{not_modified};
 my$ev=$res->{items};
 return process_events_batch($fresh,$ev) if$$fresh;
 my$known=grep{defined$_->{id}&&$STATE{event_seen}{$_->{id}}}@$ev;
 if(!$known&&@$ev>=100&&$res->{next}&&$CFG{events_max_pages}>1){
  $RUN{events_scan}={items=>[@$ev],next=>$res->{next},pages=>1};return 1;
 }
 process_events_batch($fresh,$ev);
}
sub continue_events_scan {
 my($fresh)=@_;my$s=$RUN{events_scan};return 0 unless$s&&github_rest_allowed();
 my$res=fetch_events_page($s->{next},0);
 if(!$res){$RUN{events_scan}=undef;return 1}
 push@{$s->{items}},@{$res->{items}};$s->{pages}++;
 my$known=grep{defined$_->{id}&&$STATE{event_seen}{$_->{id}}}@{$res->{items}};
 my$done=$known||!$res->{next}||$s->{pages}>=$CFG{events_max_pages};
 if(!$done){$s->{next}=$res->{next};return 1}
 if(!$known&&$res->{next}&&$s->{pages}>=$CFG{events_max_pages}){
  $STATS{poll_gap}++;logmsg('WARN',"Events catch-up reached page limit $CFG{events_max_pages}; oldest activity may require a larger window");
 }
 my@all=@{$s->{items}};$RUN{events_scan}=undef;process_events_batch($fresh,\@all);1;
}


# ── GitHub Actions CI ────────────────────────────────────────────────────────
sub actions_state { !$CFG{actions_enabled}?'off':!github_rest_allowed()?'limited':$RUN{actions_error}?'error':$STATE{last_actions_ok}?'online':'waiting' }
sub ci_bad {
 my($c)=@_;$c=lc(clean($c));
 $c=~/^(?:failure|cancelled|timed_out|action_required|startup_failure|stale)$/ ? 1 : 0;
}
sub action_key {
 my($r)=@_;join(':',int($r->{id}||0),int($r->{run_attempt}||1),clean($r->{conclusion}||''));
}
sub ci_scope_key {
 my($e)=@_;my$branch=lc(clean($e->{ref}||'repository'));
 return 'id:'.int($e->{workflow_id})."\x1f".$branch if int($e->{workflow_id}||0)>0;
 'name:'.lc(clean($e->{title}||'workflow'))."\x1f".$branch;
}
sub ci_legacy_scope_key {
 my($e)=@_;lc(clean($e->{title}||'workflow'))."\x1f".lc(clean($e->{ref}||'repository'));
}
sub ci_track_state {
 my($e)=@_;return 0 unless($e->{kind}||'')eq'ci';
 my$key=ci_scope_key($e);my$legacy=ci_legacy_scope_key($e);my$c=lc(clean($e->{conclusion}||''));
 if($key ne$legacy&&$STATE{ci_bad_state}{$legacy}&&!$STATE{ci_bad_state}{$key}){
  $STATE{ci_bad_state}{$key}=delete$STATE{ci_bad_state}{$legacy};
 }
 if(ci_bad($c)){
  $STATE{ci_bad_state}{$key}={
   run_id=>int($e->{id}||0),at=>int(time),conclusion=>$c,
   name=>clean($e->{title}||'workflow'),branch=>clean($e->{ref}||'repository'),url=>clean($e->{url}||''),attempt=>int($e->{attempt}||1),
   duration=>($e->{started_at}&&$e->{completed_at}&&$e->{completed_at}>=$e->{started_at})?int($e->{completed_at}-$e->{started_at}):0,
  };
  delete$STATE{ci_bad_state}{$legacy} if$key ne$legacy;
  return 0;
 }
 if($c eq'success'&&($STATE{ci_bad_state}{$key}||$STATE{ci_bad_state}{$legacy})){
  delete$STATE{ci_bad_state}{$key};delete$STATE{ci_bad_state}{$legacy} if$key ne$legacy;
  $e->{recovery}=1;
  return 1;
 }
 0;
}
sub current_ci_failures {
 my@f;
 for my$k(keys%{$STATE{ci_bad_state}}){
  my$v=$STATE{ci_bad_state}{$k};next unless ref($v)eq'HASH';
  my($name,$branch)=($v->{name}//'', $v->{branch}//'');
  if($name eq''){
   if($k=~/^name:([^\x1f]+)\x1f(.*)$/){($name,$branch)=($1,$2)}
   elsif($k=~/^id:(\d+)\x1f(.*)$/){($name,$branch)=("workflow $1",$2)}
  }
  push@f,{name=>clean($name||'workflow'),branch=>clean($branch||'repository'),
          conclusion=>clean($v->{conclusion}||'failure'),at=>int($v->{at}||0),
          url=>clean($v->{url}||''),run_id=>int($v->{run_id}||0),attempt=>int($v->{attempt}||1),duration=>int($v->{duration}||0)};
 }
 sort{($b->{at}||0)<=>($a->{at}||0)}@f;
}
sub current_ci_failure_count { my@f=current_ci_failures();scalar@f }

sub track_ci_flap {
 my($e,$allow_alert)=@_;return 0 unless$CFG{actions_flaky_window}>0&&$e&&($e->{kind}||'')eq'ci'&&($e->{action}||'completed')eq'completed';
 my$c=lc(clean($e->{conclusion}||''));return 0 unless$c ne'';
 my$key=ci_scope_key($e);my$now=int(time);my$v=$STATE{ci_flap_state}{$key};
 $v={} unless ref($v)eq'HASH';
 my$prev=lc(clean($v->{last_conclusion}||''));
 my@t=ref($v->{transitions})eq'ARRAY'?map{int($_||0)}@{$v->{transitions}}:();
 @t=grep{$_&&$_>=$now-$CFG{actions_flaky_window}}@t;
 push@t,$now if$prev ne''&&$prev ne$c;
 $v->{last_conclusion}=$c;$v->{last_at}=$now;$v->{transitions}=\@t;
 $v->{name}=clean($e->{title}||$v->{name}||'workflow');$v->{branch}=clean($e->{ref}||$v->{branch}||'repository');$v->{url}=clean($e->{url}||$v->{url}||'');
 $STATE{ci_flap_state}{$key}=$v;
 return 0 unless$allow_alert&&@t>=$CFG{actions_flaky_transitions};
 my$last_alert=int($v->{alerted_at}||0);
 return 0 if$last_alert&&$last_alert>=$now-$CFG{actions_flaky_window};
 $v->{alerted_at}=$now;$STATS{actions_flaky_alerts}++;
 my$notice={kind=>'ci_flaky',repo=>$CFG{repo},title=>$v->{name},ref=>$v->{branch},url=>$v->{url}||"https://github.com/$CFG{repo}/actions",scope=>$key,alert_at=>$now,transitions=>scalar(@t),window=>$CFG{actions_flaky_window}};
 my$f=fingerprint($notice);
 if(!$STATE{fingerprints}{$f}){$STATE{fingerprints}{$f}=time;enqueue(format_event($notice),'actions',1)}
 1;
}
sub current_ci_flaky {
 return() unless$CFG{actions_flaky_window}>0;my$now=int(time);my@x;
 for my$k(keys%{$STATE{ci_flap_state}}){
  my$v=$STATE{ci_flap_state}{$k};next unless ref($v)eq'HASH';
  my@t=ref($v->{transitions})eq'ARRAY'?grep{$_&&$_>=$now-$CFG{actions_flaky_window}}@{$v->{transitions}}:();
  next unless@t>=$CFG{actions_flaky_transitions};
  push@x,{name=>clean($v->{name}||'workflow'),branch=>clean($v->{branch}||'repository'),url=>clean($v->{url}||''),transitions=>scalar(@t),last_at=>int($v->{last_at}||0)};
 }
 sort{($b->{last_at}||0)<=>($a->{last_at}||0)}@x;
}
sub current_ci_flaky_count { my@x=current_ci_flaky();scalar@x }

sub actions_request {
 my($url)=@_;return unless github_rest_allowed();
 my$token=$RUN{actions_auth_mode}eq'anonymous-fallback'?'':$RUN{token};
 my$r=eval{$HTTP->get($url,{headers=>api_headers($token,0)})};
 if($r&&ref($r)eq'HASH'){
  my$limited=note_rate_limit($r,'Actions');note_github_success($r) unless$limited;
  if($token ne''&&($r->{status}==401||$r->{status}==403)&&!$limited){
   $RUN{actions_auth_mode}='anonymous-fallback';
   logmsg('WARN',"GitHub Actions authenticated access rejected ($r->{status}); next request will use public access");
  }
 }
 $r;
}
sub enrich_failed_jobs {
 my($e)=@_;return 0 unless$CFG{actions_enrich}&&ci_bad($e->{conclusion})&&int($e->{id}||0)>0;
 my$url="https://api.github.com/repos/$CFG{repo}/actions/runs/".int($e->{id})."/jobs?filter=latest&per_page=100";
 my$r=actions_request($url);return 0 unless$r&&ref($r)eq'HASH'&&$r->{success};
 my$d=eval{decode_json($r->{content})};return 0 unless$d&&ref($d)eq'HASH'&&ref($d->{jobs})eq'ARRAY';
 my@bad=grep{ci_bad($_->{conclusion})}@{$d->{jobs}};
 my@names=map{irc_content($_->{name}||'job')}@bad;
 splice@names,$CFG{actions_job_max} if@names>$CFG{actions_job_max};
 if(@names){$e->{failed_jobs}=join(', ',@names);$STATS{actions_enriched}++;return 1}
 0;
}
sub queue_ci_announcement {
 my($e)=@_;my$f=fingerprint($e);return 0 if$STATE{fingerprints}{$f};
 $STATE{fingerprints}{$f}=time;
 if($CFG{actions_enrich}&&ci_bad($e->{conclusion})){
  if(@{$STATE{ci_enrich_pending}}>=20){
   $STATS{actions_enrich_skipped}++;enqueue(format_event($e),'actions',1);save_state();return 1;
  }
  push@{$STATE{ci_enrich_pending}},{event=>$e,created=>int(time)};
  save_state();return 1;
 }
 enqueue(format_event($e),'actions',1);1;
}
sub flush_ci_enrichment_pending {
 return 0 unless@{$STATE{ci_enrich_pending}};
 my$item=shift@{$STATE{ci_enrich_pending}};my$e=$item->{event};
 $STATS{actions_enrich_skipped}++;enqueue(format_event($e),'actions',1);save_state();1;
}
sub process_ci_enrichment {
 return 0 unless@{$STATE{ci_enrich_pending}};
 return flush_ci_enrichment_pending() unless github_rest_allowed();
 my$item=shift@{$STATE{ci_enrich_pending}};my$e=$item->{event};
 enrich_failed_jobs($e);enqueue(format_event($e),'actions',1);save_state();1;
}
sub normalize_action_run {
 my($r)=@_;my$sha=clean($r->{head_sha}||'');my$status=clean($r->{status}||'completed');
 +{
  kind=>'ci',action=>$status,repo=>$CFG{repo},
  actor=>$r->{actor}{login}||$r->{triggering_actor}{login}||'github-actions',
  title=>$r->{name}||$r->{display_title}||'GitHub Actions',
  workflow_id=>$r->{workflow_id}||0,
  detail=>$r->{display_title}||'',ref=>$r->{head_branch}||'',
  sha=>$sha,id=>$r->{id},attempt=>int($r->{run_attempt}||1),
  status=>$status,started_at=>iso8601_epoch($r->{run_started_at}||$r->{created_at}||''),
  completed_at=>iso8601_epoch($r->{updated_at}||''),conclusion=>$r->{conclusion}||'',event=>$r->{event}||'',
  url=>$r->{html_url}||"https://github.com/$CFG{repo}/actions",
 };
}
sub record_ci_run_history {
 my($runs)=@_;return 0 unless ref($runs)eq'ARRAY';my%seen=map{($_->{key}=>1)}grep{ref($_)eq'HASH'}@{$STATE{ci_run_history}};my$added=0;
 for my$r(@$runs){next unless ref($r)eq'HASH'&&clean($r->{status}||'')eq'completed';my$e=normalize_action_run($r);next unless int($e->{id}||0)>0&&clean($e->{conclusion}||'')ne'';
  my$at=int($e->{completed_at}||time);my$duration=$e->{started_at}&&$at>=$e->{started_at}?int($at-$e->{started_at}):0;
  my$x=normalize_ci_history_entry({id=>$e->{id},attempt=>$e->{attempt},workflow_id=>$e->{workflow_id},scope=>ci_scope_key($e),name=>$e->{title},branch=>$e->{ref},conclusion=>$e->{conclusion},at=>$at,started_at=>$e->{started_at},duration=>$duration,sha=>$e->{sha},url=>$e->{url}});
  next unless$x&&!$seen{$x->{key}}++;push@{$STATE{ci_run_history}},$x;$added++;
 }
 if($added){my$now=time;@{$STATE{ci_run_history}}=sort{($a->{at}||0)<=>($b->{at}||0)}grep{($_->{at}||0)>=$now-MAX_CI_DAYS*86400}@{$STATE{ci_run_history}};splice@{$STATE{ci_run_history}},0,@{$STATE{ci_run_history}}-MAX_CI_RUNS if@{$STATE{ci_run_history}}>MAX_CI_RUNS}
 $added;
}
sub ci_percentile {
 my($values,$percent)=@_;my@v=sort{$a<=>$b}grep{defined&&$_>=0}@{$values||[]};return 0 unless@v;
 my$i=int($percent*@v+.999999)-1;$i=0 if$i<0;$i=$#v if$i>$#v;int($v[$i]);
}
sub ci_reliability_summary {
 my($now)=@_;$now=int($now||time);my$cut=$now-MAX_CI_DAYS*86400;
 my@runs=sort{($a->{at}||0)<=>($b->{at}||0)}grep{ref($_)eq'HASH'&&($_->{at}||0)>=$cut}@{$STATE{ci_run_history}};
 my($success,$failed,$neutral)=(0,0,0);my(@durations,@resolved);my%open;
 for my$r(@runs){my$c=lc(clean($r->{conclusion}||''));if($c eq'success'){$success++}elsif(ci_bad($c)){$failed++}else{$neutral++}
  push@durations,int($r->{duration})if int($r->{duration}||0)>0;
  my$scope=$r->{scope}||'unknown';
  if(ci_bad($c)){
   $open{$scope}||={scope=>$scope,name=>$r->{name},branch=>$r->{branch},opened_at=>int($r->{at}),failures=>0,first_url=>$r->{url}};
   $open{$scope}{failures}++;$open{$scope}{last_failure_at}=int($r->{at});$open{$scope}{last_url}=$r->{url};next;
  }
  if($c eq'success'&&$open{$scope}){my$x=delete$open{$scope};$x->{resolved_at}=int($r->{at});$x->{duration}=$x->{resolved_at}-$x->{opened_at};$x->{recovery_url}=$r->{url};push@resolved,$x if$x->{duration}>=0}
 }
 my$decisive=$success+$failed;my$rate=$decisive?int($success*1000/$decisive+.5)/10:0;
 my@mttr=map{int($_->{duration}||0)}@resolved;my$mttr_total=0;$mttr_total+=$_ for@mttr;my$mttr=@mttr?int($mttr_total/@mttr+.5):0;my$longest=@mttr?(sort{$b<=>$a}@mttr)[0]:0;
 my$green=0;for my$r(reverse@runs){my$c=lc(clean($r->{conclusion}||''));next unless$c eq'success'||ci_bad($c);last if ci_bad($c);$green++}
 my@active=current_ci_failures();my$state=!$CFG{actions_enabled}?'off':!$decisive?'waiting':@active?'degraded':$rate>=95?'stable':'watch';
 my$first=@runs?int($runs[0]{at}||0):0;my$last=@runs?$runs[-1]:{};my@recent=reverse@runs;splice@recent,10 if@recent>10;@resolved=reverse sort{($a->{resolved_at}||0)<=>($b->{resolved_at}||0)}@resolved;splice@resolved,10 if@resolved>10;
 +{state=>$state,window_days=>MAX_CI_DAYS,coverage_days=>$first?int(($now-$first)/86400)+1:0,runs=>scalar@runs,decisive_runs=>$decisive,success=>$success,failed=>$failed,neutral=>$neutral,pass_rate=>$rate,
   active_incidents=>scalar@active,resolved_incidents=>scalar@mttr,mttr_seconds=>$mttr,longest_recovery_seconds=>$longest,p50_duration_seconds=>ci_percentile(\@durations,.50),p95_duration_seconds=>ci_percentile(\@durations,.95),green_streak=>$green,
   latest=>{%$last},active=>[map{{%$_}}@active],recent=>[map{{%$_}}@recent],resolved=>[map{{%$_}}@resolved]};
}
sub ci_reliability_payload { my$s=ci_reliability_summary();+{%$s,retained_runs=>scalar(@{$STATE{ci_run_history}}),retention=>{days=>MAX_CI_DAYS,max_runs=>MAX_CI_RUNS}} }
sub update_running_ci_event {
 my($e,$allow_slow)=@_;return 0 unless$e&&($e->{kind}||'')eq'ci'&&int($e->{id}||0)>0;
 note_ci_sha_seen($e->{sha});my$cleared=clear_ci_expectation($e->{sha});
 my$id=int($e->{id});my$status=lc(clean($e->{status}||$e->{action}||''));
 if($status eq'completed'||clean($e->{conclusion}||'')ne''){
  my$had=delete$STATE{ci_running}{$id};delete$STATE{ci_slow_seen}{$id};return$had?1:0;
 }
 return 0 unless$status=~/^(?:queued|requested|waiting|pending|in_progress)$/;
 my$now=int(time);my$old=$STATE{ci_running}{$id};
 my$started=int($e->{started_at}||0);$started=int($old->{started_at}||0)if!$started&&ref($old)eq'HASH';$started=$now unless$started;
 my$new={
  id=>$id,workflow_id=>int($e->{workflow_id}||0),name=>clean($e->{title}||'GitHub Actions'),
  branch=>clean($e->{ref}||'repository'),status=>$status,started_at=>$started,last_seen=>$now,
  url=>clean($e->{url}||''),sha=>clean($e->{sha}||''),attempt=>int($e->{attempt}||1),
 };
 my$changed=!ref($old)||join("\x1f",map{$old->{$_}//''}qw(workflow_id name branch status started_at url sha attempt)) ne join("\x1f",map{$new->{$_}//''}qw(workflow_id name branch status started_at url sha attempt));
 $STATE{ci_running}{$id}=$new;
 my$slow=0;
 if($allow_slow&&$CFG{actions_slow}>0&&$status eq'in_progress'&&$now-$started>=$CFG{actions_slow}&&!$STATE{ci_slow_seen}{$id}){
  $STATE{ci_slow_seen}{$id}=$now;$STATS{actions_slow_alerts}++;$slow=1;
  my$notice={kind=>'ci_slow',repo=>$CFG{repo},id=>$id,attempt=>int($e->{attempt}||1),title=>$e->{title},
   ref=>$e->{ref},sha=>$e->{sha},started_at=>$started,url=>$e->{url},actor=>$e->{actor}||'github-actions'};
  my$f=fingerprint($notice);
  if(!$STATE{fingerprints}{$f}){$STATE{fingerprints}{$f}=time;enqueue(format_event($notice),'actions',1)}
 }
 $changed||$slow||$cleared?1:0;
}
sub refresh_running_ci {
 my($runs,$allow_slow)=@_;return 0 unless$runs&&ref($runs)eq'ARRAY';my$changed=0;
 for my$r(@$runs){my$e=normalize_action_run($r);$changed+=update_running_ci_event($e,$allow_slow)}
 $changed;
}
sub current_ci_running {
 my@r;
 for my$id(keys%{$STATE{ci_running}}){my$v=$STATE{ci_running}{$id};next unless ref($v)eq'HASH';push@r,{%$v}}
 sort{($a->{started_at}||0)<=>($b->{started_at}||0)}@r;
}
sub current_ci_running_count { my@r=current_ci_running();scalar@r }

sub ci_expect_branch_allowed { my($b)=@_;my$f=clean($CFG{actions_expect_branches}||'');return 1 if$f eq'';my$want=lc(clean($b||''));for my$x(split/,/,$f){return 1 if lc(clean($x))eq$want}0 }
sub expect_ci_for_push {
 my($e)=@_;return 0 unless$CFG{actions_enabled}&&$CFG{actions_expect}>0&&$e&&($e->{kind}||'')eq'push';
 return 0 unless ci_expect_branch_allowed($e->{ref});
 my$sha=lc(clean($e->{sha}||''));return 0 unless$sha=~/^[0-9a-f]{7,64}$/;return 0 if$STATE{ci_sha_seen}{$sha};
 $STATE{ci_expected}{$sha}={sha=>$sha,branch=>clean($e->{ref}||'repository'),at=>int(time),actor=>clean($e->{actor}||''),url=>clean($e->{url}||''),alerted=>0};
 if(keys(%{$STATE{ci_expected}})>$CFG{actions_expect_max}){
  my@k=sort{($STATE{ci_expected}{$a}{at}||0)<=>($STATE{ci_expected}{$b}{at}||0)}keys%{$STATE{ci_expected}};
  while(keys(%{$STATE{ci_expected}})>$CFG{actions_expect_max}){my$k=shift@k;last unless defined$k;delete$STATE{ci_expected}{$k}}
 }
 1;
}
sub note_ci_sha_seen { my($sha)=@_;$sha=lc(clean($sha||''));return 0 unless$sha=~/^[0-9a-f]{7,64}$/;$STATE{ci_sha_seen}{$sha}=time;1 }
sub clear_ci_expectation {
 my($sha)=@_;$sha=lc(clean($sha||''));return 0 unless$sha ne''&&$STATE{ci_expected}{$sha};
 delete$STATE{ci_expected}{$sha};$STATS{actions_expect_cleared}++;1;
}
sub current_ci_expected {
 my@x;for my$sha(keys%{$STATE{ci_expected}}){my$v=$STATE{ci_expected}{$sha};next unless ref($v)eq'HASH';push@x,{%$v,sha=>$sha}}
 sort{($a->{at}||0)<=>($b->{at}||0)}@x;
}
sub current_ci_expected_count { my@x=current_ci_expected();scalar@x }
sub check_missing_ci {
 return 0 unless$CFG{actions_enabled}&&$CFG{actions_expect}>0;
 my$now=int(time);my$changed=0;
 for my$x(current_ci_expected()){
  next if$x->{alerted};next unless$x->{at}&&$now-$x->{at}>=$CFG{actions_expect};
  my$sha=lc(clean($x->{sha}||''));next unless$STATE{ci_expected}{$sha};
  $STATE{ci_expected}{$sha}{alerted}=$now;$STATS{actions_missing_alerts}++;
  my$notice={kind=>'ci_missing',repo=>$CFG{repo},sha=>$sha,ref=>$x->{branch},actor=>$x->{actor}||'push',started_at=>$x->{at},url=>$x->{url}||"https://github.com/$CFG{repo}/commit/$sha"};
  my$f=fingerprint($notice);if(!$STATE{fingerprints}{$f}){$STATE{fingerprints}{$f}=time;enqueue(format_event($notice),'actions',1)}
  $changed=1;
 }
 save_state() if$changed;$changed;
}

sub ci_should_announce {
 my($e)=@_;return 0 unless($e->{action}||'')eq'completed';
 return 1 if$CFG{actions_recovery}&&$e->{recovery};
 return 1 unless$CFG{actions_fail_only};
 ci_bad($e->{conclusion});
}
sub webhook_event_should_announce {
 my($e)=@_;my$k=$e->{kind}||'';
 return ci_should_announce($e) if$k eq'ci';
 return 0 if$k eq'workflow_job'&&!$CFG{actions_show_jobs};
 if($k=~/^(?:workflow_job|check_run|check_suite)$/){
  return 1 unless$CFG{actions_fail_only};
  return ci_bad($e->{conclusion});
 }
 if($k eq'commit_status'){
  return 1 unless$CFG{actions_fail_only};
  return ci_bad($e->{action});
 }
 1;
}
sub kick_actions {
 return unless$CFG{actions_enabled};
 my$now=time;$RUN{actions_fast_until}=$now+$CFG{actions_fast_win}
  if$RUN{actions_fast_until}<$now+$CFG{actions_fast_win};
 my$soon=$now+10;$RUN{actions_next}=$soon if$RUN{actions_next}>$soon;
}
sub actions_delay {
 my$fast=$CFG{actions_fast};my$idle=$CFG{actions_idle};
 if($RUN{actions_auth_mode}=~/anonymous/||$RUN{token}eq''){$fast=60 if$fast<60;$idle=300 if$idle<300}
 my$d=time<$RUN{actions_fast_until}?$fast:$idle;
 if($RUN{actions_error_streak}){
  my$n=$RUN{actions_error_streak};$n=4 if$n>4;$d*=2**$n;$d=900 if$d>900;
 }
 $d;
}
sub fetch_actions_page {
 my($url,$conditional)=@_;return unless$CFG{actions_enabled}&&github_rest_allowed();
 $STATS{actions_polls}++ if$conditional;$STATS{actions_pages}++;
 my$actions_token=$RUN{actions_auth_mode}eq'anonymous-fallback'?'':$RUN{token};
 my%h=%{api_headers($actions_token,0)};
 $h{'If-None-Match'}=$STATE{actions_etag}if$conditional&&$STATE{actions_etag}ne'';
 my$r=eval{$HTTP->get($url,{headers=>\%h})};
 if($r&&ref($r)eq'HASH'){
  my$limited=note_rate_limit($r,'Actions');note_github_success($r) unless$limited;
  if($actions_token ne''&&($r->{status}==401||$r->{status}==403)&&!$limited){
   $RUN{actions_auth_mode}='anonymous-fallback';
   logmsg('WARN',"GitHub Actions authenticated access rejected ($r->{status}); next poll will use public access");
  }else{$RUN{actions_auth_mode}=$RUN{token}ne''?'authenticated':'anonymous'}
 }
 if(!$r||ref$r ne'HASH'){$RUN{actions_error}=clean($@||'request failed');$RUN{actions_error_streak}++;$STATS{actions_errors}++;return}
 update_rate($r);
 if($r->{status}==304){$RUN{actions_error}='';$RUN{actions_error_streak}=0;$STATE{last_actions_ok}=time;$STATS{actions_not_modified}++;return{runs=>[],next=>'',not_modified=>1}}
 if(!$r->{success}){$RUN{actions_error}="HTTP $r->{status} $r->{reason}";$RUN{actions_error_streak}++;$STATS{actions_errors}++;return}
 my$d=eval{decode_json($r->{content})};
 if(!$d||ref$d ne'HASH'||ref($d->{workflow_runs})ne'ARRAY'){$RUN{actions_error}='invalid JSON';$RUN{actions_error_streak}++;$STATS{actions_errors}++;return}
 $STATE{actions_etag}=$r->{headers}{etag}//$STATE{actions_etag} if$conditional;
 $STATE{last_actions_ok}=time;$RUN{actions_error}='';$RUN{actions_error_streak}=0;
 my$runs=$d->{workflow_runs};
 if($conditional&&grep{clean($_->{status}//'') ne'completed'}@$runs){
  my$until=time+300;$RUN{actions_fast_until}=$until if$RUN{actions_fast_until}<$until;
 }
 {runs=>$runs,next=>next_link($r),not_modified=>0};
}
sub process_actions_batch {
 my($fresh,$runs)=@_;my%once;
 my@uniq=grep{my$k=action_key($_);!$once{$k}++}@$runs;$runs=\@uniq;
 my$running_changed=refresh_running_ci($runs,!$$fresh);
 my@completed=grep{clean($_->{status}//'')eq'completed'&&defined$_->{id}}@$runs;
 my$history_added=record_ci_run_history(\@completed);
 if(@completed){
  my$r=$completed[0];$STATE{last_action_name}=clean($r->{name}||$r->{display_title}||'GitHub Actions');
  $STATE{last_action_conclusion}=clean($r->{conclusion}||'');
  $STATE{last_action_url}=clean($r->{html_url}||'');$STATE{last_action_at}=time;
 }

 if($$fresh){
  $STATE{actions_seen}{action_key($_)}=time for@completed;
  $STATE{ci_bad_state}={};
  for my$r(reverse@completed){my$e=normalize_action_run($r);ci_track_state($e);track_ci_flap($e,0)}
  $$fresh=0;save_state();
  logmsg('INFO','GitHub Actions baseline established — '.scalar(@completed).' completed run(s), no replay');
  return 1;
 }

 my@new=grep{!$STATE{actions_seen}{action_key($_)}}@completed;
 for my$r(reverse@new){
  my$key=action_key($r);$STATE{actions_seen}{$key}=time;$STATS{actions_new}++;
  my$e=normalize_action_run($r);
  my$recovered=ci_track_state($e);track_ci_flap($e,1);
  if(ci_bad($e->{conclusion})){$STATS{actions_failures}++}else{$STATS{actions_success}++}
  $STATS{actions_recoveries}++ if$recovered;
  next unless ci_should_announce($e);
  queue_ci_announcement($e);
 }
 save_state() if@new||$running_changed||$history_added;1;
}
sub reconcile_actions {
 my($fresh)=@_;return 0 unless$CFG{actions_enabled}&&time>=$RUN{actions_next}&&github_rest_allowed()&&!$RUN{actions_scan};
 my$res=fetch_actions_page($CFG{actions_url},1);$RUN{actions_next}=time+actions_delay();return 1 unless$res;
 return 1 if$res->{not_modified};
 my$runs=$res->{runs};
 return process_actions_batch($fresh,$runs) if$$fresh;
 my@completed=grep{clean($_->{status}//'')eq'completed'&&defined$_->{id}}@$runs;
 my$known=grep{$STATE{actions_seen}{action_key($_)}}@completed;
 if(!$known&&@$runs>=$CFG{actions_per_page}&&$res->{next}&&$CFG{actions_max_pages}>1){
  $RUN{actions_scan}={runs=>[@$runs],next=>$res->{next},pages=>1};return 1;
 }
 process_actions_batch($fresh,$runs);
}
sub continue_actions_scan {
 my($fresh)=@_;my$s=$RUN{actions_scan};return 0 unless$s&&github_rest_allowed();
 my$res=fetch_actions_page($s->{next},0);
 if(!$res){$RUN{actions_scan}=undef;return 1}
 push@{$s->{runs}},@{$res->{runs}};$s->{pages}++;
 my@completed=grep{clean($_->{status}//'')eq'completed'&&defined$_->{id}}@{$res->{runs}};
 my$known=grep{$STATE{actions_seen}{action_key($_)}}@completed;
 my$done=$known||!$res->{next}||$s->{pages}>=$CFG{actions_max_pages};
 if(!$done){$s->{next}=$res->{next};return 1}
 if(!$known&&$res->{next}&&$s->{pages}>=$CFG{actions_max_pages}){
  $STATS{actions_gap}++;logmsg('WARN',"Actions catch-up reached page limit $CFG{actions_max_pages}; oldest runs may require a larger window");
 }
 my@all=@{$s->{runs}};$RUN{actions_scan}=undef;process_actions_batch($fresh,\@all);1;
}


# ── Public GitHub account portfolio ──────────────────────────────────────────
# This inventory deliberately uses GitHub's public owner endpoint and retains
# only a small allow-list of repository metadata. It never scans organizations,
# collaborators or private repositories, and it never creates IRC broadcasts.
sub account_state {
 return'off'unless$CFG{account_enabled};return'limited'unless github_rest_allowed();
 return'error'if$RUN{account_error}ne'';return'online'if$STATE{last_account_ok};'waiting';
}
sub account_headers {
 my($conditional)=@_;my$h=api_headers($RUN{token},0);
 $h->{'If-None-Match'}=$STATE{account_etag}if$conditional&&$STATE{account_etag}ne'';$h;
}
sub account_fetch_page {
 my($url,$conditional)=@_;return unless$CFG{account_enabled}&&github_rest_allowed();
 if($url!~m{^https://api\.github\.com/users/\Q$CFG{account}\E/repos\?}i){$RUN{account_error}='refused out-of-scope account URL';$STATS{account_errors}++;return}
 $STATS{account_polls}++if$conditional;$STATS{account_pages}++;
 my$r=eval{$HTTP->get($url,{headers=>account_headers($conditional)})};
 if(!$r||ref($r)ne'HASH'){$RUN{account_error}=clean($@||'request failed');$STATS{account_errors}++;return}
 my$limited=note_rate_limit($r,'Account');note_github_success($r)unless$limited;update_rate($r);
 if($r->{status}==304){$RUN{account_error}='';$STATE{last_account_ok}=time;$STATS{account_not_modified}++;return{repos=>[],next=>'',not_modified=>1,etag=>$STATE{account_etag}}}
 if(!$r->{success}){$RUN{account_error}="HTTP $r->{status} $r->{reason}";$STATS{account_errors}++;return}
 my$d=eval{decode_json($r->{content})};
 if(ref($d)ne'ARRAY'){$RUN{account_error}='invalid repository inventory JSON';$STATS{account_errors}++;return}
 my@repos=grep{defined}map{account_normalize_repo($_)}@$d;
 $RUN{account_error}='';+{repos=>\@repos,next=>next_link($r),not_modified=>0,etag=>($r->{headers}{etag}//'')};
}
sub account_summary {
 my@repos=ref($STATE{account_repos})eq'ARRAY'?@{$STATE{account_repos}}:();my$now=time;
 my($maintained,$active,$archived,$disabled,$forked,$stale,$stars,$forks,$issues,$missing_desc,$missing_license,$missing_topics)=(0)x12;
 my(%languages,@stale_repos);
 for my$r(@repos){next unless ref($r)eq'HASH';
  $stars+=int($r->{stars}||0);$forks+=int($r->{forks}||0);$issues+=int($r->{open_issues}||0);
  $archived++if$r->{archived};$disabled++if$r->{disabled};$forked++if$r->{fork};
  my$live=!$r->{archived}&&!$r->{disabled};$maintained++if$live;
  my$pt=iso8601_epoch($r->{pushed_at});$active++if$live&&$pt&&$pt>=$now-30*86400;
  if($live&&(!$pt||$pt<$now-$CFG{account_stale_days}*86400)){$stale++;push@stale_repos,$r}
  if($live&&!$r->{fork}){$missing_desc++if clean($r->{description}//'')eq'';$missing_license++if clean($r->{license}//'')eq'';$missing_topics++if ref($r->{topics})ne'ARRAY'||!@{$r->{topics}}}
  $languages{clean($r->{language})}++if clean($r->{language}//'')ne'';
 }
 my@starred=sort{int($b->{stars}||0)<=>int($a->{stars}||0)||lc($a->{name})cmp lc($b->{name})}@repos;
 my@recent=sort{iso8601_epoch($b->{pushed_at})<=>iso8601_epoch($a->{pushed_at})||lc($a->{name})cmp lc($b->{name})}@repos;
 @stale_repos=sort{iso8601_epoch($a->{pushed_at})<=>iso8601_epoch($b->{pushed_at})||lc($a->{name})cmp lc($b->{name})}@stale_repos;
 splice@starred,$CFG{account_top}if@starred>$CFG{account_top};splice@recent,$CFG{account_top}if@recent>$CFG{account_top};splice@stale_repos,$CFG{account_top}if@stale_repos>$CFG{account_top};
 my@langs=map{{name=>$_,repositories=>$languages{$_}}}sort{$languages{$b}<=>$languages{$a}||lc($a)cmp lc($b)}keys%languages;
 my$date=utc_date($now);my@days=grep{$_ lt$date}sort keys%{$STATE{account_history}};my$prev=@days?$STATE{account_history}{$days[-1]}:{};
 my%cur=(repositories=>scalar@repos,maintained=>$maintained,active_30d=>$active,archived=>$archived,stale=>$stale,stars=>$stars,forks=>$forks,open_issues=>$issues);
 my%trend=map{$_=>{current=>$cur{$_},previous=>int($prev->{$_}||0),delta=>$cur{$_}-int($prev->{$_}||0),previous_date=>(@days?$days[-1]:'')}}keys%cur;
 +{state=>account_state(),account=>$CFG{account},last_ok=>int($STATE{last_account_ok}||0),error=>$RUN{account_error}||'',stale_days=>$CFG{account_stale_days},
  %cur,disabled=>$disabled,forked=>$forked,missing_description=>$missing_desc,missing_license=>$missing_license,missing_topics=>$missing_topics,
  most_starred=>[map{{%$_}}@starred],recently_pushed=>[map{{%$_}}@recent],stale_repositories=>[map{{%$_}}@stale_repos],languages=>\@langs,trend=>\%trend};
}
sub account_record_history {
 my$s=account_summary();my$date=utc_date(time);
 $STATE{account_history}{$date}={date=>$date,map{($_=>int($s->{$_}||0))}qw(repositories maintained active_30d archived stale stars forks open_issues)};
}
sub account_history_rows { [map{{%{$STATE{account_history}{$_}}}}sort keys%{$STATE{account_history}}] }
sub account_history_summary { my$r=account_history_rows();+{days=>scalar@$r,from=>@$r?$r->[0]{date}:'',to=>@$r?$r->[-1]{date}:'',retention_days=>MAX_ACCOUNT_DAYS} }
sub account_change_text {
 my($c)=@_;my$name=clean($c->{repo}||'');$name=~s{^\Q$CFG{account}\E/}{}i;my$k=$c->{kind}||'';
 return"$name added"if$k eq'added';return"$name removed or no longer public"if$k eq'removed';return"$name archived"if$k eq'archived';return"$name unarchived"if$k eq'unarchived';
 return"$name pushed · ".substr(clean($c->{to}||''),0,10)if$k eq'pushed';
 "$name $k · ".clean($c->{from}//0).' → '.clean($c->{to}//0);
}
sub account_change_rows {
 my@c=reverse@{$STATE{account_changes}};splice@c,$CFG{account_top}if@c>$CFG{account_top};
 [map{{%$_,text=>account_change_text($_)}}@c];
}
sub account_record_changes {
 my($new)=@_;return 0 unless ref($new)eq'ARRAY'&&@{$STATE{account_repos}};
 my%old=map{lc($_->{full_name})=>$_}@{$STATE{account_repos}};my%new=map{lc($_->{full_name})=>$_}@$new;my@c;my$at=int(time);
 for my$k(sort keys%new){my$n=$new{$k};my$o=$old{$k};if(!$o){push@c,{at=>$at,repo=>$n->{full_name},kind=>'added',from=>'',to=>$n->{pushed_at}||''};next}
  if(($o->{archived}?1:0)!=($n->{archived}?1:0)){push@c,{at=>$at,repo=>$n->{full_name},kind=>$n->{archived}?'archived':'unarchived',from=>$o->{archived}?1:0,to=>$n->{archived}?1:0}}
  push@c,{at=>$at,repo=>$n->{full_name},kind=>'pushed',from=>$o->{pushed_at}||'',to=>$n->{pushed_at}||''}if clean($o->{pushed_at}//'')ne clean($n->{pushed_at}//'');
  for my$f(qw(stars forks open_issues)){my($a,$b)=(int($o->{$f}||0),int($n->{$f}||0));push@c,{at=>$at,repo=>$n->{full_name},kind=>$f,from=>$a,to=>$b}if$a!=$b}
 }
 for my$k(sort keys%old){next if$new{$k};push@c,{at=>$at,repo=>$old{$k}{full_name},kind=>'removed',from=>$old{$k}{pushed_at}||'',to=>''}}
 push@{$STATE{account_changes}},@c;splice@{$STATE{account_changes}},0,@{$STATE{account_changes}}-$CFG{account_changes_max}if@{$STATE{account_changes}}>$CFG{account_changes_max};scalar@c;
}
sub account_status_payload { my$s=account_summary();+{%$s,scope=>'public owner repositories only',history_summary=>account_history_summary(),changes=>account_change_rows()} }
sub account_payload { my$s=account_status_payload();+{%$s,repos=>[map{{%$_}}@{$STATE{account_repos}}],history=>account_history_rows()} }
sub finish_account_scan {
 my($scan)=@_;my%seen;my@repos=grep{!$seen{lc($_->{full_name})}++}@{$scan->{repos}||[]};
 @repos=sort{lc($a->{name})cmp lc($b->{name})}@repos;$STATS{account_changes_detected}+=account_record_changes(\@repos);$STATE{account_repos}=\@repos;
 $STATE{account_etag}=$scan->{etag}if clean($scan->{etag}//'')ne'';$STATE{last_account_ok}=time;
 $STATS{account_repos_seen}+=scalar@repos;$RUN{account_error}='';account_record_history();save_state();
}
sub continue_account_scan {
 my$s=$RUN{account_scan};return 0 unless$s&&github_rest_allowed();my$res=account_fetch_page($s->{next},0);
 if(!$res){$RUN{account_scan}=undef;$RUN{account_next}=time+$CFG{account_interval};return 1}
 push@{$s->{repos}},@{$res->{repos}};$s->{pages}++;
 if($res->{next}&&$s->{pages}<$CFG{account_max_pages}){$s->{next}=$res->{next};return 1}
 if($res->{next}&&$s->{pages}>=$CFG{account_max_pages}){$RUN{account_error}="inventory truncated at $CFG{account_max_pages} pages";$STATS{account_errors}++;$RUN{account_scan}=undef;$RUN{account_next}=time+$CFG{account_interval};return 1}
 $RUN{account_scan}=undef;finish_account_scan($s);$RUN{account_next}=time+$CFG{account_interval};1;
}
sub reconcile_account {
 return 0 unless$CFG{account_enabled}&&time>=$RUN{account_next}&&github_rest_allowed();
 my$res=account_fetch_page($CFG{account_url},1);$RUN{account_next}=time+$CFG{account_interval};return 1 unless$res;
 if($res->{not_modified}){account_record_history();save_state();return 1}
 my$s={repos=>[@{$res->{repos}}],next=>$res->{next},pages=>1,etag=>$res->{etag}};
 if($s->{next}&&$CFG{account_max_pages}>1){$RUN{account_scan}=$s;$RUN{account_next}=time+.2;return 1}
 if($s->{next}){$RUN{account_error}='inventory truncated at one page';$STATS{account_errors}++;return 1}
 finish_account_scan($s);1;
}
sub account_check_cli {
 return 3 unless$CFG{account_enabled};auth_check();my($url,@repos,$pages)=($CFG{account_url});
 while($url&&$pages<$CFG{account_max_pages}){my$r=account_fetch_page($url,0);if(!$r){print "GitHub account: ERROR — $RUN{account_error}\n";return 2}push@repos,@{$r->{repos}};$url=$r->{next};$pages++}
 if($url){print "GitHub account: ERROR — inventory exceeds $CFG{account_max_pages} pages\n";return 2}
 local$STATE{account_repos}=\@repos;local$STATE{last_account_ok}=time;my$s=account_summary();
 print "GitHub account: OK — public owner=$CFG{account} — repos=$s->{repositories} — maintained=$s->{maintained} — active30d=$s->{active_30d} — stars=$s->{stars} — forks=$s->{forks} — stale=$s->{stale}\n";0;
}



# ── GitHub repository traffic ───────────────────────────────────────────────
sub traffic_state {
 return'off'unless$CFG{traffic_enabled};
 return'needs_token'if$CFG{token}eq'';
 return'limited'unless github_rest_allowed();
 return'error'if$RUN{traffic_error}ne'';
 return'online'if$STATE{last_traffic_ok};
 'waiting';
}
sub traffic_endpoint {
 my($kind)=@_;my%p=(clones=>'clones',views=>'views',referrers=>'popular/referrers',paths=>'popular/paths');
 return q{}unless$p{$kind};$CFG{traffic_base}.'/'.$p{$kind};
}
sub traffic_fetch_stage {
 my($kind)=@_;return unless$CFG{traffic_enabled};return unless github_rest_allowed();
 if($CFG{token}eq''){$RUN{traffic_error}='GitHub token required';$RUN{traffic_permission}='needs_token';return}
 my$url=traffic_endpoint($kind);return unless$url;
 $STATS{traffic_requests}++;
 my$r=eval{$HTTP->get($url,{headers=>api_headers($CFG{token},0)})};
 if(!$r||ref$r ne'HASH'){$RUN{traffic_error}=clean($@||'request failed');$STATS{traffic_errors}++;return}
 my$limited=note_rate_limit($r,'Traffic');note_github_success($r) unless$limited;update_rate($r);
 if($r->{status}==403){$RUN{traffic_error}='HTTP 403 traffic permission denied';$RUN{traffic_permission}='forbidden';$STATS{traffic_forbidden}++;return}
 if(!$r->{success}){$RUN{traffic_error}="HTTP $r->{status} $r->{reason}";$STATS{traffic_errors}++;return}
 my$d=eval{decode_json($r->{content})};
 if($kind eq'clones'){
  return do{$RUN{traffic_error}='invalid clones response';$STATS{traffic_errors}++;undef} unless$d&&ref$d eq'HASH'&&ref($d->{clones})eq'ARRAY';
 }elsif($kind eq'views'){
  return do{$RUN{traffic_error}='invalid views response';$STATS{traffic_errors}++;undef} unless$d&&ref$d eq'HASH'&&ref($d->{views})eq'ARRAY';
 }else{
  return do{$RUN{traffic_error}="invalid $kind response";$STATS{traffic_errors}++;undef} unless ref($d)eq'ARRAY';
 }
 $RUN{traffic_permission}='ok';$RUN{traffic_error}='';$d;
}
sub reconcile_traffic {
 return 0 unless$CFG{traffic_enabled}&&time>=$RUN{traffic_next};
 if($CFG{token}eq''){$RUN{traffic_error}='GitHub token required';$RUN{traffic_permission}='needs_token';$RUN{traffic_next}=time+$CFG{traffic_interval};return 1}
 return 0 unless github_rest_allowed();
 my@stages=qw(clones views referrers paths);my$stage=int($RUN{traffic_stage}||0);$stage=0 if$stage<0||$stage>@stages-1;
 my$kind=$stages[$stage];my$d=traffic_fetch_stage($kind);
 if(!defined$d){
  $RUN{traffic_stage}=0;$RUN{traffic_cycle}={};$RUN{traffic_next}=time+$CFG{traffic_interval};return 1;
 }
 $RUN{traffic_cycle}{$kind}=$d;
 if($stage<@stages-1){$RUN{traffic_stage}=$stage+1;$RUN{traffic_next}=time+.2;return 1}
 my$c=$RUN{traffic_cycle};
 $STATE{traffic_clones}={%{$c->{clones}}};
 $STATE{traffic_views}={%{$c->{views}}};
 $STATE{traffic_referrers}=[map{{%$_}}@{$c->{referrers}}];
 $STATE{traffic_paths}=[map{{%$_}}@{$c->{paths}}];
 traffic_merge_history();
 $STATE{last_traffic_ok}=time;$STATS{traffic_cycles}++;
 $RUN{traffic_stage}=0;$RUN{traffic_cycle}={};$RUN{traffic_next}=time+$CFG{traffic_interval};$RUN{traffic_error}='';save_state();1;
}
sub traffic_best_day {
 my($series,$field)=@_;return{}unless$series&&ref($series)eq'ARRAY'&&@$series;
 my$best={};for my$e(@$series){next unless ref($e)eq'HASH';$best=$e if!%$best||int($e->{$field}||0)>int($best->{$field}||0)}
 return {%$best};
}
sub traffic_summary_data {
 my$c=$STATE{traffic_clones};my$v=$STATE{traffic_views};
 my@cl=ref($c->{clones})eq'ARRAY'?@{$c->{clones}}:();my@vw=ref($v->{views})eq'ARRAY'?@{$v->{views}}:();
 my$cd=@cl||1;my$vd=@vw||1;my$bc=traffic_best_day(\@cl,'count');my$bv=traffic_best_day(\@vw,'count');
 my$daily_cu=0;my$daily_vu=0;$daily_cu+=int($_->{uniques}||0)for@cl;$daily_vu+=int($_->{uniques}||0)for@vw;
 my$lc=@cl?{%{$cl[-1]}}:{};my$lv=@vw?{%{$vw[-1]}}:{};
 +{
  state=>traffic_state(),last_ok=>int($STATE{last_traffic_ok}||0),
  clones=>int($c->{count}||0),clone_uniques=>int($c->{uniques}||0),
  views=>int($v->{count}||0),view_uniques=>int($v->{uniques}||0),
  clone_days=>scalar@cl,view_days=>scalar@vw,
  avg_clones=>scalar(@cl)?int($c->{count}||0)/scalar(@cl):0,
  avg_clone_uniques=>scalar(@cl)?$daily_cu/scalar(@cl):0,
  avg_views=>scalar(@vw)?int($v->{count}||0)/scalar(@vw):0,
  avg_view_uniques=>scalar(@vw)?$daily_vu/scalar(@vw):0,
  clone_unique_rate=>int($c->{count}||0)>0?100*int($c->{uniques}||0)/int($c->{count}):0,
  view_unique_rate=>int($v->{count}||0)>0?100*int($v->{uniques}||0)/int($v->{count}):0,
  best_clone=>$bc,best_view=>$bv,last_clone=>$lc,last_view=>$lv,
 };
}
sub traffic_api_daily_rows {
 my%r;my$c=$STATE{traffic_clones};my$v=$STATE{traffic_views};
 for my$e(ref($c->{clones})eq'ARRAY'?@{$c->{clones}}:()){my$d=clean($e->{timestamp}||'');$d=substr($d,0,10);$r{$d}{date}=$d;$r{$d}{clones}=int($e->{count}||0);$r{$d}{clone_uniques}=int($e->{uniques}||0)}
 for my$e(ref($v->{views})eq'ARRAY'?@{$v->{views}}:()){my$d=clean($e->{timestamp}||'');$d=substr($d,0,10);$r{$d}{date}=$d;$r{$d}{views}=int($e->{count}||0);$r{$d}{view_uniques}=int($e->{uniques}||0)}
 map{$r{$_}}grep{/^\d{4}-\d\d-\d\d$/}sort keys%r;
}
sub traffic_merge_history {
 my@rows=traffic_api_daily_rows();
 for my$r(@rows){my$d=clean($r->{date}||'');next unless$d=~/^\d{4}-\d\d-\d\d$/;$STATE{traffic_history}{$d}={date=>$d,map{($_=>int($r->{$_}||0))}qw(clones clone_uniques views view_uniques)}}
 my@days=sort keys%{$STATE{traffic_history}};if(@days>MAX_TRAFFIC_DAYS){delete$STATE{traffic_history}{$_}for@days[0..@days-MAX_TRAFFIC_DAYS-1]}
 scalar@rows;
}
sub traffic_daily_rows {
 my%r;
 for my$d(keys%{$STATE{traffic_history}}){my$v=$STATE{traffic_history}{$d};next unless$d=~/^\d{4}-\d\d-\d\d$/&&ref($v)eq'HASH';$r{$d}={date=>$d,map{($_=>int($v->{$_}||0))}qw(clones clone_uniques views view_uniques)}}
 for my$v(traffic_api_daily_rows()){my$d=$v->{date};$r{$d}={%$v}}
 map{$r{$_}}sort keys%r;
}
sub traffic_history_summary {
 my@r=traffic_daily_rows();+{days=>scalar@r,from=>@r?clean($r[0]{date}||''):'',to=>@r?clean($r[-1]{date}||''):'',retention_days=>MAX_TRAFFIC_DAYS,exact_unique_window_days=>14};
}
sub traffic_latest_snapshot {
 my@r=traffic_api_daily_rows();@r=traffic_daily_rows()unless@r;my$last=@r?$r[-1]:{};my$prev=@r>1?$r[-2]:{};
 my@utc=gmtime(time);my$today=sprintf('%04d-%02d-%02d',$utc[5]+1900,$utc[4]+1,$utc[3]);
 +{date=>clean($last->{date}||''),partial=>($last->{date}||'')eq$today?1:0,refreshed_at=>int($STATE{last_traffic_ok}||0),
  clones=>int($last->{clones}||0),clone_uniques=>int($last->{clone_uniques}||0),views=>int($last->{views}||0),view_uniques=>int($last->{view_uniques}||0),
  clone_delta=>int($last->{clones}||0)-int($prev->{clones}||0),clone_unique_delta=>int($last->{clone_uniques}||0)-int($prev->{clone_uniques}||0),
  view_delta=>int($last->{views}||0)-int($prev->{views}||0),view_unique_delta=>int($last->{view_uniques}||0)-int($prev->{view_uniques}||0)};
}
sub traffic_top {
 my($kind)=@_;my$src=$kind eq'referrers'?$STATE{traffic_referrers}:$STATE{traffic_paths};return()unless ref($src)eq'ARRAY';
 my@x=map{{%$_}}@$src;@x=sort{int($b->{count}||0)<=>int($a->{count}||0)}@x;splice@x,$CFG{traffic_top} if@x>$CFG{traffic_top};@x;
}
sub traffic_recent_trend {
 my($field)=@_;my@r=traffic_daily_rows();return{current=>0,previous=>0,delta=>0,pct=>0,date=>''}unless@r;
 my$cur=int($r[-1]{$field}||0);my$prev=@r>1?int($r[-2]{$field}||0):0;my$delta=$cur-$prev;
 my$pct=$prev?100*$delta/$prev:($cur?100:0);
 +{current=>$cur,previous=>$prev,delta=>$delta,pct=>$pct,date=>clean($r[-1]{date}||'')};
}
sub traffic_trend_text {
 my($field)=@_;my$x=traffic_recent_trend($field);my$sign=$x->{delta}>0?'+':'';
 $x->{current}.' today · '.$sign.$x->{delta}.' vs previous'.($x->{previous}?' ('.traffic_num($x->{pct},1).'%)':'');
}
sub traffic_period_snapshot {
 my($days,$offset)=@_;$days=int($days||7);$offset=int($offset||0);$days=1 if$days<1;$days=MAX_TRAFFIC_DAYS if$days>MAX_TRAFFIC_DAYS;$offset=0 if$offset<0;
 my@all=traffic_daily_rows();my$end=@all-$offset;$end=0 if$end<0;$end=@all if$end>@all;my$start=$end-$days;$start=0 if$start<0;
 my@rows=$start<$end?@all[$start..$end-1]:();my%sum=map{($_=>0)}qw(clones clone_uniques views view_uniques);
 for my$r(@rows){$sum{$_}+=int($r->{$_}||0) for keys%sum}
 my$n=scalar@rows;
 +{
  days_requested=>$days,days_reported=>$n,from=>$n?clean($rows[0]{date}||''):'',to=>$n?clean($rows[-1]{date}||''):'',
  clones=>$sum{clones},views=>$sum{views},
  daily_clone_unique_observations=>$sum{clone_uniques},daily_view_unique_observations=>$sum{view_uniques},
  avg_clones=>$n?$sum{clones}/$n:0,avg_views=>$n?$sum{views}/$n:0,
  avg_daily_clone_uniques=>$n?$sum{clone_uniques}/$n:0,avg_daily_view_uniques=>$n?$sum{view_uniques}/$n:0,
  active_clone_days=>scalar(grep{int($_->{clones}||0)>0}@rows),active_view_days=>scalar(grep{int($_->{views}||0)>0}@rows),
 };
}
sub traffic_change {
 my($current,$previous)=@_;$current+=0;$previous+=0;my$delta=$current-$previous;
 +{current=>$current,previous=>$previous,delta=>$delta,pct=>$previous?100*$delta/$previous:($current?100:0)};
}
sub traffic_period_comparison {
 my($days)=@_;$days=int($days||7);my$c=traffic_period_snapshot($days,0);my$p=traffic_period_snapshot($days,$days);
 +{days=>$days,current=>$c,previous=>$p,changes=>{
  clones=>traffic_change($c->{clones},$p->{clones}),views=>traffic_change($c->{views},$p->{views}),
  avg_daily_clone_uniques=>traffic_change($c->{avg_daily_clone_uniques},$p->{avg_daily_clone_uniques}),
  avg_daily_view_uniques=>traffic_change($c->{avg_daily_view_uniques},$p->{avg_daily_view_uniques}),
 }};
}
sub traffic_peak_summary {
 my@r=traffic_api_daily_rows();if(!@r){@r=traffic_daily_rows();splice@r,0,@r-14 if@r>14}
 +{clones=>traffic_best_day(\@r,'clones'),clone_uniques=>traffic_best_day(\@r,'clone_uniques'),views=>traffic_best_day(\@r,'views'),view_uniques=>traffic_best_day(\@r,'view_uniques')};
}
sub traffic_audience_summary {
 my$t=traffic_summary_data();my@d=traffic_daily_rows();my$last=@d?$d[-1]:{};my$p=traffic_peak_summary();
 my$clones=int($t->{clones}||0);my$cu=int($t->{clone_uniques}||0);
 my$views=int($t->{views}||0);my$vu=int($t->{view_uniques}||0);
 +{
  clones=>$clones,clone_uniques=>$cu,views=>$views,view_uniques=>$vu,
  clones_per_unique=>$cu?$clones/$cu:0,views_per_unique=>$vu?$views/$vu:0,
  today_clones=>int($last->{clones}||0),today_clone_uniques=>int($last->{clone_uniques}||0),
  today_views=>int($last->{views}||0),today_view_uniques=>int($last->{view_uniques}||0),
  avg_clones=>$t->{avg_clones}||0,avg_views=>$t->{avg_views}||0,
  avg_daily_clone_uniques=>$t->{avg_clone_uniques}||0,avg_daily_view_uniques=>$t->{avg_view_uniques}||0,
  clone_unique_rate=>$t->{clone_unique_rate}||0,view_unique_rate=>$t->{view_unique_rate}||0,
  best_clone_unique=>$p->{clone_uniques},best_view_unique=>$p->{view_uniques},comparison_7d=>traffic_period_comparison(7),
  raw_ip_addresses_available=>0,unique_metric=>'github_aggregated_unique',last_ok=>$t->{last_ok}||0,
  clone_unique_trend=>traffic_recent_trend('clone_uniques'),
  view_unique_trend=>traffic_recent_trend('view_uniques'),
 };
}
sub traffic_payload {
 my$s=traffic_summary_data();my$a=traffic_audience_summary();
 +{%$s,error=>$RUN{traffic_error}||'',permission=>$RUN{traffic_permission}||'',daily=>[traffic_daily_rows()],latest=>traffic_latest_snapshot(),history=>traffic_history_summary(),referrers=>[traffic_top('referrers')],paths=>[traffic_top('paths')],audience=>$a,
  semantics=>{unique_metric=>'GitHub aggregated unique cloners/visitors',raw_ip_addresses_available=>0,window_days=>14,timezone=>'UTC'}};
}
sub traffic_num { my($n,$digits)=@_;$digits//=1;my$p=10**$digits;int(($n||0)*$p+.5)/$p }
sub traffic_check_cli {
 return 3 unless$CFG{traffic_enabled};return 4 if$CFG{token}eq'';
 my%got;for my$k(qw(clones views referrers paths)){my$d=traffic_fetch_stage($k);if(!defined$d){print "GitHub Traffic: ERROR — $RUN{traffic_error}\n";return 2}$got{$k}=$d}
 my$c=$got{clones};my$v=$got{views};print "GitHub Traffic: OK — clones ".int($c->{count}||0)." / unique ".int($c->{uniques}||0)." — views ".int($v->{count}||0)." / unique ".int($v->{uniques}||0)." — referrers ".scalar(@{$got{referrers}})." — paths ".scalar(@{$got{paths}})."\n";0;
}

# ── Forum RSS ────────────────────────────────────────────────────────────────
sub decode_xml_bytes {
 my($bytes,$content_type)=@_;$bytes//=q{};return$bytes if utf8::is_utf8($bytes);
 $bytes=~s/^\xEF\xBB\xBF//;

 my$charset='';
 $charset=$1 if($content_type//q{})=~/charset\s*=\s*["']?([^;"'\s]+)/i;
 $charset=$1 if$charset eq''&&$bytes=~/^\s*<\?xml\b[^>]*\bencoding\s*=\s*["']([^"']+)["']/i;
 $charset='UTF-8' if$charset eq'';
 $charset='UTF-8' if$charset=~/^utf-?8$/i;

 for my$enc($charset,'UTF-8','Windows-1252'){
  next unless defined$enc&&$enc ne'';
  my$copy=$bytes;
  my$decoded=eval{decode($enc,$copy,FB_CROAK)};
  return$decoded if defined$decoded&&!$@;
 }
 undef;
}
sub xml_text {
 my($s)=@_;$s//=q{};
 # CDATA is literal text: protect it while stripping real markup.
 my@cdata;
 $s=~s{<!\[CDATA\[(.*?)\]\]>}{push@cdata,$1;"\x1d".($#cdata)."\x1e"}gse;
 $s=~s/<[^>]+>/ /g;
 $s=~s/&#x([0-9a-fA-F]+);/my$n=hex$1;$n<=0x10ffff?chr$n:''/ge;
 $s=~s/&#([0-9]+);/my$n=int$1;$n<=0x10ffff?chr$n:''/ge;
 my%ent=(amp=>'&',lt=>'<',gt=>'>',quot=>'"',apos=>"'");
 $s=~s/&(?:amp|lt|gt|quot|apos);/$ent{substr($&,1,-1)}/ge;
 $s=~s/\x1d(\d+)\x1e/$cdata[$1]/ge if@cdata;
 clean($s);
}
sub xml_tag {
 my($xml,$tag)=@_;my$q=quotemeta$tag;
 return xml_text($1) if$xml=~m{<$q(?:\s[^>]*)?>(.*?)</$q\s*>}is;
 q{};
}
sub rss_item_id {
 my($i)=@_;
 # Prefer immutable feed identifiers. A later title/category edit must not be
 # announced as a brand-new forum item.
 my$key=clean($i->{guid}//'');
 $key=clean($i->{link}//'') if$key eq'';
 $key=join("\x1f",clean($i->{title}//''),clean($i->{date}//'')) if$key eq'';
 sha256_hex($key);
}
sub parse_rss {
 my($xml)=@_;return[]unless defined$xml&&length$xml;
 my@out;

 while($xml=~m{<item\b[^>]*>(.*?)</item\s*>}gis){
  my$b=$1;
  my$i={
   title=>xml_tag($b,'title'),link=>xml_tag($b,'link'),guid=>xml_tag($b,'guid'),
   date=>xml_tag($b,'pubDate'),category=>xml_tag($b,'category'),
   author=>xml_tag($b,'dc:creator')||xml_tag($b,'author'),
  };
  next unless$i->{title}ne''||$i->{link}ne'';
  $i->{link}=''unless$i->{link}=~m{^https?://}i;
  $i->{id}=rss_item_id($i);push@out,$i;
  last if@out>=$CFG{rss_max_items};
 }

 # Small Atom fallback, useful if the forum feed implementation ever changes.
 if(!@out){
  while($xml=~m{<entry\b[^>]*>(.*?)</entry\s*>}gis){
   my$b=$1;my$link='';
   $link=xml_text($1)if$b=~m{<link\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*/?>}is;
   my$i={
    title=>xml_tag($b,'title'),link=>$link,guid=>xml_tag($b,'id'),
    date=>xml_tag($b,'updated')||xml_tag($b,'published'),
    category=>'',author=>xml_tag($b,'name'),
   };
   next unless$i->{title}ne''||$i->{link}ne'';
   $i->{link}=''unless$i->{link}=~m{^https?://}i;
   $i->{id}=rss_item_id($i);push@out,$i;
   last if@out>=$CFG{rss_max_items};
  }
 }
 \@out;
}
sub format_rss {
 my($i)=@_;my$title=irc_short($i->{title}||'Forum update',125);my$link=clean($i->{link}||$CFG{rss_url});
 my$who=irc_content($i->{author}||'');my$cat=irc_content($i->{category}||'');
 my$meta='';
 $meta.=' by '.paint(7,bold($who)) if$who ne'';
 $meta.=' in '.paint(13,$cat) if$cat ne'';
 icon('forum').' '.paint(11,bold('Forum')).': '.paint(10,$title).$meta.' — '.$link;
}
sub rss_backoff {
 my$n=$RUN{rss_failures};$n=4 if$n>4;
 my$d=$CFG{rss_interval}*(2**$n);$d=1800 if$d>1800;$d;
}
sub fetch_rss {
 return[]unless$CFG{rss_enabled};
 $STATS{rss_polls}++;

 my%h=(Accept=>'application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.1');
 my$baseline=$STATE{rss_id_version}==2&&$STATE{rss_text_version}==1&&keys(%{$STATE{rss_seen}});
 $h{'If-None-Match'}=$STATE{rss_etag} if$baseline&&$STATE{rss_etag}ne'';
 $h{'If-Modified-Since'}=$STATE{rss_modified} if$baseline&&$STATE{rss_modified}ne'';

 my$r=eval{$HTTP->get($CFG{rss_url},{headers=>\%h})};
 if(!$r||ref$r ne'HASH'){
  $RUN{rss_error}=clean($@||'request failed');$RUN{rss_failures}++;$STATS{rss_errors}++;return;
 }
 if($r->{status}==304){
  $RUN{rss_error}='';$RUN{rss_failures}=0;$STATE{last_rss_ok}=time;$STATS{rss_not_modified}++;return[];
 }
 if(!$r->{success}){
  $RUN{rss_error}="HTTP $r->{status} $r->{reason}";$RUN{rss_failures}++;$STATS{rss_errors}++;return;
 }

 my$raw=$r->{content}//'';
 if(length($raw)>5_000_000){
  $RUN{rss_error}='feed too large';$RUN{rss_failures}++;$STATS{rss_errors}++;return;
 }
 my$digest=sha256_hex($raw);
 if($STATE{rss_text_version}==1&&$STATE{rss_digest}ne''&&$digest eq$STATE{rss_digest}){
  $STATE{last_rss_ok}=time;$RUN{rss_error}='';$RUN{rss_failures}=0;
  $STATS{rss_unchanged}++;return[];
 }
 my$body=decode_xml_bytes($raw,$r->{headers}{'content-type'}//'');
 if(!defined$body){
  $RUN{rss_error}='feed charset decode failed';$RUN{rss_failures}++;$STATS{rss_errors}++;return;
 }
 my$items=parse_rss($body);
 if(!$items||ref$items ne'ARRAY'){
  $RUN{rss_error}='invalid feed';$RUN{rss_failures}++;$STATS{rss_errors}++;return;
 }

 $STATE{rss_etag}=$r->{headers}{etag}//$STATE{rss_etag};
 $STATE{rss_modified}=$r->{headers}{'last-modified'}//$STATE{rss_modified};
 $STATE{last_rss_ok}=time;$STATE{rss_text_version}=1;$STATE{rss_digest}=$digest;$RUN{rss_error}='';$RUN{rss_failures}=0;

 if(@$items){
  my$title=clean($items->[0]{title});my$link=clean($items->[0]{link});
  if($title ne$STATE{last_rss_title}||$link ne$STATE{last_rss_link}){
   $STATE{last_rss_title}=$title;$STATE{last_rss_link}=$link;$RUN{rss_dirty}=1;
  }
 }
 $items;
}

sub extract_last_url {
 my($s)=@_;$s=plain_irc($s//q{});
 my@u=$s=~m{(https?://[^\s]+)}g;return@u?$u[-1]:q{};
}
sub heal_legacy_latest_from_rss {
 my($items,$quiet)=@_;return 0 unless$items&&ref($items)eq'ARRAY'&&@$items;
 my$src=lc($STATE{last_event_source}||'');
 return 0 unless$src eq''||$src eq'legacy';
 my$old_url=extract_last_url($STATE{last_event_text});
 return 0 unless$old_url ne'';

 for my$i(@$items){
  next unless clean($i->{link}//'') eq$old_url;
  $STATE{last_event_text}=format_rss($i);
  $STATE{last_event_source}='rss';
  # We do not know the historical send timestamp reliably. Keep it unknown
  # instead of pretending the current poll time was the publication time.
  $STATE{last_event_at}=0;
  logmsg('INFO','Repaired legacy latest activity from RSS metadata') unless$quiet;
  return 1;
 }
 0;
}

sub reconcile_rss {
 my($fresh)=@_;return 0 unless$CFG{rss_enabled}&&time>=$RUN{rss_next};
 my$items=fetch_rss();
 $RUN{rss_next}=time+($RUN{rss_error}ne''?rss_backoff():$CFG{rss_interval});
 return 1 unless defined$items;

 my$healed=heal_legacy_latest_from_rss($items);

 if($$fresh){
  # v0.9 re-baselines once when migrating from the old RSS ID formula.
  $STATE{rss_seen}={};
  $STATE{rss_seen}{$_->{id}}=time for@$items;
  $STATE{rss_id_version}=2;$STATE{rss_text_version}=1;$RUN{rss_dirty}=0;
  $$fresh=0;save_state();
  logmsg('INFO','Forum RSS baseline established — '.scalar(@$items).' item(s), no replay');
  return 1;
 }

 my@new=grep{!$STATE{rss_seen}{$_->{id}}}@$items;
 for my$i(reverse@new){
  $STATE{rss_seen}{$i->{id}}=time;$STATS{rss_new}++;
  enqueue(format_rss($i),'rss',1);
 }
 $STATE{rss_seen}{$_->{id}}=time for@$items;
 my$dirty=$RUN{rss_dirty};$RUN{rss_dirty}=0;
 save_state() if@new||$dirty||$healed;1;
}

# ── IRC (multi-network, one lightweight event loop) ─────────────────────────
sub schedule_reconnect {
 my($net)=@_;return if$RUN{stopping};
 my$d=int($net->{reconnect_delay}||10);$d=10 if$d<10;$d=$CFG{reconnect_max} if$d>$CFG{reconnect_max};
 $net->{next_reconnect}=time+$d;
 $net->{reconnect_delay}=$d*2;$net->{reconnect_delay}=$CFG{reconnect_max} if$net->{reconnect_delay}>$CFG{reconnect_max};
}
sub reset_reconnect {
 my($net)=@_;$net->{reconnect_delay}=10;$net->{next_reconnect}=0;
}
sub sasl_plain_lines {
 my($account,$password)=@_;my$payload=encode_base64("\0$account\0$password",'');
 my@out;while(length$payload){push@out,substr($payload,0,400,'')}
 push@out,'+' if@out&&length($out[-1])==400;
 @out;
}
sub heartbeat_once {
 return 0 unless$CFG{irc_idle_ping}>0;my$now=time;my$did=0;
 for my$net(online_nets()){
  if($net->{pong_deadline}&&$now>$net->{pong_deadline}){$STATS{irc_heartbeat_timeouts}++;irc_disconnect($net,'heartbeat timeout');$did++;next}
  next if$net->{pong_deadline};
  my$last=$net->{last_rx}||$net->{last_join}||$now;next if$now-$last<$CFG{irc_idle_ping};
  my$token='ghw-'.$net->{id}.'-'.int($now);
  if(irc_raw($net,"PING :$token")){$net->{last_ping}=$now;$net->{pong_deadline}=$now+$CFG{irc_pong_timeout};$net->{ping_token}=$token;$STATS{irc_heartbeat_pings}++;$did++}
 }
 $did;
}
sub irc_raw {
 my($net,$line)=@_;return 0 unless$net&&$net->{up}&&$net->{socket};
 $line=~s/[\r\n]+/ /g;my$wire=encode('UTF-8',"$line\r\n");
 my$ok=eval{print{$net->{socket}}$wire or die"write: $!";1};
 return 1 if$ok;logmsg('WARN',"[$net->{label}] IRC write failed");irc_disconnect($net,'write error');0;
}
sub irc_msg {
 my($net,$target,$text)=@_;return 0 unless$net;
 my$reserve=$CFG{irc_colors}?1:0;$text=byte_limit($text,MAX_IRC_BYTES-$reserve);
 $text.=$R if$CFG{irc_colors}&&$text!~/\Q$R\E\z/;
 irc_raw($net,'PRIVMSG '.$target.' :'.$text);
}
sub record_history {
 my($text,$src,$at)=@_;my$t=short(plain_irc($text//q{}),350);return 0 if$t eq'';
 push@{$STATE{history}},{text=>$t,source=>clean($src||'unknown'),at=>int($at||time)};
 splice @{$STATE{history}},0,@{$STATE{history}}-$CFG{history_max} if@{$STATE{history}}>$CFG{history_max};
 1;
}
sub recent_history {
 my($limit)=@_;$limit=int($limit||$CFG{history_show});$limit=1 if$limit<1;$limit=$CFG{history_show}if$limit>$CFG{history_show};
 my@h=reverse@{$STATE{history}};splice@h,$limit if@h>$limit;@h;
}
sub queue_snapshot {
 my%out=(total=>scalar(@{$STATE{pending}}),oldest_at=>0);
 my%net_seen;
 for my$t(enabled_targets()){
  $out{$t->{metric}}=0;$out{$t->{metric}.'_oldest_at'}=0;
  my$nid=$t->{net}{id};$out{$nid}=0;$out{$nid.'_oldest_at'}=0 unless$net_seen{$nid}++;
 }
 for my$item(@{$STATE{pending}}){
  my$c=int($item->{created}||0);$out{oldest_at}=$c if$c&&(!$out{oldest_at}||$c<$out{oldest_at});
  my%wanted=map{($_=>1)}item_target_ids($item);my%pending_net;
  for my$t(enabled_targets()){
   next unless$wanted{$t->{id}};next if$item->{delivered}{$t->{id}};
   my$m=$t->{metric};$out{$m}++;
   my$mk=$m.'_oldest_at';$out{$mk}=$c if$c&&(!$out{$mk}||$c<$out{$mk});
   $pending_net{$t->{net}{id}}=1;
  }
  for my$nid(keys%pending_net){
   $out{$nid}++;my$nk=$nid.'_oldest_at';$out{$nk}=$c if$c&&(!$out{$nk}||$c<$out{$nk});
  }
 }
 \%out;
}
sub mark_source_sent {
 my($item)=@_;return if$item->{counted};$item->{counted}=1;
 my$s=$item->{source}||'';
 $STATS{hook_sent}++if$s eq'hook';$STATS{poll_sent}++if$s eq'poll';
 $STATS{actions_sent}++if$s eq'actions';$STATS{rss_sent}++if$s eq'rss';
}
sub drop_queue_for_space {
 return 0 unless@{$STATE{pending}}>=MAX_PENDING;
 my$idx=-1;
 for my$i(0..$#{$STATE{pending}}){
  my$item=$STATE{pending}[$i];my$delivered=scalar keys%{$item->{delivered}||{}};
  if($delivered){$idx=$i;$STATS{queue_partial_dropped}++;last}
 }
 $idx=0 if$idx<0;
 my$gone=$STATE{pending}[$idx];note_broadcast_dropped($gone);
 splice@{$STATE{pending}},$idx,1;$STATS{queue_dropped}++;1;
}
sub enqueue {
 my($text,$src,$defer)=@_;my$now=time;$STATE{last_event_text}=$text;$STATE{last_event_source}=clean($src||'unknown');$STATE{last_event_at}=$now;
 record_history($text,$src,$now);drop_queue_for_space();
 my$item={id=>broadcast_event_id($src,$text,$now),text=>$text,source=>$src||'unknown',created=>int($now),targets=>[current_target_ids()],delivered=>{},counted=>0};
 push@{$STATE{pending}},$item;record_broadcast_enqueue($item);$STATS{broadcast_enqueued}++;
 save_state()unless$defer;1;
}
sub drain_queue {
 my@on=online_nets();return unless@on&&@{$STATE{pending}};my$changed=0;
 for my$net(@on){
  next if time<$net->{next_send};
  my@channels=net_channels($net);next unless@channels;
  my$start=int($net->{send_cursor}||0)%scalar(@channels);
  for my$off(0..$#channels){
   my$idx=($start+$off)%scalar(@channels);my$ch=$channels[$idx];next unless$ch->{joined};
   my$tid=delivery_target_id($net,$ch->{name});
   my($item)=grep{my%w=map{($_=>1)}item_target_ids($_);$w{$tid}&&!$_->{delivered}{$tid}}@{$STATE{pending}};
   next unless$item;
   $STATS{broadcast_delivery_attempts}++;
   if(!irc_msg($net,$ch->{name},$item->{text})){$STATS{broadcast_delivery_failures}++;next}
   my$at=int(time);$item->{delivered}{$tid}=$at;note_broadcast_delivery($item,$tid,$at);mark_source_sent($item);
   $net->{next_send}=time+$CFG{send_interval};$net->{send_cursor}=($idx+1)%scalar(@channels);$changed=1;
   $STATS{'irc_'.$net->{id}.'_sent'}++ if exists$STATS{'irc_'.$net->{id}.'_sent'};
   my$mk=target_metric_key($net,$ch->{name});$STATS{'irc_'.$mk.'_sent'}++ if exists$STATS{'irc_'.$mk.'_sent'};
   last;
  }
 }
 if($changed){
  my@keep;for my$item(@{$STATE{pending}}){if(all_networks_delivered($item)){note_broadcast_complete($item)}else{push@keep,$item}}
  $STATE{pending}=\@keep;save_state();
 }
}
sub irc_disconnect {
 my($net,$why)=@_;return unless$net;
 logmsg('WARN',"[$net->{label}] IRC disconnected: $why")if$why;$net->{up}=0;
 for my$ch(net_channels($net)){$ch->{joined}=0;$ch->{startup_sent}=0;$ch->{join_error}=clean($why||'disconnected');$ch->{next_join}=0}
 eval{close$net->{socket}if$net->{socket}};$net->{socket}=undef;$net->{buf}='';$net->{pong_deadline}=0;$net->{ping_token}='';
 schedule_reconnect($net);
}
sub irc_open_socket {
 my($net)=@_;return unless$net;
 my$timeout=$net->{id}eq'undernet'?$CFG{undernet_connect_timeout}:15;
 if($net->{tls}){
  return IO::Socket::SSL->new(PeerHost=>$net->{host},PeerPort=>$net->{port},Proto=>'tcp',SSL_verify_mode=>SSL_VERIFY_PEER,SSL_hostname=>$net->{host},Timeout=>$timeout);
 }
 IO::Socket::INET->new(PeerHost=>$net->{host},PeerPort=>$net->{port},Proto=>'tcp',Timeout=>$timeout);
}
sub irc_connect {
 my($net)=@_;return 0 unless$net&&$net->{enabled};
 my$transport=$net->{tls}?'TLS':'TCP';
 logmsg('INFO',"[$net->{label}] IRC $transport connecting to $net->{host}:$net->{port} as $net->{nick}");
 my$s=irc_open_socket($net);
 return logmsg('WARN',"[$net->{label}] IRC $transport connection failed"),0 unless$s;

 $s->autoflush(1);
 my$want_sasl=$net->{sasl_account}ne''&&$net->{sasl_password}ne'';
 $net->{sasl_state}=$want_sasl?'pending':'off';
 print{$s}encode('UTF-8',"CAP LS 302\r\n") if$want_sasl;
 print{$s}encode('UTF-8',"NICK $net->{nick}\r\nUSER $net->{user} 0 * :$net->{realname}\r\n");

 my@channels=net_channels($net);my%wanted=map{lc($_->{name})=>$_}@channels;my%joined;
 my$deadline=time+($net->{id}eq'undernet'?$CFG{undernet_register_timeout}:40);my$buf='';my$sel=IO::Select->new($s);my$join_sent=0;
 while(time<$deadline){
  my@r=($net->{tls}&&(eval{$s->pending}||0)>0)?($s):$sel->can_read(1);next unless@r;
  my$c='';my$n=sysread($s,$c,8192);return close($s),0 unless defined$n&&$n>0;$buf.=$c;
  while($buf=~s/^(.*?\n)//s){
   my$l=$1;$l=~s/[\r\n]+$//;
   if($l=~/^PING\s+:(.*)$/){print{$s}encode('UTF-8',"PONG :$1\r\n");next}

   if($want_sasl&&$l=~/\sCAP\s+\S+\s+LS(?:\s+\*)?\s+:(.*)$/i){
    my$caps=$1;
    if($caps=~/(?:^|\s)sasl(?:[=\s]|$)/i){print{$s}encode('UTF-8',"CAP REQ :sasl\r\n")}
    elsif($l!~/\sLS\s+\*\s+:/){
     if($net->{require_sasl}){logmsg('WARN',"[$net->{label}] SASL not advertised");close$s;return 0}
     print{$s}encode('UTF-8',"CAP END\r\n");$net->{sasl_state}='unavailable';
    }
    next;
   }
   if($want_sasl&&$l=~/\sCAP\s+\S+\s+ACK\s+:.*\bsasl\b/i){print{$s}encode('UTF-8',"AUTHENTICATE PLAIN\r\n");next}
   if($want_sasl&&$l=~/^AUTHENTICATE\s+\+$/i){print{$s}encode('UTF-8',"AUTHENTICATE $_\r\n") for sasl_plain_lines($net->{sasl_account},$net->{sasl_password});next}
   if($want_sasl&&$l=~/\s903\s/){$net->{sasl_state}='ok';print{$s}encode('UTF-8',"CAP END\r\n");logmsg('INFO',"[$net->{label}] SASL authenticated as $net->{sasl_account}");next}
   if($want_sasl&&$l=~/\s(?:904|905|906|907)\s/){
    $net->{sasl_state}='failed';
    if($net->{require_sasl}){logmsg('WARN',"[$net->{label}] SASL authentication failed");close$s;return 0}
    print{$s}encode('UTF-8',"CAP END\r\n");next;
   }

   if($l=~/\s001\s/&&!$join_sent){
    if($want_sasl&&$net->{require_sasl}&&$net->{sasl_state}ne'ok'){logmsg('WARN',"[$net->{label}] registration completed without required SASL");close$s;return 0}
    for my$ch(@channels){
     my$j=join_command($net,$ch);print{$s}encode('UTF-8',"$j\r\n") if$j ne'';
     $ch->{joined}=0;$ch->{join_error}='';$ch->{startup_sent}=0;$ch->{next_join}=time+($net->{id}eq'undernet'?$CFG{undernet_join_retry}:10);
    }
    $join_sent=1;
    if($net->{fast_registration}){
     my$was_joined=$net->{last_join}?1:0;
     $net->{socket}=$s;$net->{up}=1;$net->{buf}=$buf;$net->{next_send}=time;$net->{startup_sent}=0;$net->{last_join}=time;$net->{last_rx}=time;$net->{last_ping}=0;$net->{pong_deadline}=0;$net->{ping_token}='';$net->{send_cursor}=0;
     reset_reconnect($net);$STATS{'irc_'.$net->{id}.'_reconnects'}++ if$was_joined&&exists$STATS{'irc_'.$net->{id}.'_reconnects'};
     logmsg('INFO',"[$net->{label}] IRC registered; joining ".join(',',map{$_->{name}}@channels)." asynchronously");return 1;
    }
    next;
   }

   if($join_sent&&$l=~/^:\Q$net->{nick}\E![^ ]+\s+JOIN\s+:?(\S+)$/i){
    my$ch=lc(clean($1));if($wanted{$ch}){$joined{$ch}=1;mark_channel_joined($net,$ch)}
   }
   if($join_sent&&$l=~/\s366\s+\Q$net->{nick}\E\s+(\S+)\s+/i){
    my$ch=lc(clean($1));if($wanted{$ch}){$joined{$ch}=1;mark_channel_joined($net,$ch)}
   }
   if($join_sent&&keys(%joined)==keys(%wanted)){
    my$was_joined=$net->{last_join}?1:0;
    $net->{socket}=$s;$net->{up}=1;$net->{buf}='';$net->{next_send}=time;$net->{startup_sent}=0;$net->{last_join}=time;$net->{last_rx}=time;$net->{last_ping}=0;$net->{pong_deadline}=0;$net->{ping_token}='';$net->{send_cursor}=0;
    reset_reconnect($net);$STATS{'irc_'.$net->{id}.'_reconnects'}++ if$was_joined&&exists$STATS{'irc_'.$net->{id}.'_reconnects'};
    logmsg('INFO',"[$net->{label}] IRC joined ".join(',',map{$_->{name}}@channels));return 1;
   }

   if($join_sent&&$l=~/\s(?:403|405|471|473|474|475|477)\s+\Q$net->{nick}\E\s+(\S+)(?:\s|:)/i){
    my$ch=clean($1);if($wanted{lc($ch)}){logmsg('WARN',"[$net->{label}] JOIN rejected for $ch");close$s;return 0}
   }
   if($l=~/\s433\s/){logmsg('WARN',"[$net->{label}] nick $net->{nick} already in use");close$s;return 0}
   if($l=~/\s(?:432|464|465)\s/){logmsg('WARN',"[$net->{label}] registration rejected");close$s;return 0}
  }
 }
 logmsg('WARN',"[$net->{label}] IRC registration/JOIN timeout");close$s;0;
}
sub read_irc {
 my($net)=@_;return unless$net&&$net->{up}&&$net->{socket};
 if($net->{buf}!~/\n/){
  my$c='';my$n=sysread($net->{socket},$c,8192);
  return irc_disconnect($net,'read error')unless defined$n;
  return irc_disconnect($net,'connection closed')if$n==0;$net->{last_rx}=time;$net->{pong_deadline}=0;$net->{ping_token}='';$net->{buf}.=$c;
 }
 while($net->{buf}=~s/^(.*?\n)//s){
  my$l=$1;$l=~s/[\r\n]+$//;
  if($l=~/^PING\s+:(.*)$/){irc_raw($net,"PONG :$1");next}
  if($l=~/^(?::\S+\s+)?PONG(?:\s+\S+)?\s+:?(.*)$/i){$net->{pong_deadline}=0;$net->{ping_token}='';next}
  if($l=~/^ERROR\s*:(.*)$/i){irc_disconnect($net,'server ERROR: '.clean($1));return}

  # Runtime channel membership is tracked independently. This is essential for
  # Undernet's primary and secondary channels share one TCP connection.
  if($l=~/^:\Q$net->{nick}\E![^ ]+\s+JOIN\s+:?(\S+)$/i){
   my$ch=clean($1);
   if(channel_config($net,$ch)){
    my$new=mark_channel_joined($net,$ch);$net->{last_join}=time;
    logmsg('INFO',"[$net->{label}] IRC joined $ch") if$new;startup_announce($net);next;
   }
  }
  if($l=~/\s366\s+\Q$net->{nick}\E\s+(\S+)\s+/i){
   my$ch=clean($1);
   if(channel_config($net,$ch)){
    my$new=mark_channel_joined($net,$ch);$net->{last_join}=time;
    logmsg('INFO',"[$net->{label}] IRC joined $ch") if$new;startup_announce($net);next;
   }
  }
  if($l=~/\s(403|405|471|473|474|475|477)\s+\Q$net->{nick}\E\s+(\S+)(?:\s|:)/i){
   my($num,$ch)=($1,clean($2));my$c=channel_config($net,$ch);
   if($c){
    $STATS{irc_join_rejects}++;mark_channel_down($net,$ch,"JOIN rejected $num");
    logmsg('WARN',"[$net->{label}] JOIN rejected for $ch (numeric $num); network connection kept alive");
    if(scalar(net_channels($net))<=1){irc_disconnect($net,"JOIN rejected for $ch");return}
    next;
   }
  }
  if($l=~/^:([^!]+)![^ ]+\s+KICK\s+(\S+)\s+(\S+)\s*:?(.*)$/i&&lc($3)eq lc($net->{nick})&&channel_config($net,$2)){
   my($ch,$why)=(clean($2),clean($4));
   if(scalar(net_channels($net))>1){mark_channel_down($net,$ch,'kicked: '.$why);logmsg('WARN',"[$net->{label}] kicked from $ch; other channels stay online");next}
   irc_disconnect($net,'kicked from '.$ch.': '.$why);return
  }
  if($l=~/^:\Q$net->{nick}\E![^ ]+\s+PART\s+:?(\S+)(?:\s|$)/i&&channel_config($net,$1)){
   my$ch=clean($1);
   if(scalar(net_channels($net))>1){mark_channel_down($net,$ch,'parted');logmsg('WARN',"[$net->{label}] left $ch; scheduling channel rejoin");next}
   irc_disconnect($net,'left channel '.$ch);return
  }
  command($net,$1,$2,$3)if$l=~/^:([^!]+)![^ ]+\s+PRIVMSG\s+(\S+)\s+:(.*)$/;
 }
 irc_disconnect($net,'input buffer limit')if length($net->{buf})>16384;
}

# ── IRC commands ─────────────────────────────────────────────────────────────
sub reset_text { $RUN{rate_reset}=~/^\d+$/?scalar localtime($RUN{rate_reset}):'?' }
sub hook_status { "$CFG{hook_bind}:$CFG{hook_port}$CFG{hook_path}" }
sub command {
 my($net,$from,$to,$msg)=@_;return unless$msg=~/^!github(?:\s+(\S+)(?:\s+(.+?))?)?\s*$/i;
 my$key=$net->{id}."\x1f".lc($from);my$now=time;
 if($CFG{cmd_cooldown}>0&&$RUN{cmd_last}{$key}&&$now-$RUN{cmd_last}{$key}<$CFG{cmd_cooldown}){$STATS{command_throttled}++;return}
 $RUN{cmd_last}{$key}=$now;
 if(keys(%{$RUN{cmd_last}})>500){delete$RUN{cmd_last}{$_} for grep{$RUN{cmd_last}{$_}<$now-3600}keys%{$RUN{cmd_last}}}
 my$cmd=lc($1//'help');my$arg=clean($2//'');my$r=lc($to)eq lc($net->{nick})?$from:$to;my$s=sep();

 if($cmd eq'status'){
  my($as,$cs,$rs,$hs,$ts)=(api_state(),actions_state(),rss_state(),webhook_state(),traffic_state());
  my$q=@{$STATE{pending}}?paint(8,scalar(@{$STATE{pending}}).' queued'):paint(3,'queue clear');
  irc_msg($net,$r,icon('github').' '.tag().'Watch '.paint(10,'v'.VERSION).$s.paint(6,$CFG{repo}).$s.
   $NET{epiknet}{label}.' '.paint(!$NET{epiknet}{enabled}?14:$NET{epiknet}{up}?3:4,!$NET{epiknet}{enabled}?'DISABLED':$NET{epiknet}{up}?'ON':'OFF').$s.
   ($NET{libera}{enabled}?$NET{libera}{label}.' '.paint($NET{libera}{up}?3:4,$NET{libera}{up}?'ON':'OFF').$s:'').
   ($NET{undernet}{enabled}?$NET{undernet}{label}.' '.paint($NET{undernet}{up}?3:4,$NET{undernet}{up}?'ON':'OFF').$s:'').
   icon('api').' '.paint(state_color_num($as),'API '.uc($as)).$s.
   icon('ci').' '.paint(state_color_num($cs),'CI '.uc($cs)).$s.
   icon('stats').' '.paint(state_color_num($ts),'TRAFFIC '.uc($ts)).$s.
   icon('forum').' '.paint(state_color_num($rs),'RSS '.uc($rs)).$s.icon('queue').' '.$q);
  my$pa=account_summary();irc_msg($net,$r,icon('repo').' '.paint(11,bold($CFG{account}.' portfolio')).$s.paint(state_color_num($pa->{state}),uc($pa->{state})).$s.'public repos '.paint(10,$pa->{repositories}).$s.'active 30d '.paint(10,$pa->{active_30d}).$s.'stars '.paint(10,$pa->{stars}).$s.'updated '.paint(14,$pa->{last_ok}?age($pa->{last_ok}):'never'));
  return
 }
 if($cmd eq'health'){
  my($h,$a,$ci,$rss)=(webhook_state(),api_state(),actions_state(),rss_state());my$hr=health_report();my@bt=broadcast_target_snapshot();my$joined=scalar grep{$_->{joined}}@bt;
  irc_msg($net,$r,icon('health').' '.paint($hr->{status}eq'ok'?3:8,bold('Health '.uc($hr->{status}))).$s.
   'targets '.paint($joined==scalar(@bt)?3:8,$joined.'/'.scalar(@bt)).$s.
   'webhook '.paint(state_color_num($h),$h).$s.'API '.paint(state_color_num($a),$a).$s.
   'CI '.paint(state_color_num($ci),$ci).$s.'RSS '.paint(state_color_num($rss),$rss).$s.
   'queue '.paint(@{$STATE{pending}}?8:3,scalar@{$STATE{pending}}));
  if(@{$hr->{issues}}){my@i=@{$hr->{issues}};splice@i,4 if@i>4;irc_msg($net,$r,paint(8,bold('Issues')).$s.join($s,map{irc_short($_,70)}@i))}
  return
 }
 if($cmd eq'auth'){
  my$st=$RUN{auth_state}eq'verified'&&$RUN{auth_events}eq'ok'?paint(3,bold('TOKEN VERIFIED')):$RUN{auth_state}eq'rejected'?paint(4,bold('TOKEN REJECTED')):$RUN{auth_state}eq'anonymous'?paint(8,bold('ANONYMOUS')):paint(8,bold('TOKEN LIMITED'));
  my$user=$RUN{auth_login}ne''?paint(10,$RUN{auth_login}):paint(14,'n/a');
  my$access=$RUN{auth_events}eq'ok'?paint(3,'repo events OK'):$RUN{auth_events}eq'public'?paint(8,'public fallback'):paint(4,$RUN{auth_events}||'unchecked');
  my$aa=$RUN{actions_auth_mode}eq'authenticated'?paint(3,'CI authenticated'):$RUN{actions_auth_mode}eq'anonymous-fallback'?paint(8,'CI public fallback'):paint(14,'CI '.$RUN{actions_auth_mode});
  irc_msg($net,$r,icon('auth').' '.paint(11,bold('GitHub Auth')).$s.$st.$s.'user '.$user.$s.'access '.$access.$s.$aa.$s.'quota '.paint(10,"$RUN{rate_remaining}/$RUN{rate_limit}"));
  return
 }
 if($cmd eq'ci'){
  my$cs=actions_state();my$st=paint(state_color_num($cs),bold(uc($cs)));
  my$mode=$CFG{actions_fail_only}?'failures + recovery':'all completed runs';
  my$last=$STATE{last_actions_ok}?paint(3,age($STATE{last_actions_ok})):paint(14,'never');
  my$run=$STATE{last_action_name}?paint(10,irc_short($STATE{last_action_name},70)).' '.state_color($STATE{last_action_conclusion}):paint(14,'no completed run cached');
  my$red=current_ci_failure_count();my$running=current_ci_running_count();my$expected=current_ci_expected_count();my$flaky=current_ci_flaky_count();
  irc_msg($net,$r,icon('ci').' '.paint(11,bold('GitHub Actions')).$s.$st.$s.$mode.$s.
   'red '.paint($red?4:3,$red).$s.'running '.paint($running?8:3,$running).$s.($CFG{actions_expect}?'expected '.paint($expected?8:3,$expected).$s:'').($CFG{actions_flaky_window}?'flaky '.paint($flaky?8:3,$flaky).$s:'').
   'idle '.paint(6,$CFG{actions_idle}.'s').' / fast '.paint(6,$CFG{actions_fast}.'s').$s.
   'last API '.$last.$s.'latest '.$run.$s.'slow alert '.($CFG{actions_slow}?paint(8,duration_text($CFG{actions_slow})):paint(14,'off')).$s.
   'failed-job detail '.($CFG{actions_enrich}?paint(3,'on'):paint(14,'off')));
  return
 }
 if($cmd eq'reliability'||$cmd eq'slo'){
  my$x=ci_reliability_summary();my$state=$x->{state};my$color=$state eq'stable'?3:$state eq'degraded'?4:$state eq'watch'?8:14;
  if(!$x->{decisive_runs}){irc_msg($net,$r,icon('ci').' '.paint($color,bold('CI reliability '.uc($state))).$s.'waiting for completed decisive runs');return}
  irc_msg($net,$r,icon('ci').' '.paint(11,bold('CI reliability · '.$x->{window_days}.'d')).$s.paint($color,uc($state)).$s.
   'pass '.paint($x->{pass_rate}>=95?3:$x->{pass_rate}>=80?8:4,$x->{pass_rate}.'%').$s.
   paint(10,$x->{success}.' success / '.$x->{failed}.' failed').$s.'coverage '.paint(14,$x->{coverage_days}.'d · '.$x->{runs}.' runs retained'));
  irc_msg($net,$r,icon('time').' '.paint(11,bold('CI recovery')).$s.
   'active '.paint($x->{active_incidents}?4:3,$x->{active_incidents}).$s.'resolved '.paint(10,$x->{resolved_incidents}).$s.
   'MTTR '.paint(10,$x->{resolved_incidents}?duration_text($x->{mttr_seconds}):'n/a').$s.
   'p95 runtime '.paint(10,$x->{p95_duration_seconds}?duration_text($x->{p95_duration_seconds}):'n/a').$s.
   'green streak '.paint($x->{green_streak}?3:14,$x->{green_streak}));
  return
 }
 if($cmd eq'incident'||$cmd eq'incidents'){
  my$x=ci_reliability_summary();my@active=@{$x->{active}};my@resolved=@{$x->{resolved}};
  if(!@active&&!@resolved){irc_msg($net,$r,icon('ci').' '.paint(3,bold('CI incidents')).$s.'none in retained history');return}
  if(@active){irc_msg($net,$r,icon('ci').' '.paint(4,bold('Active CI incidents')).$s.scalar(@active));my$limit=@active>3?3:scalar@active;for my$i(0..$limit-1){my$f=$active[$i];my$line=paint(10,irc_short($f->{name},65)).' on '.paint(10,irc_short($f->{branch},35)).' · '.paint(4,uc($f->{conclusion}||'failure')).' · open '.paint(14,$f->{at}?age($f->{at}):'time unknown');$line.=' — '.$f->{url}if$f->{url};irc_msg($net,$r,$line)}}
  if(@resolved){my$z=$resolved[0];irc_msg($net,$r,icon('health').' '.paint(11,bold('Latest recovery')).$s.paint(10,irc_short($z->{name},65)).' on '.paint(10,irc_short($z->{branch},35)).$s.'after '.paint(3,duration_text($z->{duration})).$s.'failed runs '.paint(14,$z->{failures}).($z->{recovery_url}?' — '.$z->{recovery_url}:''))}
  return
 }
 if($cmd eq'failures'){
  my@f=current_ci_failures();
  if(!@f){irc_msg($net,$r,icon('ci').' '.paint(3,bold('CI failures')).$s.'none currently tracked');return}
  my$limit=@f>3?3:scalar@f;
  irc_msg($net,$r,icon('ci').' '.paint(4,bold('Current CI failures')).$s.paint(4,scalar(@f)).' tracked'.(@f>$limit?$s.'showing '.$limit:''));
  for my$i(0..$limit-1){
   my$f=$f[$i];my$extra=(int($f->{attempt}||1)>1?' · attempt '.int($f->{attempt}):'').($f->{duration}?' · '.duration_text($f->{duration}):'');my$line=paint(10,irc_short($f->{name},70)).' on '.paint(10,irc_short($f->{branch},40)).
    ' — '.paint(4,uc($f->{conclusion}||'failure')).$extra.($f->{at}?$s.paint(14,age($f->{at})):'');
   $line.=' — '.$f->{url} if$f->{url} ne'';
   irc_msg($net,$r,$line);
  }
  return
 }
 if($cmd eq'flaky'){
  if(!$CFG{actions_flaky_window}){irc_msg($net,$r,icon('ci').' '.paint(14,bold('CI flaky detector')).$s.'disabled');return}
  my@f=current_ci_flaky();
  if(!@f){irc_msg($net,$r,icon('ci').' '.paint(3,bold('CI flaky detector')).$s.'no workflow currently flapping');return}
  my$limit=@f>3?3:scalar@f;irc_msg($net,$r,icon('ci').' '.paint(8,bold('Flaky CI')).$s.scalar(@f).' tracked'.(@f>$limit?$s.'showing '.$limit:''));
  for my$i(0..$limit-1){my$f=$f[$i];my$line=paint(10,irc_short($f->{name},65)).' on '.paint(10,irc_short($f->{branch},35)).' · '.paint(8,$f->{transitions}.' changes').' / '.duration_text($CFG{actions_flaky_window});$line.=' — '.$f->{url} if$f->{url};irc_msg($net,$r,$line)}
  return
 }
 if($cmd eq'running'){
  my@c=current_ci_running();
  if(!@c){irc_msg($net,$r,icon('ci').' '.paint(3,bold('Running CI')).$s.'none currently tracked');return}
  my$limit=@c>$CFG{actions_running_max}?$CFG{actions_running_max}:scalar@c;
  irc_msg($net,$r,icon('ci').' '.paint(8,bold('Running CI')).$s.paint(8,scalar(@c)).' tracked'.(@c>$limit?$s.'showing '.$limit:''));
  for my$i(0..$limit-1){
   my$c=$c[$i];my$elapsed=$c->{started_at}?duration_text(time-$c->{started_at}):'?';
   my$attempt=int($c->{attempt}||1)>1?' · attempt '.int($c->{attempt}):'';my$line=paint(10,irc_short($c->{name},65)).' on '.paint(10,irc_short($c->{branch},35)).
    ' — '.paint(8,uc($c->{status}||'running')).' '.paint(14,$elapsed).$attempt;
   $line.=' — '.$c->{url} if($c->{url}||'')ne'';
   irc_msg($net,$r,$line);
  }
  return
 }
 if($cmd eq'expected'){
  if(!$CFG{actions_expect}){irc_msg($net,$r,icon('ci').' '.paint(14,bold('Expected CI')).$s.'disabled · set GITHUB_ACTIONS_EXPECT_AFTER_PUSH_SECONDS to enable');return}
  my@x=current_ci_expected();if(!@x){irc_msg($net,$r,icon('ci').' '.paint(3,bold('Expected CI')).$s.'none pending');return}
  my$limit=@x>3?3:scalar@x;irc_msg($net,$r,icon('ci').' '.paint(8,bold('Expected CI')).$s.scalar(@x).' waiting'.(@x>$limit?$s.'showing '.$limit:''));
  for my$i(0..$limit-1){my$x=$x[$i];my$sha=substr(clean($x->{sha}||''),0,7);my$wait=$x->{at}?duration_text(time-$x->{at}):'?';irc_msg($net,$r,paint(10,irc_short($x->{branch}||'repository',40)).' @ '.paint(14,$sha).' · waiting '.paint($x->{alerted}?4:8,$wait).($x->{alerted}?' · alerted':''))}
  return
 }
 if($cmd eq'schedule'){
  my$now=time;my$due=sub{my($t)=@_;return'due now'if!$t||$t<=$now;duration_text($t-$now)};my$fast=time<$RUN{actions_fast_until}?'fast '.duration_text($RUN{actions_fast_until}-time).' left':'idle';
  irc_msg($net,$r,icon('time').' '.paint(11,bold('Scheduler')).$s.'Events '.paint(10,$due->($RUN{next_poll})).$s.'Actions '.paint(10,$due->($RUN{actions_next})).' '.paint(14,"($fast)").$s.($CFG{traffic_enabled}?'Traffic '.paint(10,$due->($RUN{traffic_next})).$s:'').'RSS '.paint(10,$due->($RUN{rss_next})).$s.'GitHub REST '.(github_rest_allowed()?paint(3,'ready'):paint(8,'paused '.rate_resume_text())).$s.'heartbeat '.($CFG{irc_idle_ping}?paint(10,$CFG{irc_idle_ping}.'s/'.$CFG{irc_pong_timeout}.'s'):paint(14,'off')));
  return
 }
 if($cmd eq'summary'){
  my$h=health_report();my$red=current_ci_failure_count();my$run=current_ci_running_count();my$exp=current_ci_expected_count();my$q=queue_snapshot();
  irc_msg($net,$r,icon('health').' '.paint($h->{status} eq 'ok'?3:8,bold('Summary '.uc($h->{status}))).$s.
   'EpiKnet '.paint(!$NET{epiknet}{enabled}?14:$NET{epiknet}{up}?3:4,!$NET{epiknet}{enabled}?'OFF':$NET{epiknet}{up}?'ON':'OFF').$s.'Libera '.paint(!$NET{libera}{enabled}?14:$NET{libera}{up}?3:4,!$NET{libera}{enabled}?'OFF':$NET{libera}{up}?'ON':'OFF').$s.
   'Undernet '.paint(!$NET{undernet}{enabled}?14:$NET{undernet}{up}?3:4,!$NET{undernet}{enabled}?'OFF':$NET{undernet}{up}?'ON':'OFF').$s.
   'CI red '.paint($red?4:3,$red).' / running '.paint($run?8:3,$run).($CFG{actions_expect}?' / expected '.paint($exp?8:3,$exp):'').$s.'queue '.paint($q->{total}?8:3,$q->{total}));
  my$tt=traffic_summary_data();
  irc_msg($net,$r,icon('github').' '.paint(11,bold('Sources')).$s.'hook '.paint(state_color_num(webhook_state()),webhook_state()).$s.'events '.paint(state_color_num(api_state()),api_state()).$s.'actions '.paint(state_color_num(actions_state()),actions_state()).$s.'traffic '.paint(state_color_num(traffic_state()),traffic_state()).$s.'RSS '.paint(state_color_num(rss_state()),rss_state()).$s.'latest '.paint(14,$STATE{last_event_at}?age($STATE{last_event_at}):'none'));
  irc_msg($net,$r,icon('stats').' '.paint(11,bold('Repo pulse')).$s.'14d clones '.paint(10,$tt->{clones}).' / '.paint(10,$tt->{clone_uniques}.' unique').$s.'views '.paint(10,$tt->{views}).' / '.paint(10,$tt->{view_uniques}.' unique').$s.'broadcast '.paint(10,$STATS{broadcast_completed}.'/'.$STATS{broadcast_enqueued}));
  return
 }
 if($cmd eq'pulse'||$cmd eq'now'){
  my$t=traffic_summary_data();my$h=health_report();my$q=queue_snapshot();my@bt=broadcast_target_snapshot();my$joined=scalar grep{$_->{joined}}@bt;
  my$ct=traffic_recent_trend('clones');my$vt=traffic_recent_trend('views');
  irc_msg($net,$r,icon('github').' '.paint(11,bold('Repository pulse')).$s.paint($h->{status}eq'ok'?3:8,uc($h->{status})).$s.
   'CI red '.paint(current_ci_failure_count()?4:3,current_ci_failure_count()).' / running '.paint(current_ci_running_count()?8:3,current_ci_running_count()).$s.
   'fan-out '.paint($joined==scalar(@bt)?3:8,$joined.'/'.scalar(@bt)).$s.'queue '.paint($q->{total}?8:3,$q->{total}));
 irc_msg($net,$r,icon('stats').' '.paint(11,bold('Traffic now')).$s.
   'clones '.paint(10,$ct->{current}.' / '.$t->{last_clone}{uniques}.' unique').' today '.paint($ct->{delta}>0?3:$ct->{delta}<0?8:14,($ct->{delta}>0?'+':'').$ct->{delta}).$s.
   'views '.paint(10,$vt->{current}.' / '.$t->{last_view}{uniques}.' unique').' today '.paint($vt->{delta}>0?3:$vt->{delta}<0?8:14,($vt->{delta}>0?'+':'').$vt->{delta}).$s.
   '14d '.paint(10,$t->{clones}.' clones / '.$t->{views}.' views'));
  if($STATE{last_event_text}){irc_msg($net,$r,icon('latest').' '.paint(11,bold('Latest')).$s.paint(14,$STATE{last_event_at}?age($STATE{last_event_at}):'time unknown').$s.irc_short($STATE{last_event_text},250))}
  return
 }
 if($cmd eq'today'){
  my$t=traffic_summary_data();my$ct=traffic_recent_trend('clones');my$vt=traffic_recent_trend('views');my$a=traffic_audience_summary();
  irc_msg($net,$r,icon('stats').' '.paint(11,bold('Today')).$s.
   'clones '.paint(10,$ct->{current}).' / '.paint(10,$a->{today_clone_uniques}.' unique').' '.paint($ct->{delta}>0?3:$ct->{delta}<0?8:14,($ct->{delta}>0?'+':'').$ct->{delta}).$s.
   'views '.paint(10,$vt->{current}).' / '.paint(10,$a->{today_view_uniques}.' unique').' '.paint($vt->{delta}>0?3:$vt->{delta}<0?8:14,($vt->{delta}>0?'+':'').$vt->{delta}).$s.
   '14d '.paint(10,$t->{clones}.' clones / '.$t->{views}.' views'));
  if($STATE{last_event_text}){irc_msg($net,$r,icon('latest').' '.paint(11,bold('Latest activity')).$s.paint(14,$STATE{last_event_at}?age($STATE{last_event_at}):'time unknown').$s.irc_short($STATE{last_event_text},255))}
  return
 }
 if($cmd eq'snapshot'||$cmd eq'lateststats'||$cmd eq'clones'){
  my$l=traffic_latest_snapshot();
  if(!$l->{date}){irc_msg($net,$r,icon('stats').' '.paint(14,bold('Latest traffic')).$s.'traffic data not cached yet');return}
  my$sign=sub{$_[0]>0?'+'.$_[0]:$_[0]};
  irc_msg($net,$r,icon('stats').' '.paint(11,bold('Latest GitHub traffic')).$s.paint(14,$l->{date}.($l->{partial}?' · live UTC day':' · closed UTC day')).$s.
   'clones '.paint(10,$l->{clones}).' / '.paint(10,$l->{clone_uniques}.' unique').$s.
   'views '.paint(10,$l->{views}).' / '.paint(10,$l->{view_uniques}.' unique'));
  irc_msg($net,$r,icon('stats').' '.paint(11,bold('Since previous day')).$s.
   'clones '.paint($l->{clone_delta}>0?3:$l->{clone_delta}<0?8:14,$sign->($l->{clone_delta})).' / unique '.paint($l->{clone_unique_delta}>0?3:$l->{clone_unique_delta}<0?8:14,$sign->($l->{clone_unique_delta})).$s.
   'refreshed '.paint(14,$l->{refreshed_at}?age($l->{refreshed_at}):'time unknown'));
  return
 }
 if($cmd eq'history'){
  my$h=traffic_history_summary();
  if(!$h->{days}){irc_msg($net,$r,icon('stats').' '.paint(14,bold('Traffic history')).$s.'no daily snapshots cached yet');return}
  irc_msg($net,$r,icon('stats').' '.paint(11,bold('Traffic history')).$s.
   paint(10,$h->{days}.' daily snapshot'.($h->{days}==1?'':'s')).$s.paint(14,$h->{from}.' → '.$h->{to}).$s.
   'retention '.paint(10,$h->{retention_days}.' days').$s.paint(14,'14d totals stay exact GitHub aggregates'));
  return
 }
 if($cmd eq'problems'){
  my$h=health_report();my@f=current_ci_failures();my$q=queue_snapshot();my@bt=broadcast_target_snapshot();my@p=@{$h->{issues}||[]};
  push@p,scalar(@f).' current CI failure'.(@f==1?'':'s') if@f;
  for my$b(@bt){push@p,$b->{label}.' '.$b->{channel}.' has '.$b->{pending}.' pending' if$b->{pending}}
  if(!@p){irc_msg($net,$r,icon('health').' '.paint(3,bold('Problems')).$s.'none · everything currently looks healthy');return}
  irc_msg($net,$r,icon('health').' '.paint(8,bold('Problems')).$s.scalar(@p).' item'.(@p==1?'':'s'));
  splice@p,6 if@p>6;for my$p(@p){irc_msg($net,$r,paint(8,'•').' '.irc_short($p,300))}
  return
 }
 if($cmd eq'audience'||$cmd eq'uniques'){
  my$a=traffic_audience_summary();
  if(!$STATE{last_traffic_ok}){irc_msg($net,$r,icon('stats').' '.paint(14,bold('Audience')).$s.'traffic data not cached yet');return}
  irc_msg($net,$r,icon('stats').' '.paint(11,bold('Audience · exact GitHub 14d')).$s.
   'clones '.paint(10,$a->{clones}).' / '.paint(10,$a->{clone_uniques}.' unique cloners').$s.
   'views '.paint(10,$a->{views}).' / '.paint(10,$a->{view_uniques}.' unique visitors'));
  irc_msg($net,$r,icon('stats').' '.paint(11,bold('Today')).$s.
   'clones '.paint(10,$a->{today_clones}).' / '.paint(10,$a->{today_clone_uniques}.' unique').$s.
   'views '.paint(10,$a->{today_views}).' / '.paint(10,$a->{today_view_uniques}.' unique').$s.
   'updated '.paint(14,$a->{last_ok}?age($a->{last_ok}):'never'));
  irc_msg($net,$r,icon('stats').' '.paint(11,bold('Audience depth')).$s.
   'clones / cloner '.paint(10,traffic_num($a->{clones_per_unique},2)).$s.
   'views / visitor '.paint(10,traffic_num($a->{views_per_unique},2)).$s.
   'daily unique avg '.paint(10,traffic_num($a->{avg_daily_clone_uniques},1).' cloners / '.traffic_num($a->{avg_daily_view_uniques},1).' visitors'));
  irc_msg($net,$r,paint(14,'Unique cloners/visitors are GitHub aggregate metrics; raw visitor IP addresses are not exposed.'));
  return
 }
 if($cmd eq'trend'){
  my$a=traffic_audience_summary();my$ct=traffic_recent_trend('clones');my$vt=traffic_recent_trend('views');
  my$cu=traffic_recent_trend('clone_uniques');my$vu=traffic_recent_trend('view_uniques');
  irc_msg($net,$r,icon('stats').' '.paint(11,bold('Traffic trend')).$s.
   'clones today '.paint(10,$ct->{current}).' '.paint($ct->{delta}>0?3:$ct->{delta}<0?8:14,($ct->{delta}>0?'+':'').$ct->{delta}).' vs previous'.$s.
   'views today '.paint(10,$vt->{current}).' '.paint($vt->{delta}>0?3:$vt->{delta}<0?8:14,($vt->{delta}>0?'+':'').$vt->{delta}).' vs previous');
  irc_msg($net,$r,icon('stats').' '.paint(11,bold('Unique audience trend')).$s.
   'cloners '.paint(10,$cu->{current}).' '.paint($cu->{delta}>0?3:$cu->{delta}<0?8:14,($cu->{delta}>0?'+':'').$cu->{delta}).$s.
   'visitors '.paint(10,$vu->{current}).' '.paint($vu->{delta}>0?3:$vu->{delta}<0?8:14,($vu->{delta}>0?'+':'').$vu->{delta}).$s.
   paint(14,'daily GitHub uniques, not IP addresses'));
  irc_msg($net,$r,icon('stats').' '.paint(11,bold('14d efficiency')).$s.
   'clones / unique cloner '.paint(10,traffic_num($a->{clones_per_unique},2)).$s.
   'views / unique visitor '.paint(10,traffic_num($a->{views_per_unique},2)).$s.
   'avg/day '.paint(10,traffic_num($a->{avg_clones},1).' clones / '.traffic_num($a->{avg_views},1).' views'));
  return
 }
 if($cmd eq'week'||$cmd eq'compare'){
  my$x=traffic_period_comparison(7);my$c=$x->{current};my$p=$x->{previous};
  if(!$c->{days_reported}){irc_msg($net,$r,icon('stats').' '.paint(14,bold('7-day comparison')).$s.'traffic data not cached yet');return}
  my$fmt=sub{my($z)=@_;my$sign=$z->{delta}>0?'+':'';traffic_num($z->{current},1).' ('.$sign.traffic_num($z->{delta},1).', '.$sign.traffic_num($z->{pct},1).'%)'};
  irc_msg($net,$r,icon('stats').' '.paint(11,bold('Last 7d vs previous 7d')).$s.
   'clones '.paint(10,$fmt->($x->{changes}{clones})).$s.'views '.paint(10,$fmt->($x->{changes}{views})).$s.
   paint(14,$c->{days_reported}.'/'.$p->{days_reported}.' reported days'));
  irc_msg($net,$r,icon('stats').' '.paint(11,bold('Daily unique average')).$s.
   'cloners '.paint(10,$fmt->($x->{changes}{avg_daily_clone_uniques})).$s.
   'visitors '.paint(10,$fmt->($x->{changes}{avg_daily_view_uniques})).$s.
   paint(14,'daily GitHub aggregates'));
  return
 }
 if($cmd eq'peaks'){
  my$p=traffic_peak_summary();
  if(!%{$p->{clones}}){irc_msg($net,$r,icon('stats').' '.paint(14,bold('Traffic peaks')).$s.'traffic data not cached yet');return}
  my$date=sub{substr(clean($_[0]{date}||''),0,10)||'?'};
  irc_msg($net,$r,icon('stats').' '.paint(11,bold('Clone peaks · 14d')).$s.
   'total '.paint(10,int($p->{clones}{clones}||0)).' on '.paint(14,$date->($p->{clones})).$s.
   'unique '.paint(10,int($p->{clone_uniques}{clone_uniques}||0)).' on '.paint(14,$date->($p->{clone_uniques})));
  irc_msg($net,$r,icon('stats').' '.paint(11,bold('Visitor peaks · 14d')).$s.
   'views '.paint(10,int($p->{views}{views}||0)).' on '.paint(14,$date->($p->{views})).$s.
   'unique '.paint(10,int($p->{view_uniques}{view_uniques}||0)).' on '.paint(14,$date->($p->{view_uniques})));
  return
 }
 if($cmd eq'freshness'){
  irc_msg($net,$r,icon('time').' '.paint(11,bold('Source freshness')).$s.
   'webhook '.paint(10,$STATE{last_hook_ok}?age($STATE{last_hook_ok}):'never').$s.
   'events '.paint(10,$RUN{last_api_ok}?age($RUN{last_api_ok}):'never').$s.
   'CI '.paint(10,$STATE{last_actions_ok}?age($STATE{last_actions_ok}):'never').$s.
   'traffic '.paint(10,$STATE{last_traffic_ok}?age($STATE{last_traffic_ok}):'never').$s.
   'portfolio '.paint(10,$STATE{last_account_ok}?age($STATE{last_account_ok}):'never').$s.
   'RSS '.paint(10,$STATE{last_rss_ok}?age($STATE{last_rss_ok}):'never'));
  return
 }
 if($cmd eq'top'){
  my@refs=traffic_top('referrers');my@paths=traffic_top('paths');
  my$tr=@refs?$refs[0]:undef;my$tp=@paths?$paths[0]:undef;
  irc_msg($net,$r,icon('stats').' '.paint(11,bold('Top traffic · 14d')).$s.
   'referrer '.($tr?paint(10,irc_short($tr->{referrer}||'direct',65)).' '.int($tr->{count}||0).' / '.int($tr->{uniques}||0).' unique':paint(14,'n/a')).$s.
   'path '.($tp?paint(10,irc_short($tp->{path}||'/',65)).' '.int($tp->{count}||0).' / '.int($tp->{uniques}||0).' unique':paint(14,'n/a')));
  return
 }
 if($cmd eq'dashboard'){
  if($CFG{dashboard_public_url}ne''){irc_msg($net,$r,icon('api').' '.paint(11,bold('Live dashboard')).$s.paint(10,$CFG{dashboard_public_url}));return}
  irc_msg($net,$r,icon('api').' '.paint(14,bold('Live dashboard')).$s.'public URL not configured · set '.paint(10,'DASHBOARD_PUBLIC_URL'));
  return
 }
 if($cmd eq'state'){
  my$st=state_status();my$p=$st->{primary};my$b=$st->{backup};
  irc_msg($net,$r,icon('shield').' '.paint(11,bold('Persistent state')).$s.'primary '.paint($p eq'ok'?3:$p eq'missing'?14:4,uc($p)).$s.'backup '.paint($b eq'ok'?3:$b eq'missing'?14:4,uc($b)).$s.'loaded '.paint(10,$st->{loaded_from}).$s.'last save '.paint(14,$st->{last_saved}?age($st->{last_saved}):'never').$s.'backups '.paint(10,$STATS{state_backups}).' / recoveries '.paint($STATS{state_recoveries}?8:3,$STATS{state_recoveries}).' / errors '.paint($STATS{state_save_errors}?4:3,$STATS{state_save_errors}));
  return
 }
 if($cmd eq'alerts'){
  my$h=health_report();irc_msg($net,$r,icon('health').' '.paint(11,bold('Operational alerts')).$s.($CFG{ops_alerts}?paint(3,'ON'):paint(14,'OFF')).$s.'health '.paint($h->{status} eq 'ok'?3:8,uc($h->{status})).$s.'debounce '.paint(10,$CFG{ops_debounce}.'s').$s.'degraded '.paint(10,$STATS{ops_degraded_alerts}).' / recovered '.paint(10,$STATS{ops_recovery_alerts}));
  return
 }
 if($cmd eq'recent'){
  my@h=recent_history($CFG{history_show});
  if(!@h){irc_msg($net,$r,icon('latest').' '.paint(14,'No activity history yet'));return}
  irc_msg($net,$r,icon('latest').' '.paint(11,bold('Recent activity')).$s.scalar(@h).' latest');
  for my$h(@h){
   my$when=$h->{at}?age($h->{at}):'time unknown';
   irc_msg($net,$r,paint(14,'['.uc($h->{source}||'event').' '.$when.']').' '.irc_short($h->{text},260));
  }
  return
 }
 if($cmd eq'queue'){
  my$q=queue_snapshot();my$old=$q->{oldest_at}?age($q->{oldest_at}):'none';
  irc_msg($net,$r,icon('queue').' '.paint(11,bold('Delivery queue')).$s.'total '.paint($q->{total}?8:3,$q->{total}).$s.'oldest '.paint(14,$old).$s.'dropped '.paint($STATS{queue_dropped}?4:3,$STATS{queue_dropped}).' / partial '.paint(14,$STATS{queue_partial_dropped}));
  my@parts;for my$t(enabled_targets()){my$m=$t->{metric};my$c=channel_config($t->{net},$t->{channel});my$st=$c&&$c->{joined}?paint(3,'ON'):$t->{net}{up}?paint(8,'WAIT'):paint(4,'OFF');push@parts,$t->{net}{label}.' '.paint(10,$t->{channel}).' '.$st.' pending '.paint($q->{$m}?8:3,int($q->{$m}||0)).' oldest '.paint(14,$q->{$m.'_oldest_at'}?age($q->{$m.'_oldest_at'}):'none')}
  while(@parts){irc_msg($net,$r,join($s,splice(@parts,0,2)))}
  return
 }
 if($cmd eq'last'){
  if($STATE{last_event_text}){my$src=uc($STATE{last_event_source}||'legacy');my$when=$STATE{last_event_at}?$s.paint(14,age($STATE{last_event_at})) :'';
   irc_msg($net,$r,icon('latest').' '.paint(6,bold('Latest')).' '.paint(14,"[$src]").$when.$s.$STATE{last_event_text})
  }else{irc_msg($net,$r,icon('latest').' '.paint(14,'No public activity cached yet'))}
  return
 }
 if($cmd eq'rate'){my$rest=github_rest_allowed()?paint(3,'REST ready'):paint(8,'REST paused '.rate_resume_text());irc_msg($net,$r,icon('rate').' '.tag().' API'.$s.'quota '.paint(10,"$RUN{rate_remaining}/$RUN{rate_limit}").$s.$rest.$s.'reset '.paint(10,reset_text()).$s.'last OK '.paint(3,age($RUN{last_api_ok})).$s.'events poll '.paint(6,maxn($CFG{reconcile},$RUN{poll_min}).'s').$s.'CI '.paint(6,actions_delay().'s'));return}
 if($cmd eq'traffic'){
  my$t=traffic_summary_data();my$st=traffic_state();
  if($st eq'off'){irc_msg($net,$r,icon('stats').' '.paint(14,bold('GitHub Traffic')).$s.'disabled');return}
  if($st eq'needs_token'){irc_msg($net,$r,icon('stats').' '.paint(8,bold('GitHub Traffic')).$s.'token with repository traffic permission required');return}
  if(!$STATE{last_traffic_ok}){irc_msg($net,$r,icon('stats').' '.paint($st eq'error'?4:8,bold('GitHub Traffic')).$s.uc($st).($RUN{traffic_error}?$s.irc_short($RUN{traffic_error},120):''));return}
  my$ct=traffic_recent_trend('clones');my$vt=traffic_recent_trend('views');
  irc_msg($net,$r,icon('stats').' '.paint(11,bold('GitHub Traffic · 14d')).$s.
   'clones '.paint(10,$t->{clones}).' / unique '.paint(10,$t->{clone_uniques}).$s.
   'views '.paint(10,$t->{views}).' / unique '.paint(10,$t->{view_uniques}).$s.
   'avg/day '.paint(6,traffic_num($t->{avg_clones},1).' clones / '.traffic_num($t->{avg_views},1).' views').$s.
   'updated '.paint(14,age($t->{last_ok})));
  irc_msg($net,$r,icon('stats').' '.paint(11,bold('Traffic today')).$s.
   'clones '.paint(10,$ct->{current}.' / '.int($t->{last_clone}{uniques}||0).' unique').' '.paint($ct->{delta}>0?3:$ct->{delta}<0?8:14,($ct->{delta}>0?'+':'').$ct->{delta}.' vs previous').$s.
   'views '.paint(10,$vt->{current}.' / '.int($t->{last_view}{uniques}||0).' unique').' '.paint($vt->{delta}>0?3:$vt->{delta}<0?8:14,($vt->{delta}>0?'+':'').$vt->{delta}.' vs previous').($ct->{date}?$s.paint(14,$ct->{date}):''));
  my$bc=$t->{best_clone};my$bv=$t->{best_view};
  irc_msg($net,$r,icon('stats').' '.paint(11,bold('Traffic peaks')).$s.
   'best clones '.paint(10,int($bc->{count}||0)).' / '.paint(10,int($bc->{uniques}||0).' unique').' '.paint(14,substr(clean($bc->{timestamp}||'?'),0,10)).$s.
   'best views '.paint(10,int($bv->{count}||0)).' / '.paint(10,int($bv->{uniques}||0).' unique').' '.paint(14,substr(clean($bv->{timestamp}||'?'),0,10)));
  return
 }
 if($cmd eq'referrers'){
  my@x=traffic_top('referrers');if(!@x){irc_msg($net,$r,icon('stats').' '.paint(14,'No GitHub referrer data cached'));return}
  irc_msg($net,$r,icon('stats').' '.paint(11,bold('Top referrers · 14d')).$s.join($s,map{paint(10,irc_short($_->{referrer}||'direct',45)).' '.int($_->{count}||0).' / '.int($_->{uniques}||0).' unique'}@x));return
 }
 if($cmd eq'paths'){
  my@x=traffic_top('paths');if(!@x){irc_msg($net,$r,icon('stats').' '.paint(14,'No GitHub path data cached'));return}
  irc_msg($net,$r,icon('stats').' '.paint(11,bold('Top paths · 14d')).$s.join($s,map{paint(10,irc_short($_->{path}||'/',55)).' '.int($_->{count}||0).' / '.int($_->{uniques}||0).' unique'}@x));return
 }
 if($cmd eq'broadcast'){
  my@b=broadcast_target_snapshot();my$q=queue_snapshot();
  irc_msg($net,$r,icon('events').' '.paint(11,bold('Broadcast fan-out')).$s.
   'targets '.paint(10,scalar(@b)).$s.'queued events '.paint($q->{total}?8:3,$q->{total}).$s.
   'enqueued '.paint(10,$STATS{broadcast_enqueued}).' / complete '.paint(3,$STATS{broadcast_completed}).$s.
   'delivery failures '.paint($STATS{broadcast_delivery_failures}?4:3,$STATS{broadcast_delivery_failures}));
  my@parts;
  for my$b(@b){
   my$state=$b->{joined}?paint(3,'ON'):$b->{online}?paint(8,'WAIT'):paint(4,'OFF');
   push@parts,$b->{label}.' '.paint(10,$b->{channel}).' '.$state.' sent '.paint(10,$b->{sent}).' pending '.paint($b->{pending}?8:3,$b->{pending}).' last '.paint(14,$b->{last_at}?age($b->{last_at}):'never');
  }
  while(@parts){irc_msg($net,$r,join($s,splice(@parts,0,2)))}
  my$h=@{$STATE{broadcast_history}}?$STATE{broadcast_history}[-1]:undef;
  if($h){my$total=scalar keys%{$h->{targets}||{}};my$done=scalar grep{$_}values%{$h->{targets}||{}};irc_msg($net,$r,paint(14,'last '.($h->{id}||'?')).$s.paint($done==$total?3:8,"delivered $done/$total").$s.irc_short($h->{text}||'',180))}
  return
 }
 if($cmd eq'stats'){
  my$aud=traffic_audience_summary();
  irc_msg($net,$r,icon('stats').' '.paint(11,bold('Repository audience · 14d')).$s.
   'clones '.paint(10,$aud->{clones}).' / '.paint(10,$aud->{clone_uniques}.' unique cloners').$s.
   'views '.paint(10,$aud->{views}).' / '.paint(10,$aud->{view_uniques}.' unique visitors').$s.
   'today '.paint(10,$aud->{today_clones}.' clones / '.$aud->{today_clone_uniques}.' unique · '.$aud->{today_views}.' views / '.$aud->{today_view_uniques}.' unique'));
  irc_msg($net,$r,icon('webhook').' '.paint(11,bold('Webhook')).$s.'received '.paint(10,$STATS{hook_received}).$s.'valid '.paint(3,$STATS{hook_valid}).$s.'sent '.paint(3,$STATS{hook_sent}).$s.'dupes '.paint(14,$STATS{hook_dupe}).$s.'rejected '.paint($STATS{hook_invalid}?4:3,$STATS{hook_invalid}).$s.'sig/hdr/json/repo '.paint(14,join('/',@STATS{qw(hook_bad_signature hook_missing_headers hook_bad_json hook_wrong_repo)})));
  irc_msg($net,$r,icon('refresh').' '.paint(11,bold('GitHub events')).$s.'polls '.paint(10,$STATS{poll_runs}).$s.'pages '.paint(10,$STATS{poll_pages}).$s.'new '.paint(3,$STATS{poll_new}).$s.'sent '.paint(3,$STATS{poll_sent}).$s.'304 '.paint(14,$STATS{poll_not_modified}).$s.'gaps '.paint($STATS{poll_gap}?8:3,$STATS{poll_gap}).$s.'errors '.paint($STATS{poll_errors}?4:3,$STATS{poll_errors}));
  irc_msg($net,$r,icon('ci').' '.paint(11,bold('GitHub Actions')).$s.'polls '.paint(10,$STATS{actions_polls}).$s.'pages '.paint(10,$STATS{actions_pages}).$s.'new '.paint(3,$STATS{actions_new}).$s.'fail '.paint($STATS{actions_failures}?4:3,$STATS{actions_failures}).$s.'recovered '.paint(3,$STATS{actions_recoveries}).$s.'slow '.paint(14,$STATS{actions_slow_alerts}).$s.'flaky '.paint(14,$STATS{actions_flaky_alerts}).$s.'sent '.paint(3,$STATS{actions_sent}).$s.'enrich skip '.paint(14,$STATS{actions_enrich_skipped}).$s.'304 '.paint(14,$STATS{actions_not_modified}).$s.'gaps '.paint($STATS{actions_gap}?8:3,$STATS{actions_gap}).$s.'errors '.paint($STATS{actions_errors}?4:3,$STATS{actions_errors}));
  irc_msg($net,$r,icon('stats').' '.paint(11,bold('GitHub Traffic')).$s.'state '.paint(traffic_state()eq'online'?3:traffic_state()eq'error'?4:8,uc(traffic_state())).$s.'cycles '.paint(10,$STATS{traffic_cycles}).$s.'requests '.paint(10,$STATS{traffic_requests}).$s.'403 '.paint($STATS{traffic_forbidden}?8:3,$STATS{traffic_forbidden}).$s.'errors '.paint($STATS{traffic_errors}?4:3,$STATS{traffic_errors}).$s.'last '.paint(14,$STATE{last_traffic_ok}?age($STATE{last_traffic_ok}):'never'));
  my$pa=account_summary();irc_msg($net,$r,icon('repo').' '.paint(11,bold($CFG{account}.' public portfolio')).$s.'state '.paint(account_state()eq'online'?3:account_state()eq'error'?4:8,uc(account_state())).$s.'repos '.paint(10,$pa->{repositories}).$s.'stars '.paint(10,$pa->{stars}).$s.'polls/pages '.paint(14,$STATS{account_polls}.'/'.$STATS{account_pages}).$s.'304 '.paint(14,$STATS{account_not_modified}).$s.'errors '.paint($STATS{account_errors}?4:3,$STATS{account_errors}).$s.'last '.paint(14,$STATE{last_account_ok}?age($STATE{last_account_ok}):'never'));
  irc_msg($net,$r,icon('events').' '.paint(11,bold('Broadcast')).$s.'enqueued '.paint(10,$STATS{broadcast_enqueued}).$s.'complete '.paint(3,$STATS{broadcast_completed}).$s.'attempts '.paint(10,$STATS{broadcast_delivery_attempts}).$s.'failures '.paint($STATS{broadcast_delivery_failures}?4:3,$STATS{broadcast_delivery_failures}).$s.'targets '.paint(10,scalar(enabled_targets())));
  irc_msg($net,$r,icon('forum').' '.paint(11,bold('Forum RSS')).$s.'polls '.paint(10,$STATS{rss_polls}).$s.'new '.paint(3,$STATS{rss_new}).$s.'sent '.paint(3,$STATS{rss_sent}).$s.'304 '.paint(14,$STATS{rss_not_modified}).$s.'same '.paint(14,$STATS{rss_unchanged}).$s.'errors '.paint($STATS{rss_errors}?4:3,$STATS{rss_errors}).$s.'queue '.paint(@{$STATE{pending}}?8:3,scalar@{$STATE{pending}}));
  return
 }
 if($cmd eq'rss'){
  my$rs=rss_state();my$st=paint(state_color_num($rs),bold(uc($rs)));my$last=$STATE{last_rss_ok}?paint(3,age($STATE{last_rss_ok})):paint(14,'never');
  my$title=$STATE{last_rss_title}?paint(10,irc_short($STATE{last_rss_title},80)):paint(14,'no item cached');
  irc_msg($net,$r,icon('forum').' '.paint(11,bold('Forum RSS')).$s.$st.$s.'url '.paint(10,$CFG{rss_url}).$s.'every '.paint(6,$CFG{rss_interval}.'s').$s.'last OK '.$last.$s.'latest '.$title);return
 }
 if($cmd eq'webhook'){
  my$ws=webhook_state();my$st=paint(state_color_num($ws),bold(uc($ws)));my$seen=$STATE{last_hook_ok}?paint(3,age($STATE{last_hook_ok})).' '.paint(10,$STATE{last_hook_event}):paint(14,'not seen yet');
  my$sig=$CFG{hook_secret}eq''?paint(14,'POST disabled'):$STATE{last_hook_ok}?paint(3,'HMAC-SHA256 verified'):paint(8,'HMAC-SHA256 ready');
  my$rej=$STATS{hook_invalid}?paint(4,$STATS{hook_invalid}.' rejected').' '.paint(14,'sig '.$STATS{hook_bad_signature}.' hdr '.$STATS{hook_missing_headers}.' json '.$STATS{hook_bad_json}.' repo '.$STATS{hook_wrong_repo}):paint(3,'no rejected signed requests');
  my$lastrej=$STATE{last_hook_reject_at}?$s.'last reject '.paint(14,age($STATE{last_hook_reject_at}).' '.$STATE{last_hook_reject_reason}):'';
  my$lasthttp=$RUN{http_last_at}?$s.'last HTTP '.paint(14,age($RUN{http_last_at}).' '.$RUN{http_last_method}.' '.$RUN{http_last_path}.' → '.$RUN{http_last_status}):'';
  irc_msg($net,$r,icon('webhook').' '.paint(11,bold('Webhook')).$s.$st.$s.'HTTP '.paint($RUN{listener}?3:4,$RUN{listener}?'LISTENING':'DOWN').$s.'endpoint '.paint(10,hook_status()).$s.'signature '.$sig.$s.'GitHub '.$seen.$s.$rej.$lastrej.$lasthttp);return
 }
 if($cmd eq'networks'){
  my@parts;
  for my$n(enabled_nets()){
   my@c=net_channels($n);my$transport=$n->{tls}?'TLS':'TCP';my$extra='';
   $extra=' SASL '.uc($n->{sasl_state}) if$n->{sasl_account}ne'';
   my$chstate=join(',',map{$_->{name}.($_->{joined}?'[ON]':'[WAIT]')}@c);
   push@parts,$n->{label}.' '.paint($n->{up}?3:4,$n->{up}?'ONLINE':'OFFLINE').' '.paint(10,"$n->{host}:$n->{port} $transport $chstate").$extra.' sent '.paint(10,$STATS{'irc_'.$n->{id}.'_sent'}||0).' RX '.paint(14,age($n->{last_rx}));
  }
  irc_msg($net,$r,paint(11,bold('IRC networks')).$s.join($s,@parts).$s.'heartbeat '.($CFG{irc_idle_ping}?paint(10,$CFG{irc_idle_ping}.'s').' timeout '.paint(10,$CFG{irc_pong_timeout}.'s'):paint(14,'off')).$s.'join retry/reject '.paint(14,$STATS{irc_join_retries}.'/'.$STATS{irc_join_rejects}));
  return
 }
 if($cmd eq'endpoints'){irc_msg($net,$r,icon('api').' '.paint(11,bold('Local HTTP')).$s.'dashboard /'.$s.'live-data ?api=dashboard'.$s.'status /status.json'.$s.'health /healthz'.$s.'live /livez'.$s.'ready /readyz'.$s.'CI reliability /ci.json'.$s.'broadcast /broadcast.json'.$s.'traffic /traffic.json'.$s.'account /account.json'.$s.'metrics '.($CFG{metrics_enabled}?'/metrics':'off').$s.'webhook '.$CFG{hook_path});return}
 if($cmd eq'icons'){irc_msg($net,$r,paint(11,bold('Icons')).$s.'mode '.paint(10,$CFG{icon_mode}).$s.icon('github').' GitHub '.$s.icon('forum').' Forum '.$s.icon('ci').' CI '.$s.icon('health').' OK '.$s.icon('webhook').' hook '.$s.icon('refresh').' poll');return}
 if($cmd eq'events'){irc_msg($net,$r,icon('events').' '.paint(11,bold('Public feed')).$s.'push issues comments PR reviews releases refs stars forks discussions CI failures/recovery optional slow/missing/flaky CI checks deploys pages repo changes'.$s.paint(14,'security alerts intentionally hidden'));return}
 if($cmd eq'portfolio'||$cmd eq'projects'){
  my$a=account_summary();
  if($a->{state}eq'off'){irc_msg($net,$r,icon('repo').' '.paint(14,bold($CFG{account}.' public portfolio')).$s.'disabled');return}
  if(!$a->{last_ok}){irc_msg($net,$r,icon('repo').' '.paint($a->{state}eq'error'?4:8,bold($CFG{account}.' public portfolio')).$s.uc($a->{state}).($a->{error}?$s.irc_short($a->{error},120):''));return}
  my$dt=$a->{trend}{stars}{delta};my$ds=$dt>0?'+'.$dt:"$dt";
  irc_msg($net,$r,icon('repo').' '.paint(11,bold($CFG{account}.' · public portfolio')).$s.
   'repos '.paint(10,$a->{repositories}).' / maintained '.paint(3,$a->{maintained}).$s.
   'active 30d '.paint($a->{active_30d}?3:14,$a->{active_30d}).$s.'stars '.paint(10,$a->{stars}).' ('.paint($dt>0?3:$dt<0?8:14,$ds).')'.$s.
   'forks '.paint(10,$a->{forks}).$s.'open issues '.paint($a->{open_issues}?8:3,$a->{open_issues}).$s.'stale '.paint($a->{stale}?8:3,$a->{stale}).$s.'updated '.paint(14,age($a->{last_ok})));
  irc_msg($net,$r,paint(11,bold('Public hygiene')).$s.'missing description '.paint($a->{missing_description}?8:3,$a->{missing_description}).$s.'license '.paint($a->{missing_license}?8:3,$a->{missing_license}).$s.'topics '.paint($a->{missing_topics}?8:3,$a->{missing_topics}).$s.'archived '.paint(14,$a->{archived}).$s.paint(14,'owner-only public metadata'));
  return
 }
 if($cmd eq'repos'){
  my$a=account_summary();my@x=@{$a->{recently_pushed}};if(!@x){irc_msg($net,$r,icon('repo').' '.paint(14,'No public '.$CFG{account}.' repository cached yet'));return}
  irc_msg($net,$r,icon('repo').' '.paint(11,bold($CFG{account}.' · recently pushed')).$s.join($s,map{paint(10,$_->{name}).' '.paint(14,iso8601_epoch($_->{pushed_at})?age(iso8601_epoch($_->{pushed_at})):'never').($_->{language}?' · '.$_->{language}:'')}@x));return
 }
 if($cmd eq'stars'){
  my$a=account_summary();my@x=@{$a->{most_starred}};if(!@x){irc_msg($net,$r,icon('repo').' '.paint(14,'No public '.$CFG{account}.' repository cached yet'));return}
  irc_msg($net,$r,icon('repo').' '.paint(11,bold($CFG{account}.' · most starred')).$s.join($s,map{paint(10,$_->{name}).' ★'.int($_->{stars}||0).' · forks '.int($_->{forks}||0)}@x));return
 }
 if($cmd eq'stale'){
  my$a=account_summary();my@x=@{$a->{stale_repositories}};if(!@x){irc_msg($net,$r,icon('repo').' '.paint(3,bold($CFG{account}.' · stale projects')).$s.'none beyond '.$CFG{account_stale_days}.' days');return}
  irc_msg($net,$r,icon('repo').' '.paint(8,bold($CFG{account}.' · stale projects')).$s.join($s,map{paint(10,$_->{name}).' '.paint(14,iso8601_epoch($_->{pushed_at})?age(iso8601_epoch($_->{pushed_at})):'never')}@x));return
 }
 if($cmd eq'changes'){
  my$x=account_change_rows();if(!@$x){irc_msg($net,$r,icon('repo').' '.paint(14,'No '.$CFG{account}.' portfolio change recorded yet'));return}
  irc_msg($net,$r,icon('repo').' '.paint(11,bold($CFG{account}.' · portfolio changes')).$s.join($s,map{paint(14,$_->{at}?age($_->{at}):'time unknown').' '.paint(10,irc_short($_->{text},100))}@$x));return
 }
 if($cmd eq'project'){
  if($arg eq''){irc_msg($net,$r,icon('repo').' usage: '.paint(10,'!github project <name>'));return}
  my($p)=grep{lc($_->{name})eq lc($arg)}@{$STATE{account_repos}};
  if(!$p){irc_msg($net,$r,icon('repo').' '.paint(4,"Unknown public $CFG{account} project '$arg'"));return}
  my$flags=join(', ',grep{length}($p->{archived}?'archived':'',$p->{fork}?'fork':'',$p->{disabled}?'disabled':''));$flags||='maintained';
  irc_msg($net,$r,icon('repo').' '.paint(11,bold($p->{full_name})).$s.paint(10,$flags).$s.'stars '.int($p->{stars}||0).$s.'forks '.int($p->{forks}||0).$s.'issues '.int($p->{open_issues}||0).$s.($p->{language}?$p->{language}.$s:'').'last push '.paint(14,iso8601_epoch($p->{pushed_at})?age(iso8601_epoch($p->{pushed_at})):'never').$s.$p->{html_url});return
 }
 if($cmd eq'repo'){irc_msg($net,$r,icon('repo').' '.paint(11,bold('Repository')).$s.paint(10,$CFG{repo}).$s."https://github.com/$CFG{repo}");return}
 if($cmd eq'help'){
  irc_msg($net,$r,icon('github').' '.paint(11,bold(APP_NAME.' · overview')).$s.join(' ',map{paint(10,$_)}qw(pulse now today summary status health problems dashboard recent last)));
  irc_msg($net,$r,icon('ci').' '.paint(11,bold('CI / delivery')).$s.join(' ',map{paint(10,$_)}qw(ci reliability slo incidents failures flaky running expected broadcast queue networks schedule)));
  irc_msg($net,$r,icon('stats').' '.paint(11,bold('Traffic')).$s.join(' ',map{paint(10,$_)}qw(snapshot lateststats clones traffic audience uniques trend week compare peaks history top referrers paths)));
  irc_msg($net,$r,icon('repo').' '.paint(11,bold($CFG{account}.' portfolio')).$s.join(' ',map{paint(10,$_)}qw(portfolio repos stars stale changes)).' '.paint(10,'project <name>'));
  irc_msg($net,$r,icon('shield').' '.paint(11,bold('Diagnostics')).$s.join(' ',map{paint(10,$_)}qw(freshness stats webhook auth rate state alerts endpoints icons events repo)));
  return
 }
 irc_msg($net,$r,icon('generic').' '.paint(4,"Unknown '$cmd'").$s.'try '.paint(10,'!github help'));
}
sub startup_announce {
 my($net)=@_;return unless$net&&$CFG{startup_announce}&&$net->{up};
 my$auth=$RUN{auth_state}eq'verified'&&$RUN{auth_events}eq'ok'?paint(3,'TOKEN VERIFIED').' '.paint(10,$RUN{auth_login}):$RUN{auth_state}eq'rejected'?paint(4,'TOKEN REJECTED').' '.paint(8,'anonymous fallback'):paint(8,auth_short());
 my$msg=icon('auth').' '.paint(11,bold(APP_NAME.' v'.VERSION)).sep().$auth.sep().
  icon('ci').' CI '.($CFG{actions_enabled}?paint(10,'watching failures'):paint(14,'off')).sep().
  icon('webhook').' '.($CFG{hook_secret}ne''?paint(8,'webhook listening'):paint(14,'webhook POST disabled')).sep().
  icon('forum').' RSS '.($CFG{rss_enabled}?paint(10,$CFG{rss_interval}.'s'):paint(14,'off')).sep().
  'network '.paint(10,$net->{label});
 my$sent=0;
 for my$ch(net_channels($net)){
  next unless$ch->{joined};next if$ch->{startup_sent};
  if(irc_msg($net,$ch->{name},$msg)){$ch->{startup_sent}=1;$sent++}
 }
 $net->{startup_sent}=1 if$sent&&scalar(grep{$_->{joined}&&!$_->{startup_sent}}net_channels($net))==0;
 $sent;
}

# ── Local status dashboard ───────────────────────────────────────────────────
sub html_escape {
 my($s)=@_;$s//=q{};
 $s=~s/&/&amp;/g;$s=~s/</&lt;/g;$s=~s/>/&gt;/g;$s=~s/"/&quot;/g;$s=~s/'/&#39;/g;
 $s;
}
sub html_linkify {
 my($s)=@_;$s=plain_irc($s//q{});my$out='';
 while($s=~/(.*?)(https?:\/\/[^\s<>"']+)(.*)/s){
  my($pre,$url,$rest)=($1,$2,$3);$out.=html_escape($pre);
  my$eu=html_escape($url);$out.='<a href="'.$eu.'" rel="noopener noreferrer">'.$eu.'</a>';$s=$rest;
 }
 $out.html_escape($s);
}
sub ops_health_key {
 my($h)=@_;return'ok'if$h->{status}eq'ok';'degraded:'.join('|',sort@{$h->{issues}||[]});
}
sub format_ops_alert {
 my($kind,$h)=@_;return icon('health').' '.paint(3,bold('Ops RECOVERED')).' — all monitored sources healthy' if$kind eq'recovered';
 icon('health').' '.paint(4,bold('Ops DEGRADED')).' — '.join('; ',@{$h->{issues}||[]});
}
sub check_ops_alerts {
 return 0 unless$CFG{ops_alerts};my$h=health_report();my$key=ops_health_key($h);my$now=int(time);
 if($STATE{ops_health_key} eq''){$STATE{ops_health_key}=$key;$STATE{ops_health_since}=$now;$STATE{ops_health_alerted}=0;save_state();return 1}
 if($key ne$STATE{ops_health_key}){$STATE{ops_health_key}=$key;$STATE{ops_health_since}=$now;$STATE{ops_health_alerted}=0;save_state();return 1}
 return 0 if$STATE{ops_health_alerted};return 0 if$now-int($STATE{ops_health_since}||$now)<$CFG{ops_debounce};
 if($h->{status}eq'degraded'){
  enqueue(format_ops_alert('degraded',$h),'ops',1);$STATE{ops_health_alerted}=1;$STATE{ops_degraded_announced}=1;$STATS{ops_degraded_alerts}++;save_state();return 1;
 }
 if($STATE{ops_degraded_announced}){
  enqueue(format_ops_alert('recovered',$h),'ops',1);$STATE{ops_health_alerted}=1;$STATE{ops_degraded_announced}=0;$STATS{ops_recovery_alerts}++;save_state();return 1;
 }
 $STATE{ops_health_alerted}=1;save_state();1;
}
sub health_report {
 my@issues;
 push@issues,'EpiKnet offline' if$NET{epiknet}{enabled}&&!$NET{epiknet}{up};
 push@issues,'Libera offline' if$NET{libera}{enabled}&&!$NET{libera}{up};
 push@issues,'Undernet offline' if$NET{undernet}{enabled}&&!$NET{undernet}{up};
 for my$n(enabled_nets()){
  next unless$n->{up};
  for my$ch(net_channels($n)){push@issues,$n->{label}.' '.$ch->{name}.' not joined' unless$ch->{joined}}
 }
 push@issues,'HTTP listener down' unless$RUN{listener};
 my$a=api_state();push@issues,"Events API $a" if$CFG{poll_enabled}&&$a=~/^(?:error|limited)$/;
 my$c=actions_state();push@issues,"Actions $c" if$CFG{actions_enabled}&&$c=~/^(?:error|limited)$/;
 my$r=rss_state();push@issues,"RSS $r" if$CFG{rss_enabled}&&$r eq'error';
 push@issues,'queue high '.scalar(@{$STATE{pending}}).'/'.MAX_PENDING if@{$STATE{pending}}>=$CFG{health_queue_warn};
 +{status=>@issues?'degraded':'ok',issues=>\@issues};
}
sub rate_resume_text {
 return'ready'if github_rest_allowed();
 my$s=int($RUN{rate_block_until}-time);$s=0 if$s<0;
 $s<60?"${s}s":$s<3600?int(($s+59)/60).'m':int(($s+3599)/3600).'h';
}
sub traffic_dashboard_html {
 my$st=traffic_state();my$s=traffic_summary_data();
 if($st eq'off'){return'<section class="card full"><div class="label">GitHub Traffic</div><div class="small">Traffic statistics disabled.</div></section>'}
 if($st eq'needs_token'){return'<section class="card full traffic-panel"><div class="label">GitHub Traffic · 14 days</div><div class="value warn">TOKEN PERMISSION REQUIRED</div><div class="small">Uses the existing GITHUB_TOKEN. Repository traffic endpoints require suitable repository traffic access.</div></section>'}
 if(!$STATE{last_traffic_ok}){my$d=html_escape($RUN{traffic_error}||'waiting for first traffic refresh');return'<section class="card full traffic-panel"><div class="label">GitHub Traffic · 14 days</div><div class="value '.($st eq'error'?'bad':'warn').'">'.html_escape(uc($st)).'</div><div class="small">'.$d.'</div></section>'}
 my@rows=traffic_daily_rows();my$maxc=1;my$maxv=1;for my$r(@rows){$maxc=$r->{clones}if($r->{clones}||0)>$maxc;$maxv=$r->{views}if($r->{views}||0)>$maxv}
 my$bars='';for my$r(@rows){my$cp=int(100*int($r->{clones}||0)/$maxc);my$vp=int(100*int($r->{views}||0)/$maxv);$cp=4 if$cp>0&&$cp<4;$vp=4 if$vp>0&&$vp<4;$bars.='<div class="traffic-day" title="'.html_escape(($r->{date}||'').' · '.int($r->{clones}||0).' clones · '.int($r->{views}||0).' views').'"><div class="traffic-bar clones" style="height:'.$cp.'%"></div><div class="traffic-bar views" style="height:'.$vp.'%"></div></div>'}
 my$daily='';for my$r(reverse@rows){$daily.='<tr><td>'.html_escape($r->{date}||'').'</td><td>'.int($r->{clones}||0).'</td><td>'.int($r->{clone_uniques}||0).'</td><td>'.int($r->{views}||0).'</td><td>'.int($r->{view_uniques}||0).'</td></tr>'}
 my@refs=traffic_top('referrers');my@paths=traffic_top('paths');
 my$refs=@refs?join('',map{'<div class="traffic-list-row"><span>'.html_escape($_->{referrer}||'direct').'</span><b>'.int($_->{count}||0).' / '.int($_->{uniques}||0).' unique</b></div>'}@refs):'<div class="small">No referrer data.</div>';
 my$paths=@paths?join('',map{'<div class="traffic-list-row"><span>'.html_escape($_->{path}||'/').'</span><b>'.int($_->{count}||0).' / '.int($_->{uniques}||0).' unique</b></div>'}@paths):'<div class="small">No path data.</div>';
 my$bc=ref($s->{best_clone})eq'HASH'?$s->{best_clone}:{};my$bv=ref($s->{best_view})eq'HASH'?$s->{best_view}:{};
 return'<section class="card full traffic-panel"><div class="label">GitHub Traffic · rolling 14 days <span class="source">'.html_escape(age($s->{last_ok})).'</span></div>'.
  '<div class="traffic-kpis">'.
   '<div class="traffic-kpi cyan"><span>Clones</span><b>'.$s->{clones}.'</b><small>'.$s->{clone_uniques}.' unique · '.traffic_num($s->{avg_clones},1).'/day</small></div>'.
   '<div class="traffic-kpi pink"><span>Views</span><b>'.$s->{views}.'</b><small>'.$s->{view_uniques}.' unique · '.traffic_num($s->{avg_views},1).'/day</small></div>'.
   '<div class="traffic-kpi green"><span>Best clone day</span><b>'.int($bc->{count}||0).'</b><small>'.html_escape(substr(clean($bc->{timestamp}||'?'),0,10)).' · '.int($bc->{uniques}||0).' unique</small></div>'.
   '<div class="traffic-kpi yellow"><span>Best view day</span><b>'.int($bv->{count}||0).'</b><small>'.html_escape(substr(clean($bv->{timestamp}||'?'),0,10)).' · '.int($bv->{uniques}||0).' unique</small></div>'.
  '</div><div class="traffic-spark">'.$bars.'</div><div class="traffic-legend"><span><i class="legend-clones"></i> clones</span><span><i class="legend-views"></i> views</span></div>'.
  '<div class="traffic-columns"><div><h3>Top referrers</h3>'.$refs.'</div><div><h3>Top paths</h3>'.$paths.'</div></div>'.
  '<div class="traffic-table-wrap"><table class="traffic-table"><thead><tr><th>Date</th><th>Clones</th><th>Clone uniques</th><th>Views</th><th>View uniques</th></tr></thead><tbody>'.$daily.'</tbody></table></div></section>';
}
sub dashboard_js {
 return <<'JS';
(()=>{
'use strict';

const $=id=>document.getElementById(id);
const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const num=value=>Number.isFinite(Number(value))?Number(value):0;
const upper=value=>String(value??'').toUpperCase();
const stateClass=value=>{
  const s=String(value??'').toLowerCase();
  if(['online','live','ok','ready','stable','token ok'].includes(s))return'ok';
  if(['error','offline','bad','token bad','auth error','degraded'].includes(s))return'bad';
  if(['off','disabled'].includes(s))return'off';
  return'warn';
};
const rel=ts=>{
  ts=num(ts);if(!ts)return'never';
  let s=Math.max(0,Math.floor(Date.now()/1000-ts));
  if(s<60)return`${s}s ago`;
  if(s<3600)return`${Math.floor(s/60)}m ago`;
  if(s<86400)return`${Math.floor(s/3600)}h ago`;
  return`${Math.floor(s/86400)}d ago`;
};
const duration=seconds=>{
  let s=Math.max(0,Math.floor(num(seconds)));if(!s)return'n/a';
  if(s<60)return`${s}s`;
  if(s<3600)return`${Math.floor(s/60)}m ${s%60}s`;
  if(s<86400)return`${Math.floor(s/3600)}h ${Math.floor((s%3600)/60)}m`;
  return`${Math.floor(s/86400)}d ${Math.floor((s%86400)/3600)}h`;
};
const linkify=text=>{
  text=String(text??'');let out='',last=0;
  const re=/https?:\/\/[^\s<>"']+/g;let m;
  while((m=re.exec(text))){
    out+=esc(text.slice(last,m.index));
    const u=esc(m[0]);out+=`<a href="${u}" rel="noopener noreferrer">${u}</a>`;
    last=m.index+m[0].length;
  }
  return out+esc(text.slice(last));
};
const html=(id,value)=>{const el=$(id);if(el&&el.innerHTML!==value)el.innerHTML=value};
const txt=(id,value)=>{const el=$(id);value=String(value??'');if(el&&el.textContent!==value)el.textContent=value};
const pill=(label,value,cls=stateClass(value))=>`<span class="pill"><span>${esc(label)}</span><b class="${cls}">${esc(value)}</b></span>`;
const statusPill=(label,state)=>pill(label,upper(state),stateClass(state));

let pollMs=3000;
let hiddenMs=20000;
let timeoutMs=4000;
let inFlight=false;
let timer=null;
let failures=0;
let lastSuccess=0;

const endpoint=()=>{
  const u=new URL(window.location.href);
  u.search='?api=dashboard';
  u.hash='';
  return u.toString();
};

const setLive=(state,detail)=>{
  const el=$('live-badge');if(!el)return;
  el.textContent=detail;el.className=state;
};

let chartRange=14;
let lastDashboard=null;
const svgNS='http://www.w3.org/2000/svg';
const svgEl=(name,attrs={})=>{const n=document.createElementNS(svgNS,name);Object.entries(attrs).forEach(([k,v])=>n.setAttribute(k,v));return n};
function chartRows(d){const rows=Array.isArray(d.github_traffic?.daily)?d.github_traffic.daily:[];return rows.slice(-Math.max(1,chartRange))}
function renderChart(d){
  const svg=$('traffic-chart');if(!svg)return;const rows=chartRows(d);svg.replaceChildren();
  if(!rows.length){const t=svgEl('text',{x:'50%',y:'50%','text-anchor':'middle',class:'chart-axis'});t.textContent='No traffic data';svg.appendChild(t);return}
  const W=1000,H=238,pad={l:42,r:18,t:10,b:28},iw=W-pad.l-pad.r,ih=H-pad.t-pad.b;
  svg.setAttribute('viewBox',`0 0 ${W} ${H}`);
  const maxY=Math.max(1,...rows.flatMap(x=>[num(x.clones),num(x.views)]));
  const x=i=>pad.l+(rows.length===1?iw/2:iw*i/(rows.length-1));const y=v=>pad.t+ih-(num(v)/maxY)*ih;
  const defs=svgEl('defs');
  const g1=svgEl('linearGradient',{id:'cloneArea',x1:'0',y1:'0',x2:'0',y2:'1'});g1.append(svgEl('stop',{offset:'0%','stop-color':'#5794f2','stop-opacity':'.55'}),svgEl('stop',{offset:'100%','stop-color':'#5794f2','stop-opacity':'0'}));
  const g2=svgEl('linearGradient',{id:'viewArea',x1:'0',y1:'0',x2:'0',y2:'1'});g2.append(svgEl('stop',{offset:'0%','stop-color':'#56d2c9','stop-opacity':'.42'}),svgEl('stop',{offset:'100%','stop-color':'#56d2c9','stop-opacity':'0'}));defs.append(g1,g2);svg.appendChild(defs);
  for(let i=0;i<=4;i++){const yy=pad.t+ih*i/4;svg.appendChild(svgEl('line',{x1:pad.l,y1:yy,x2:W-pad.r,y2:yy,class:'chart-grid'}));const label=svgEl('text',{x:pad.l-8,y:yy+3,'text-anchor':'end',class:'chart-axis'});label.textContent=Math.round(maxY*(1-i/4));svg.appendChild(label)}
  const points=field=>rows.map((r,i)=>[x(i),y(r[field])]);const path=pts=>pts.map((q,i)=>(i?'L':'M')+q[0].toFixed(1)+' '+q[1].toFixed(1)).join(' ');const area=pts=>`${path(pts)} L ${pts[pts.length-1][0].toFixed(1)} ${(pad.t+ih).toFixed(1)} L ${pts[0][0].toFixed(1)} ${(pad.t+ih).toFixed(1)} Z`;
  const cp=points('clones'),vp=points('views');svg.appendChild(svgEl('path',{d:area(cp),class:'chart-area-clones'}));svg.appendChild(svgEl('path',{d:area(vp),class:'chart-area-views'}));svg.appendChild(svgEl('path',{d:path(cp),class:'chart-line-clones'}));svg.appendChild(svgEl('path',{d:path(vp),class:'chart-line-views'}));
  const tip=$('chart-tooltip');const showTip=(ev,row)=>{if(!tip)return;tip.innerHTML=`<b>${esc(row.date||'')}</b><br>Clones ${num(row.clones)} · unique ${num(row.clone_uniques)}<br>Views ${num(row.views)} · unique ${num(row.view_uniques)}`;tip.style.display='block';tip.style.left=`${ev.clientX+12}px`;tip.style.top=`${ev.clientY+12}px`};const hideTip=()=>{if(tip)tip.style.display='none'};
  rows.forEach((row,i)=>{const hit=svgEl('rect',{x:x(i)-Math.max(8,iw/rows.length/2),y:pad.t,width:Math.max(16,iw/rows.length),height:ih,fill:'transparent'});hit.addEventListener('mousemove',ev=>showTip(ev,row));hit.addEventListener('mouseleave',hideTip);svg.appendChild(hit);svg.append(svgEl('circle',{cx:x(i),cy:y(row.clones),r:3,fill:'#5794f2',class:'chart-dot'}),svgEl('circle',{cx:x(i),cy:y(row.views),r:3,fill:'#56d2c9',class:'chart-dot'}));if(i===0||i===rows.length-1||rows.length<=7){const label=svgEl('text',{x:x(i),y:H-7,'text-anchor':i===0?'start':i===rows.length-1?'end':'middle',class:'chart-axis'});label.textContent=String(row.date||'').slice(5);svg.appendChild(label)}});
  const retained=num(d.github_traffic?.history?.days);txt('chart-updated',`updated ${d.last_traffic_ok?rel(d.last_traffic_ok):'never'} · ${retained}d retained · UTC`);
}

function renderUniqueChart(d){
  const svg=$('unique-chart');if(!svg)return;
  const rows=chartRows(d);svg.replaceChildren();
  if(!rows.length){const t=svgEl('text',{x:'50%',y:'50%','text-anchor':'middle',class:'chart-axis'});t.textContent='No unique audience data';svg.appendChild(t);return}
  const W=600,H=238,pad={l:36,r:14,t:10,b:28},iw=W-pad.l-pad.r,ih=H-pad.t-pad.b;
  svg.setAttribute('viewBox',`0 0 ${W} ${H}`);
  const maxY=Math.max(1,...rows.flatMap(x=>[num(x.clone_uniques),num(x.view_uniques)]));
  const x=i=>pad.l+(rows.length===1?iw/2:iw*i/(rows.length-1));
  const y=v=>pad.t+ih-(num(v)/maxY)*ih;
  const defs=svgEl('defs');
  const g1=svgEl('linearGradient',{id:'clonerUniqueArea',x1:'0',y1:'0',x2:'0',y2:'1'});
  g1.append(svgEl('stop',{offset:'0%','stop-color':'#b877d9','stop-opacity':'.48'}),svgEl('stop',{offset:'100%','stop-color':'#b877d9','stop-opacity':'0'}));
  const g2=svgEl('linearGradient',{id:'visitorUniqueArea',x1:'0',y1:'0',x2:'0',y2:'1'});
  g2.append(svgEl('stop',{offset:'0%','stop-color':'#73bf69','stop-opacity':'.40'}),svgEl('stop',{offset:'100%','stop-color':'#73bf69','stop-opacity':'0'}));
  defs.append(g1,g2);svg.appendChild(defs);
  for(let i=0;i<=4;i++){
    const yy=pad.t+ih*i/4;
    svg.appendChild(svgEl('line',{x1:pad.l,y1:yy,x2:W-pad.r,y2:yy,class:'chart-grid'}));
    const label=svgEl('text',{x:pad.l-7,y:yy+3,'text-anchor':'end',class:'chart-axis'});
    label.textContent=Math.round(maxY*(1-i/4));svg.appendChild(label);
  }
  const points=field=>rows.map((r,i)=>[x(i),y(r[field])]);
  const path=pts=>pts.map((q,i)=>(i?'L':'M')+q[0].toFixed(1)+' '+q[1].toFixed(1)).join(' ');
  const area=pts=>`${path(pts)} L ${pts[pts.length-1][0].toFixed(1)} ${(pad.t+ih).toFixed(1)} L ${pts[0][0].toFixed(1)} ${(pad.t+ih).toFixed(1)} Z`;
  const cp=points('clone_uniques'),vp=points('view_uniques');
  svg.appendChild(svgEl('path',{d:area(cp),class:'chart-area-cloner-uniques'}));
  svg.appendChild(svgEl('path',{d:area(vp),class:'chart-area-visitor-uniques'}));
  svg.appendChild(svgEl('path',{d:path(cp),class:'chart-line-cloner-uniques'}));
  svg.appendChild(svgEl('path',{d:path(vp),class:'chart-line-visitor-uniques'}));
  const tip=$('unique-chart-tooltip');
  const showTip=(ev,row)=>{
    if(!tip)return;
    tip.innerHTML=`<b>${esc(row.date||'')}</b><br>Unique cloners ${num(row.clone_uniques)}<br>Unique visitors ${num(row.view_uniques)}<br><span style="color:#8d95a3">GitHub aggregate uniques · no raw IPs</span>`;
    tip.style.display='block';tip.style.left=`${ev.clientX+12}px`;tip.style.top=`${ev.clientY+12}px`;
  };
  const hideTip=()=>{if(tip)tip.style.display='none'};
  rows.forEach((row,i)=>{
    const hit=svgEl('rect',{x:x(i)-Math.max(7,iw/rows.length/2),y:pad.t,width:Math.max(14,iw/rows.length),height:ih,fill:'transparent'});
    hit.addEventListener('mousemove',ev=>showTip(ev,row));hit.addEventListener('mouseleave',hideTip);svg.appendChild(hit);
    svg.append(
      svgEl('circle',{cx:x(i),cy:y(row.clone_uniques),r:3,fill:'#b877d9',class:'chart-dot'}),
      svgEl('circle',{cx:x(i),cy:y(row.view_uniques),r:3,fill:'#73bf69',class:'chart-dot'})
    );
    if(i===0||i===rows.length-1||rows.length<=7){
      const label=svgEl('text',{x:x(i),y:H-7,'text-anchor':i===0?'start':i===rows.length-1?'end':'middle',class:'chart-axis'});
      label.textContent=String(row.date||'').slice(5);svg.appendChild(label);
    }
  });
  txt('unique-chart-range',`${rows.length}d daily curve · UTC`);
}

function renderHero(d){
  const t=d.github_traffic||{},b=d.broadcast||{},targets=b.targets||[],daily=Array.isArray(t.daily)?t.daily:[];
  const last=t.latest||((daily.length?daily[daily.length-1]:{})),prev=daily.length>1?daily[daily.length-2]:{};
  const cloneDelta=num(last.clones)-num(prev.clones),viewDelta=num(last.views)-num(prev.views);
  txt('stat-clones',num(t.clones));txt('stat-clone-uniques',num(t.clone_uniques));txt('stat-views',num(t.views));txt('stat-view-uniques',num(t.view_uniques));
  txt('stat-clones-unique',`${num(t.clone_uniques)} unique cloners`);txt('stat-views-unique',`${num(t.view_uniques)} unique visitors`);
  txt('toolbar-audience',`${num(t.clone_uniques)} cloners · ${num(t.view_uniques)} visitors`);
  txt('toolbar-latest-traffic',`${num(last.clones)} clones · ${num(last.clone_uniques)} unique`);
  const cd=$('stat-clones-delta'),vd=$('stat-views-delta');if(cd){cd.textContent=`${cloneDelta>0?'+':''}${cloneDelta} today`;cd.className=`stat-delta ${cloneDelta>0?'up':cloneDelta<0?'down':''}`}if(vd){vd.textContent=`${viewDelta>0?'+':''}${viewDelta} today`;vd.className=`stat-delta ${viewDelta>0?'up':viewDelta<0?'down':''}`}
  const cloneUniqueDelta=num(last.clone_uniques)-num(prev.clone_uniques),viewUniqueDelta=num(last.view_uniques)-num(prev.view_uniques);
  txt('stat-clone-uniques-today',`${num(last.clone_uniques)} today`);txt('stat-view-uniques-today',`${num(last.view_uniques)} today`);
  const cud=$('stat-clone-uniques-delta'),vud=$('stat-view-uniques-delta');
  if(cud){cud.textContent=`${cloneUniqueDelta>0?'+':''}${cloneUniqueDelta} vs previous`;cud.className=`stat-delta ${cloneUniqueDelta>0?'up':cloneUniqueDelta<0?'down':''}`}
  if(vud){vud.textContent=`${viewUniqueDelta>0?'+':''}${viewUniqueDelta} vs previous`;vud.className=`stat-delta ${viewUniqueDelta>0?'up':viewUniqueDelta<0?'down':''}`}
  const a=t.audience||{},cmp=a.comparison_7d||{},change=cmp.changes?.clones||{},peak=a.best_clone_unique||{};
  txt('audience-clone-depth',`${num(a.clones_per_unique).toFixed(2)} / cloner`);
  txt('audience-unique-average',`${num(a.avg_daily_clone_uniques).toFixed(1)} cloners`);
  txt('audience-unique-peak',`${num(peak.clone_uniques)} · ${String(peak.date||'?').slice(0,10)}`);
  const wc=$('audience-week-change');if(wc){const pct=num(change.pct);wc.textContent=`${pct>0?'+':''}${pct.toFixed(1)}% vs previous`;wc.className=pct>0?'up':pct<0?'down':''}
  const joined=targets.filter(x=>x.joined).length;txt('pulse-webhook',upper(d.webhook));const pw=$('pulse-webhook');if(pw)pw.className=`pulse-value ${stateClass(d.webhook)}`;txt('pulse-ci',upper(d.github_actions));const pc=$('pulse-ci');if(pc)pc.className=`pulse-value ${stateClass(d.github_actions)}`;txt('pulse-fanout',`${joined}/${targets.length}`);const pf=$('pulse-fanout');if(pf)pf.className=`pulse-value ${joined===targets.length?'ok':'warn'}`;txt('pulse-queue',num(d.queue));const pq=$('pulse-queue');if(pq)pq.className=`pulse-value ${num(d.queue)?'warn':'ok'}`;txt('pulse-today',`${num(last.clones)} clones · ${num(last.clone_uniques)} unique`);txt('pulse-latest',d.last_event_at?rel(d.last_event_at):'none');
  const refs=t.referrers||[],paths=t.paths||[];html('top-referrers',refs.length?refs.map(x=>`<div class="list-row"><span>${esc(x.referrer||'direct')}</span><b>${num(x.count)} · ${num(x.uniques)} unique</b></div>`).join(''):'<div class="small">No referrer data.</div>');html('top-paths',paths.length?paths.map(x=>`<div class="list-row"><span>${esc(x.path||'/')}</span><b>${num(x.count)} · ${num(x.uniques)} unique</b></div>`).join(''):'<div class="small">No path data.</div>');
  renderChart(d);
  renderUniqueChart(d);
}

function renderIRC(d){
  const targets=d.broadcast?.targets||[];
  html('irc-pills',targets.map(t=>{
    const state=t.joined?'ON':t.online?'WAIT':'OFF';
    return pill(`${t.label} ${t.channel}`,state,t.joined?'ok':t.online?'warn':'bad');
  }).join(''));
  txt('irc-detail',`${targets.length} delivery targets · persistent fan-out queue · heartbeat ${d.irc?.heartbeat?.idle_ping_seconds||0}s`);
}

function renderReliability(d){
  const r=d.ci_reliability||{},state=String(r.state||'waiting').toLowerCase();
  const decisive=num(r.decisive_runs),resolved=num(r.resolved_incidents),active=num(r.active_incidents);
  txt('ci-rel-window',`${num(r.window_days)||30}d window · ${num(r.runs)} runs retained · ${num(r.coverage_days)}d coverage`);
  txt('ci-rel-state',upper(state));const st=$('ci-rel-state');if(st)st.className=stateClass(state);
  txt('ci-rel-state-note',active?`${active} active incident${active===1?'':'s'}`:decisive?'no active incident':'collecting baseline');
  txt('ci-rel-pass',decisive?`${num(r.pass_rate).toFixed(1)}%`:'n/a');const pass=$('ci-rel-pass');if(pass)pass.className=!decisive?'off':num(r.pass_rate)>=95?'ok':num(r.pass_rate)>=80?'warn':'bad';
  txt('ci-rel-outcomes',`${num(r.success)} success · ${num(r.failed)} failed`);
  txt('ci-rel-incidents',`${active} / ${resolved}`);const inc=$('ci-rel-incidents');if(inc)inc.className=active?'bad':resolved?'ok':'off';
  txt('ci-rel-mttr',resolved?duration(r.mttr_seconds):'n/a');
  txt('ci-rel-p95',num(r.p95_duration_seconds)?duration(r.p95_duration_seconds):'n/a');
  txt('ci-rel-streak',num(r.green_streak));const streak=$('ci-rel-streak');if(streak)streak.className=num(r.green_streak)?'ok':'off';
}

function renderGitHub(d){
  const traffic=d.github_traffic||{},account=d.github_account||{};
  html('github-pills',
    statusPill('API',d.github_api)+
    statusPill('CI',d.github_actions)+
    statusPill('Reliability',d.ci_reliability?.state||'waiting')+
    statusPill('Traffic',traffic.state||'waiting')+
    statusPill(account.account||'account',account.state||'waiting')+
    pill('Auth',d.auth||'?')
  );
  const rate=d.github_rate||{};
  txt('github-detail',`quota ${rate.remaining??'?'} / ${rate.limit??'?'} · red ${num(d.current_ci_failures)} · running ${num(d.current_ci_running)} · expected ${num(d.current_ci_expected)} · flaky ${num(d.current_ci_flaky)}`);
}

function renderAccount(d){
  const a=d.github_account||{},trend=a.trend||{};
  txt('account-repositories',num(a.repositories));txt('account-maintained',num(a.maintained));txt('account-active',num(a.active_30d));txt('account-stars',num(a.stars));txt('account-forks',num(a.forks));txt('account-stale',num(a.stale));
  txt('account-updated',a.last_ok?`public owner-only · updated ${rel(a.last_ok)}`:`${upper(a.state||'waiting')} · ${a.error||'first inventory pending'}`);
  const sd=$('account-stars-delta'),delta=num(trend.stars?.delta),previous=trend.stars?.previous_date||'previous snapshot';if(sd){sd.textContent=`${delta>0?'+':''}${delta} vs ${previous}`;sd.className=delta>0?'up':delta<0?'down':''}
  txt('account-hygiene',`Missing: description ${num(a.missing_description)} · license ${num(a.missing_license)} · topics ${num(a.missing_topics)} · archived ${num(a.archived)} · forks ${num(a.forked)}`);
  const row=(x,meta)=>`<div class="list-row"><span><a href="${esc(x.html_url||'#')}" rel="noopener noreferrer">${esc(x.name||'?')}</a>${x.language?` · ${esc(x.language)}`:''}</span><b>${meta}</b></div>`;
  const recent=Array.isArray(a.recently_pushed)?a.recently_pushed:[],starred=Array.isArray(a.most_starred)?a.most_starred:[];
  html('account-recent',recent.length?recent.map(x=>row(x,x.pushed_at?rel(Date.parse(x.pushed_at)/1000):'never')).join(''):'<div class="small">No public repository cached yet.</div>');
  html('account-starred',starred.length?starred.map(x=>row(x,`★ ${num(x.stars)} · forks ${num(x.forks)} · issues ${num(x.open_issues)}`)).join(''):'<div class="small">No public repository cached yet.</div>');
  const changes=Array.isArray(a.changes)?a.changes:[];html('account-changes',changes.length?changes.map(x=>`<div class="history-row"><span class="source">${esc(upper(x.kind||'change'))}</span> <span class="muted">${x.at?rel(x.at):'time unknown'}</span> ${esc(x.text||'')}</div>`).join(''):'<div class="small">No portfolio change recorded yet.</div>');
}

function renderSources(d){
  html('source-pills',statusPill('Webhook',d.webhook)+statusPill('RSS',d.rss));
  const hook=d.last_webhook_ok?`webhook ${rel(d.last_webhook_ok)}`:'webhook not seen';
  const rss=d.last_rss_ok?`RSS ${rel(d.last_rss_ok)}`:'RSS waiting';
  txt('source-detail',`${hook} · ${rss}`);
}

function renderRuntime(d){
  const st=d.state||{},q=d.queue_detail||{};
  html('runtime-pills',
    pill('Queue',num(d.queue),num(d.queue)?'warn':'ok')+
    pill('State',upper(st.primary||'?'),st.primary==='ok'?'ok':'warn')+
    pill('Uptime',d.uptime||'?','')
  );
  txt('runtime-detail',`oldest ${q.oldest_at?rel(q.oldest_at):'none'} · backup ${st.backup||'?'} · history ${num(d.history_count)}`);
}

function renderBroadcast(d){
  const b=d.broadcast||{},targets=b.targets||[];html('broadcast-targets',targets.map(t=>{const state=t.joined?'ON':t.online?'WAIT':'OFF',cls=t.joined?'ok':t.online?'warn':'bad';return `<div class="audit-target"><strong>${esc(t.label)} · ${esc(t.channel)} <span class="${cls}">${state}</span></strong><small>sent ${num(t.sent)} · pending ${num(t.pending)} · last ${t.last_at?rel(t.last_at):'never'}</small></div>`}).join(''));
  const recent=(b.recent||[])[0];if(recent){const vals=Object.values(recent.targets||{}),total=vals.length,done=vals.filter(Boolean).length;html('broadcast-recent',`Latest fan-out · ${esc(recent.id||'?')} · <b class="${done===total?'ok':'warn'}">${done}/${total} delivered</b> · ${linkify(recent.text||'')}`)}else html('broadcast-recent','No broadcast audit yet.');
}

function renderCounters(d){
  const c=d.counters||{},w=c.webhook||{},g=c.github_poll||{},a=c.actions||{},r=c.rss||{},t=c.traffic||{},p=c.account||{},b=d.broadcast||{};
  txt('counter-webhook',`recv ${num(w.received)} · valid ${num(w.valid)} · sent ${num(w.sent)} · rejected ${num(w.rejected)} · sig ${num(w.bad_signature)} · json ${num(w.invalid_json)}`);
  txt('counter-events',`runs ${num(g.runs)} · pages ${num(g.pages)} · new ${num(g.new)} · sent ${num(g.sent)} · 304 ${num(g.not_modified)} · errors ${num(g.errors)}`);
  txt('counter-actions',`polls ${num(a.polls)} · new ${num(a.new)} · failures ${num(a.failures)} · recovered ${num(a.recoveries)} · sent ${num(a.sent)} · errors ${num(a.errors)}`);
  txt('counter-broadcast',`enqueued ${num(b.enqueued)} · complete ${num(b.completed)} · attempts ${num(b.delivery_attempts)} · failures ${num(b.delivery_failures)}`);
  txt('counter-traffic',`cycles ${num(t.cycles)} · requests ${num(t.requests)} · 403 ${num(t.forbidden)} · errors ${num(t.errors)} · last ${d.last_traffic_ok?rel(d.last_traffic_ok):'never'}`);
  txt('counter-account',`polls ${num(p.polls)} · pages ${num(p.pages)} · 304 ${num(p.not_modified)} · repositories observed ${num(p.repos_seen)} · changes ${num(p.changes_detected)} · errors ${num(p.errors)}`);
  txt('counter-rss',`polls ${num(r.polls)} · new ${num(r.new)} · sent ${num(r.sent)} · 304 ${num(r.not_modified)} · errors ${num(r.errors)}`);
}

function renderTraffic(d){
  // v0.25 renders traffic through stat, chart, referrer and content panels.
}

function renderActivity(d){
  txt('latest-source',upper(d.last_event_source||'event'));
  txt('latest-age',d.last_event_at?rel(d.last_event_at):'time unknown');
  html('latest-text',linkify(d.last_event_text||'No public activity cached yet'));

  const rows=Array.isArray(d.recent_activity)?d.recent_activity:[];
  html('recent-activity',rows.length?rows.map(x=>`<div class="history-row"><span class="source">${esc(upper(x.source||'event'))}</span> <span class="muted">${x.at?rel(x.at):'time unknown'}</span> ${linkify(x.text||'')}</div>`).join(''):'<div class="small">No activity history yet</div>');
}

function render(d){
  if(!d||typeof d!=='object')return;lastDashboard=d;
  const cfg=d.dashboard||{};
  pollMs=Math.max(1000,num(cfg.poll_seconds||3)*1000);
  hiddenMs=Math.max(5000,num(cfg.hidden_poll_seconds||20)*1000);
  timeoutMs=Math.max(1000,num(cfg.timeout_seconds||4)*1000);

  txt('version-badge',`v${d.version||'?'}`);
  txt('repo-name',d.repo||'');

  const health=d.health?.status||'degraded';const hb=$('health-badge'),ht=$('health-text');if(hb){hb.className=health==='ok'?'ok':'warn';hb.textContent='●'}if(ht)ht.textContent=`HEALTH ${upper(health)}`

  renderHero(d);
  renderAccount(d);
  renderIRC(d);
  renderReliability(d);
  renderGitHub(d);
  renderSources(d);
  renderRuntime(d);
  renderBroadcast(d);
  renderCounters(d);
  renderTraffic(d);
  renderActivity(d);

  lastSuccess=Date.now();
  setLive('ok','LIVE · updated now');
}

function nextDelay(){
  const base=document.hidden?hiddenMs:pollMs;
  return Math.min(30000,base*Math.max(1,2**Math.min(failures,3)));
}
function schedule(){
  clearTimeout(timer);
  timer=setTimeout(refresh,nextDelay());
}
async function refresh(){
  if(inFlight){schedule();return}
  if(!navigator.onLine){setLive('warn','OFFLINE · waiting for network');schedule();return}

  inFlight=true;
  setLive('sync','LIVE · syncing…');
  const ctl=new AbortController();
  const killer=setTimeout(()=>ctl.abort(),timeoutMs);

  try{
    const res=await fetch(endpoint(),{
      headers:{Accept:'application/json'},
      cache:'no-store',
      credentials:'same-origin',
      signal:ctl.signal
    });
    if(!res.ok)throw new Error(`HTTP ${res.status}`);
    const data=await res.json();
    failures=0;
    requestAnimationFrame(()=>render(data));
  }catch(err){
    failures++;
    const stale=lastSuccess?` · last good ${Math.floor((Date.now()-lastSuccess)/1000)}s ago`:'';
    setLive('bad',`STALE · ${err.name==='AbortError'?'timeout':err.message}${stale}`);
  }finally{
    clearTimeout(killer);
    inFlight=false;
    schedule();
  }
}

document.addEventListener('click',ev=>{const btn=ev.target.closest('.range-btn');if(!btn)return;chartRange=Math.max(1,num(btn.dataset.range||14));document.querySelectorAll('.range-btn').forEach(x=>x.classList.toggle('active',x===btn));if(lastDashboard){renderChart(lastDashboard);renderUniqueChart(lastDashboard)}});
document.addEventListener('visibilitychange',()=>{
  clearTimeout(timer);
  if(document.hidden)schedule();else refresh();
});
window.addEventListener('online',refresh);
window.addEventListener('offline',()=>setLive('warn','OFFLINE · waiting for network'));

refresh();
})();
JS
}

sub dashboard_html {
 my$hook=uc(webhook_state());my$hook_class=lc($hook)eq'live'?'ok':lc($hook)eq'listening'?'warn':'off';
 my$api=uc(api_state());my$api_class=lc($api)eq'online'?'ok':lc($api)eq'error'?'bad':lc($api)=~/^(?:waiting|limited)$/?'warn':'off';
 my$ci=uc(actions_state());my$ci_class=lc($ci)eq'online'?'ok':lc($ci)eq'error'?'bad':lc($ci)=~/^(?:waiting|limited)$/?'warn':'off';
 my$rss=uc(rss_state());my$rss_class=lc($rss)eq'online'?'ok':lc($rss)eq'error'?'bad':lc($rss)eq'waiting'?'warn':'off';
 my$auth=auth_short();my$auth_class=$auth eq'TOKEN OK'?'ok':$auth eq'TOKEN BAD'||$auth eq'AUTH ERROR'?'bad':'warn';

 my$repo=html_escape($CFG{repo});my$ver=html_escape(VERSION);my$app=html_escape(APP_NAME);my$account_name=html_escape($CFG{account});my$up=html_escape(uptime());
 my$q=scalar@{$STATE{pending}};my$qclass=$q?'warn':'ok';
 my$epi=!$NET{epiknet}{enabled}?'OFF':$NET{epiknet}{up}?'ONLINE':'OFFLINE';my$epi_class=!$NET{epiknet}{enabled}?'off':$NET{epiknet}{up}?'ok':'bad';
 my$lib=!$NET{libera}{enabled}?'OFF':$NET{libera}{up}?'ONLINE':'OFFLINE';my$lib_class=!$NET{libera}{enabled}?'off':$NET{libera}{up}?'ok':'bad';
 my$und=!$NET{undernet}{enabled}?'OFF':$NET{undernet}{up}?'ONLINE':'OFFLINE';my$und_class=!$NET{undernet}{enabled}?'off':$NET{undernet}{up}?'ok':'bad';
 my$und_channels=html_escape(join(' · ',map{$_->{name}.' '.($_->{joined}?'JOINED':'WAIT')}net_channels($NET{undernet})));
 my$lib_sasl=$NET{libera}{sasl_account}ne''?' · SASL '.uc($NET{libera}{sasl_state}):' · SASL off';
 my$lh=html_escape(($RUN{listener}?'HTTP listening':'HTTP DOWN').' · '.($STATE{last_hook_ok}?age($STATE{last_hook_ok}).' · '.($STATE{last_hook_event}||'event'):'No signed GitHub delivery seen yet').($STATE{last_hook_reject_at}?' · last reject '.age($STATE{last_hook_reject_at}).' '.$STATE{last_hook_reject_reason}:''));
 my$api_detail=html_escape(!github_rest_allowed()?'rate limited · resume '.rate_resume_text():$RUN{last_api_error}ne''?$RUN{last_api_error}:$RUN{last_api_ok}?'last OK '.age($RUN{last_api_ok}).' · events '.maxn($CFG{reconcile},$RUN{poll_min}).'s':'waiting for first successful poll');
 my$red=current_ci_failure_count();my$running=current_ci_running_count();my$expected=current_ci_expected_count();
 my$ci_detail=html_escape((!github_rest_allowed()?'rate limited · resume '.rate_resume_text():$RUN{actions_error}ne''?$RUN{actions_error}:$STATE{last_actions_ok}?'last API '.age($STATE{last_actions_ok}).' · '.($STATE{last_action_name}||'workflow').' '.($STATE{last_action_conclusion}||''):'waiting for first Actions poll').' · red '.$red.' · running '.$running.($CFG{actions_expect}?' · expected '.$expected:'').($CFG{actions_flaky_window}?' · flaky '.current_ci_flaky_count():'').($CFG{actions_slow}?' · slow alert '.duration_text($CFG{actions_slow}):''));
 my$ci_rel=ci_reliability_summary();my$ci_rel_state=uc($ci_rel->{state}||'waiting');
 my$ci_rel_class=$ci_rel->{state}eq'stable'?'ok':$ci_rel->{state}eq'degraded'?'bad':$ci_rel->{state}eq'off'?'off':'warn';
 my$ci_rel_pass=$ci_rel->{decisive_runs}?traffic_num($ci_rel->{pass_rate},1).'%':'n/a';
 my$ci_rel_pass_class=!$ci_rel->{decisive_runs}?'off':$ci_rel->{pass_rate}>=95?'ok':$ci_rel->{pass_rate}>=80?'warn':'bad';
 my$ci_rel_state_note=$ci_rel->{active_incidents}?$ci_rel->{active_incidents}.' active incident'.($ci_rel->{active_incidents}==1?'':'s'):$ci_rel->{decisive_runs}?'no active incident':'collecting baseline';
 my$ci_rel_incident_class=$ci_rel->{active_incidents}?'bad':$ci_rel->{resolved_incidents}?'ok':'off';
 my$rss_detail_txt=html_escape($RUN{rss_error}ne''?$RUN{rss_error}:$STATE{last_rss_ok}?age($STATE{last_rss_ok}).' · '.($STATE{last_rss_title}||'feed OK'):'waiting for first successful poll');
 my$rss_detail_html=$STATE{last_rss_link}ne''&&$STATE{last_rss_title}ne''
  ? age($STATE{last_rss_ok}).' · <a href="'.html_escape($STATE{last_rss_link}).'" rel="noopener noreferrer">'.html_escape($STATE{last_rss_title}).'</a>'
  : $rss_detail_txt;

 my$last=$STATE{last_event_text}?short(repair_activity_text($STATE{last_event_text},$STATE{last_event_source}),220):'No event cached yet';
 my$le=html_linkify($last);my$last_source=html_escape(uc($STATE{last_event_source}||'legacy'));
 my$last_age=html_escape($STATE{last_event_at}?age($STATE{last_event_at}):'time unknown');

 my$health=health_report();my$health_txt=uc($health->{status});my$health_class=$health->{status}eq'ok'?'ok':'warn';
 my$qsum=queue_snapshot();my@qparts;
 for my$t(enabled_targets()){my$m=$t->{metric};push@qparts,$t->{net}{label}.' '.$t->{channel}.' pending '.int($qsum->{$m}||0)}
 my$qdetail=html_escape(join(' · ',@qparts).' · oldest '.($qsum->{oldest_at}?age($qsum->{oldest_at}):'none'));my$state_info=state_status();my$state_txt=html_escape('state '.$state_info->{primary}.' · backup '.$state_info->{backup});
 my$hero_t=traffic_summary_data();my$hero_ct=traffic_recent_trend('clones');my$hero_vt=traffic_recent_trend('views');
 my$hero_clones=int($hero_t->{clones}||0);my$hero_uniques=int($hero_t->{clone_uniques}||0);
 my$hero_views=int($hero_t->{views}||0);my$hero_view_uniques=int($hero_t->{view_uniques}||0);
 my$hero_clones_today=int($hero_ct->{current}||0);my$hero_views_today=int($hero_vt->{current}||0);
 my$hero_traffic_age=html_escape($STATE{last_traffic_ok}?age($STATE{last_traffic_ok}):'waiting');
 my$hero_clone_delta=int($hero_ct->{delta}||0);my$hero_view_delta=int($hero_vt->{delta}||0);
 my@hero_rows=traffic_daily_rows();my$hero_max=1;for my$hr(@hero_rows){my$v=int($hr->{clones}||0)+int($hr->{views}||0);$hero_max=$v if$v>$hero_max}
 my$hero_spark=join('',map{my$v=int($_->{clones}||0)+int($_->{views}||0);my$h=$v?int(100*$v/$hero_max):0;$h=12 if$h>0&&$h<12;'<i style="height:'.$h.'%" title="'.html_escape(($_->{date}||'').' · '.$v.' combined').'"></i>'}@hero_rows);
 my@initial_refs=traffic_top('referrers');my@initial_paths=traffic_top('paths');
 my$initial_refs_html=@initial_refs?join('',map{'<div class="list-row"><span>'.html_escape($_->{referrer}||'direct').'</span><b>'.int($_->{count}||0).' · '.int($_->{uniques}||0).' unique</b></div>'}@initial_refs):'<div class="small">No referrer data.</div>';
 my$initial_paths_html=@initial_paths?join('',map{'<div class="list-row"><span>'.html_escape($_->{path}||'/').'</span><b>'.int($_->{count}||0).' · '.int($_->{uniques}||0).' unique</b></div>'}@initial_paths):'<div class="small">No path data.</div>';
 my$account=account_summary();
 my$account_recent_html=@{$account->{recently_pushed}}?join('',map{'<div class="list-row"><span><a href="'.html_escape($_->{html_url}).'" rel="noopener noreferrer">'.html_escape($_->{name}).'</a>'.($_->{language}?' · '.html_escape($_->{language}):'').'</span><b>'.html_escape(iso8601_epoch($_->{pushed_at})?age(iso8601_epoch($_->{pushed_at})):'never').'</b></div>'}@{$account->{recently_pushed}}):'<div class="small">No public repository cached yet.</div>';
 my$account_starred_html=@{$account->{most_starred}}?join('',map{'<div class="list-row"><span><a href="'.html_escape($_->{html_url}).'" rel="noopener noreferrer">'.html_escape($_->{name}).'</a>'.($_->{language}?' · '.html_escape($_->{language}):'').'</span><b>★ '.int($_->{stars}||0).' · forks '.int($_->{forks}||0).' · issues '.int($_->{open_issues}||0).'</b></div>'}@{$account->{most_starred}}):'<div class="small">No public repository cached yet.</div>';
 my$account_age=html_escape($account->{last_ok}?'public owner-only · updated '.age($account->{last_ok}):uc($account->{state}).' · '.($account->{error}||'first inventory pending'));
 my$account_star_delta=int($account->{trend}{stars}{delta}||0);my$account_star_sign=$account_star_delta>0?'+':'';my$account_star_class=$account_star_delta>0?'up':$account_star_delta<0?'down':'';
 my$account_prev_label=html_escape($account->{trend}{stars}{previous_date}||'previous snapshot');
 my$account_changes=account_change_rows();my$account_changes_html=@$account_changes?join('',map{'<div class="history-row"><span class="source">'.html_escape(uc($_->{kind}||'change')).'</span> <span class="muted">'.html_escape($_->{at}?age($_->{at}):'time unknown').'</span> '.html_escape($_->{text}||'').'</div>'}@$account_changes):'<div class="small">No portfolio change recorded yet.</div>';
 my$audience=traffic_audience_summary();
 my$latest_traffic=traffic_latest_snapshot();my$traffic_history=traffic_history_summary();
 my$aud_week=$audience->{comparison_7d};my$aud_clone_change=$aud_week->{changes}{clones};
 my$aud_peak=$audience->{best_clone_unique};my$aud_peak_value=int($aud_peak->{clone_uniques}||0);my$aud_peak_date=html_escape(substr(clean($aud_peak->{date}||'?'),0,10));
 my$aud_change_sign=$aud_clone_change->{pct}>0?'+':'';my$aud_change_class=$aud_clone_change->{delta}>0?'up':$aud_clone_change->{delta}<0?'down':'';
 my$traffic_html=eval{traffic_dashboard_html()};
 if(!defined($traffic_html)||$@){
  my$why=clean($@||'unknown render error');$RUN{traffic_render_error}=$why;
  logmsg('WARN',"Traffic dashboard render failed: $why");
  $traffic_html='<section class="card full traffic-panel"><div class="label">GitHub Traffic</div><div class="value bad">RENDER DEGRADED</div><div class="small">'.html_escape($why).'</div></section>';
 }else{$RUN{traffic_render_error}=''}
 my@hist=recent_history($CFG{history_show});my$history_html='';
 for my$h(@hist){$history_html.='<div class="history-row"><span class="source">'.html_escape(uc($h->{source}||'event')).'</span> <span class="muted">'.html_escape($h->{at}?age($h->{at}):'time unknown').'</span> '.html_linkify(repair_activity_text($h->{text},$h->{source})).'</div>'}
 $history_html='<div class="small">No activity history yet</div>' if$history_html eq'';
 my$hook_stats=html_escape("recv $STATS{hook_received} · valid $STATS{hook_valid} · sent $STATS{hook_sent} · dupes $STATS{hook_dupe} · rejected $STATS{hook_invalid} · sig $STATS{hook_bad_signature} · hdr $STATS{hook_missing_headers} · json $STATS{hook_bad_json} · repo $STATS{hook_wrong_repo}");
 my$poll_stats=html_escape("runs $STATS{poll_runs} · pages $STATS{poll_pages} · new $STATS{poll_new} · sent $STATS{poll_sent} · 304 $STATS{poll_not_modified} · gaps $STATS{poll_gap} · errors $STATS{poll_errors}");
 my$actions_stats=html_escape("polls $STATS{actions_polls} · pages $STATS{actions_pages} · new $STATS{actions_new} · failures $STATS{actions_failures} · recovered $STATS{actions_recoveries} · slow $STATS{actions_slow_alerts} · missing $STATS{actions_missing_alerts} · flaky $STATS{actions_flaky_alerts} · sent $STATS{actions_sent} · enriched $STATS{actions_enriched} · enrich skipped $STATS{actions_enrich_skipped} · 304 $STATS{actions_not_modified} · gaps $STATS{actions_gap} · errors $STATS{actions_errors}");
 my$rss_stats=html_escape("polls $STATS{rss_polls} · new $STATS{rss_new} · sent $STATS{rss_sent} · 304 $STATS{rss_not_modified} · same $STATS{rss_unchanged} · errors $STATS{rss_errors}");

 my@bt=broadcast_target_snapshot();my$irc_pills='';my$broadcast_targets_html='';
 for my$b(@bt){
  my$cls=$b->{joined}?'ok':$b->{online}?'warn':'bad';my$state=$b->{joined}?'ON':$b->{online}?'WAIT':'OFF';
  $irc_pills.='<span class="pill"><b>'.html_escape($b->{label}.' '.$b->{channel}).'</b><span class="'.$cls.'">'.$state.'</span></span>';
  $broadcast_targets_html.='<div class="broadcast-target"><b>'.html_escape($b->{label}.' '.$b->{channel}).' <span class="'.$cls.'">'.$state.'</span></b><small>sent '.int($b->{sent}).' · pending '.int($b->{pending}).' · last '.html_escape($b->{last_at}?age($b->{last_at}):'never').'</small></div>';
 }
 my$gh_pills='<span class="pill">API <b class="'.$api_class.'">'.$api.'</b></span><span class="pill">CI <b class="'.$ci_class.'">'.$ci.'</b></span><span class="pill">Traffic <b class="'.(traffic_state()eq'online'?'ok':traffic_state()eq'error'?'bad':'warn').'">'.html_escape(uc(traffic_state())).'</b></span><span class="pill">'.$account_name.' <b class="'.(account_state()eq'online'?'ok':account_state()eq'error'?'bad':account_state()eq'off'?'off':'warn').'">'.html_escape(uc(account_state())).'</b></span><span class="pill">Auth <b class="'.$auth_class.'">'.html_escape($auth).'</b></span>';
 my$source_pills='<span class="pill">Webhook <b class="'.$hook_class.'">'.$hook.'</b></span><span class="pill">RSS <b class="'.$rss_class.'">'.$rss.'</b></span>';
 my$sys_pills='<span class="pill">Queue <b class="'.($q?'warn':'ok').'">'.$q.'</b></span><span class="pill">State <b class="'.($state_info->{primary}eq'ok'?'ok':'warn').'">'.html_escape($state_info->{primary}).'</b></span><span class="pill">Uptime <b>'.$up.'</b></span>';
 my$hero_fanout_total=scalar(@bt);my$hero_fanout_joined=scalar grep{$_->{joined}}@bt;
 my$essential_pills=
  '<span class="pill">Webhook <b class="'.$hook_class.'">'.$hook.'</b></span>'.
  '<span class="pill">CI <b class="'.$ci_class.'">'.$ci.'</b></span>'.
  '<span class="pill">Fan-out <b class="'.($hero_fanout_joined==$hero_fanout_total?'ok':'warn').'">'.$hero_fanout_joined.'/'.$hero_fanout_total.'</b></span>'.
  '<span class="pill">Queue <b class="'.($q?'warn':'ok').'">'.$q.'</b></span>'.
  '<span class="pill">RSS <b class="'.$rss_class.'">'.$rss.'</b></span>';
 my$last_broadcast=@{$STATE{broadcast_history}}?$STATE{broadcast_history}[-1]:undef;my$broadcast_recent='';
 if($last_broadcast){my$total=scalar keys%{$last_broadcast->{targets}||{}};my$done=scalar grep{$_}values%{$last_broadcast->{targets}||{}};$broadcast_recent='<div class="broadcast-recent">Latest fan-out · '.html_escape($last_broadcast->{id}||'?').' · <b class="'.($done==$total?'ok':'warn').'">'.$done.'/'.$total.' delivered</b> · '.html_linkify(short($last_broadcast->{text}||'',180)).'</div>'}

 return <<"HTML";
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>$app $ver</title>
<script src="?asset=dashboard-js" defer></script>
<style>
:root{color-scheme:dark;--bg:#0b0c0e;--panel:#111217;--panel2:#0e1014;--line:#24262d;--line2:#333640;--text:#e9edf2;--muted:#8d95a3;--muted2:#6f7784;--ok:#73bf69;--warn:#f2cc0c;--bad:#f2495c;--accent:#5794f2;--accent2:#73a5f5;--cyan:#56d2c9}
*{box-sizing:border-box}html{min-height:100%;scroll-behavior:smooth}body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);font:14px/1.45 Inter,system-ui,-apple-system,Segoe UI,sans-serif}
body:before{content:"";position:fixed;inset:0;pointer-events:none;background:linear-gradient(90deg,transparent 0%,rgba(255,255,255,.012) 50%,transparent 100%)}
main{position:relative;z-index:1;max-width:1360px;margin:0 auto 40px;padding:0 18px}.top{position:sticky;top:0;z-index:20;display:flex;align-items:center;justify-content:space-between;gap:16px;margin:0 -18px 12px;padding:10px 18px;background:rgba(11,12,14,.94);border-bottom:1px solid var(--line);backdrop-filter:blur(12px)}
h1{font-size:20px;font-weight:650;letter-spacing:-.02em;margin:0}.repo{color:#aab4c0;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:11px;margin-top:1px}
.badge{border:1px solid var(--line);border-radius:999px;padding:5px 9px;color:var(--muted);white-space:nowrap;background:#10151c}
.grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:8px}.card{background:var(--panel);border:1px solid var(--line);border-radius:4px;padding:12px;box-shadow:none;transition:border-color .12s ease,background .12s ease}.card:hover{border-color:var(--line2);background:#13141a}
.label{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:8px}.value{font-weight:700;font-size:17px}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}.off{color:var(--muted)}
.full{grid-column:1/-1}.small{font-size:13px;color:var(--muted);margin-top:7px;overflow-wrap:anywhere}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.stat{padding:11px;border:1px solid var(--line);border-radius:9px;background:var(--bg)}
.stat b{display:block;color:var(--accent);font-size:12px;text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px}.stat span{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:13px}
.source{font-size:11px;padding:3px 7px;border:1px solid var(--line);border-radius:999px;color:var(--muted);margin-left:7px;vertical-align:middle}.muted{color:var(--muted)}.history-row{padding:7px 0;border-top:1px solid var(--line);overflow-wrap:anywhere}.history-row:first-child{border-top:0}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}footer{margin-top:18px;color:var(--muted);font-size:12px}
.live-badge{display:inline-flex;align-items:center;gap:7px}.live-dot{width:7px;height:7px;border-radius:50%;background:currentColor;box-shadow:0 0 0 0 currentColor;animation:pulseLive 1.8s infinite}.live-badge.sync{color:var(--accent)}\@keyframes pulseLive{0%{box-shadow:0 0 0 0 currentColor}70%{box-shadow:0 0 0 7px transparent}100%{box-shadow:0 0 0 0 transparent}}.traffic-host{display:contents}.compact-card{padding:12px 14px}.compact-lines{display:flex;flex-wrap:wrap;gap:7px;margin-top:7px}.pill{display:inline-flex;align-items:center;gap:5px;border:1px solid var(--line);border-radius:999px;padding:4px 8px;background:rgba(0,0,0,.18);font-size:11px}.pill b{font-size:11px}.broadcast-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}.broadcast-target{border:1px solid var(--line);border-radius:10px;padding:10px;background:rgba(0,0,0,.17)}.broadcast-target b{display:block;font-size:12px}.broadcast-target small{display:block;color:var(--muted);margin-top:4px}.broadcast-recent{margin-top:10px;font-size:12px;color:var(--muted)}
.traffic-panel{background:var(--panel);border-color:#28323d}
.traffic-kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.traffic-kpi{padding:14px;border:1px solid var(--line);border-radius:12px;background:rgba(0,0,0,.20)}
.traffic-kpi span{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.06em}.traffic-kpi b{display:block;font-size:25px;margin:4px 0}.traffic-kpi small{color:var(--muted)}
.traffic-kpi.cyan b,.traffic-kpi.pink b{color:var(--accent2)}.traffic-kpi.green b,.traffic-kpi.yellow b{color:#b9c5d1}
.traffic-spark{height:130px;display:flex;align-items:flex-end;gap:5px;padding:14px;margin-top:12px;border:1px solid var(--line);border-radius:12px;background:rgba(0,0,0,.20)}
.traffic-day{flex:1;height:100%;display:flex;align-items:flex-end;gap:2px}.traffic-bar{flex:1;min-height:0;border-radius:5px 5px 2px 2px}.traffic-bar.clones{background:#607f9a}.traffic-bar.views{background:#8aa9bf}
.traffic-legend{display:flex;gap:16px;color:var(--muted);font-size:11px;margin:7px 0}.traffic-legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px}.legend-clones{background:#607f9a}.legend-views{background:#8aa9bf}
.traffic-columns{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px}.traffic-columns>div{border:1px solid var(--line);border-radius:12px;padding:12px;background:rgba(0,0,0,.16)}.traffic-columns h3{font-size:12px;margin:0 0 7px;color:var(--accent)}
.traffic-list-row{display:flex;justify-content:space-between;gap:10px;border-top:1px solid var(--line);padding:6px 0;font-size:12px}.traffic-list-row:first-of-type{border-top:0}.traffic-list-row span{overflow-wrap:anywhere}.traffic-list-row b{white-space:nowrap;color:var(--muted)}
.traffic-table-wrap{overflow-x:auto;margin-top:12px}.traffic-table{width:100%;border-collapse:collapse;font-size:12px}.traffic-table th,.traffic-table td{padding:7px 9px;border-bottom:1px solid var(--line);text-align:right}.traffic-table th:first-child,.traffic-table td:first-child{text-align:left}.traffic-table th{color:var(--muted)}
.toolbar-left{display:flex;align-items:center;gap:10px;min-width:0}.toolbar-mark{width:27px;height:27px;border-radius:5px;display:grid;place-items:center;background:#161922;border:1px solid var(--line2);color:var(--accent);font-weight:800}.toolbar-title{min-width:0}.toolbar-right{display:flex;align-items:center;gap:6px;flex-wrap:wrap;justify-content:flex-end}.toolbar-chip{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);background:#111217;border-radius:4px;padding:5px 8px;color:var(--muted);font-size:10px}.toolbar-chip strong{color:var(--text);font-weight:600}
.stat-row{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-bottom:8px}.stat-panel{min-height:108px;padding:11px 12px;border:1px solid var(--line);border-radius:4px;background:var(--panel);position:relative;overflow:hidden}.stat-panel:before{content:"";position:absolute;left:0;top:0;bottom:0;width:2px;background:var(--accent);opacity:.85}.stat-panel .stat-title{font-size:11px;color:var(--muted);font-weight:600}.stat-panel .stat-value{font-size:30px;line-height:1;margin-top:12px;letter-spacing:-.035em;font-weight:600;color:#f2f5f8}.stat-panel .stat-meta{display:flex;justify-content:space-between;gap:8px;margin-top:9px;color:var(--muted);font-size:10px}.stat-panel .stat-delta.up{color:var(--ok)}.stat-panel .stat-delta.down{color:var(--warn)}.stat-panel.clone:before{background:#5794f2}.stat-panel.unique:before{background:#73a5f5}.stat-panel.views:before{background:#56d2c9}.stat-panel.visitors:before{background:#73bf69}
.dashboard-row{display:grid;grid-template-columns:minmax(0,1.7fr) minmax(320px,1fr);gap:8px;margin-bottom:8px}.panel-title{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:8px;color:#c7cdd5;font-size:11px;font-weight:600}.panel-title small{color:var(--muted2);font-weight:500}.chart-panel{min-height:305px}.chart-wrap{height:238px;position:relative}.chart-svg{display:block;width:100%;height:100%;overflow:visible}.chart-grid{stroke:#252831;stroke-width:1}.chart-axis{fill:#747d8b;font-size:10px}.chart-line-clones{fill:none;stroke:#5794f2;stroke-width:2}.chart-line-views{fill:none;stroke:#56d2c9;stroke-width:2}.chart-dot{stroke:#0b0c0e;stroke-width:2}.chart-area-clones{fill:url(#cloneArea);opacity:.17}.chart-area-views{fill:url(#viewArea);opacity:.11}.chart-legend{display:flex;gap:14px;align-items:center;color:var(--muted);font-size:10px;margin-top:5px;flex-wrap:wrap}.chart-legend i{width:9px;height:2px;display:inline-block;margin-right:5px;vertical-align:middle}.legend-blue{background:#5794f2}.legend-cyan{background:#56d2c9}.legend-unique-cloners{background:#b877d9}.legend-unique-visitors{background:#73bf69}
.unique-chart-panel{min-height:305px}.unique-chart-panel .chart-wrap{height:238px}.unique-chart-note{color:var(--muted2);font-size:10px;margin-top:5px}
.chart-line-cloner-uniques{fill:none;stroke:#b877d9;stroke-width:2}.chart-line-visitor-uniques{fill:none;stroke:#73bf69;stroke-width:2}.chart-area-cloner-uniques{fill:url(#clonerUniqueArea);opacity:.14}.chart-area-visitor-uniques{fill:url(#visitorUniqueArea);opacity:.11}
.audience-strip{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:6px;margin-bottom:8px}.audience-cell{display:flex;align-items:center;justify-content:space-between;gap:10px;background:var(--panel);border:1px solid var(--line);border-radius:4px;padding:8px 10px}.audience-cell span{color:var(--muted);font-size:9px;text-transform:uppercase;letter-spacing:.06em}.audience-cell strong{font-size:11px;text-align:right;color:#dce2e8}.audience-cell strong.up{color:var(--ok)}.audience-cell strong.down{color:var(--warn)}
.pulse-strip{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:6px;margin-bottom:8px}.pulse-cell{display:flex;align-items:center;justify-content:space-between;gap:8px;background:var(--panel);border:1px solid var(--line);border-radius:4px;padding:8px 10px}.pulse-cell .pulse-label{color:var(--muted);font-size:9px;text-transform:uppercase;letter-spacing:.06em}.pulse-cell .pulse-value{font-size:11px;text-align:right}
.ci-reliability-panel{margin-bottom:8px;border-color:#2b3442}.ci-reliability-grid{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:6px}.ci-reliability-cell{min-width:0;border:1px solid var(--line);border-radius:4px;background:#0f1115;padding:9px 10px}.ci-reliability-cell span{display:block;color:var(--muted);font-size:9px;text-transform:uppercase;letter-spacing:.06em}.ci-reliability-cell strong{display:block;margin-top:3px;font-size:16px;line-height:1.2;color:#dce2e8;overflow-wrap:anywhere}.ci-reliability-cell small{display:block;margin-top:4px;color:var(--muted2);font-size:9px;overflow-wrap:anywhere}.ci-reliability-cell strong.ok{color:var(--ok)}.ci-reliability-cell strong.warn{color:var(--warn)}.ci-reliability-cell strong.bad{color:var(--bad)}.ci-reliability-cell strong.off{color:var(--muted)}
.pulse-panel{display:flex;flex-direction:column;gap:8px}.pulse-row{display:flex;align-items:center;justify-content:space-between;gap:10px;padding-bottom:7px;border-bottom:1px solid var(--line)}.pulse-row:last-child{border-bottom:0}.pulse-label{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.06em}.pulse-value{font-size:12px;color:#dce2e8;text-align:right}.pulse-value.ok{color:var(--ok)}.pulse-value.warn{color:var(--warn)}.pulse-value.bad{color:var(--bad)}
.lower-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px}.list-panel{min-height:182px}.list-row{display:flex;justify-content:space-between;gap:12px;padding:7px 0;border-top:1px solid var(--line);font-size:11px}.list-row:first-child{border-top:0}.list-row span{color:#c9d0d8;overflow-wrap:anywhere}.list-row b{color:var(--muted);white-space:nowrap;font-weight:550}.panel-toolbar{display:flex;gap:4px;align-items:center}.range-btn{appearance:none;border:1px solid var(--line);background:#0f1115;color:var(--muted);border-radius:3px;padding:3px 7px;font-size:10px;cursor:pointer}.range-btn.active{border-color:#3e6caa;background:#172033;color:#dce9fa}.range-btn:hover{border-color:var(--line2);color:var(--text)}
.account-panel{margin-bottom:8px}.account-kpis{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:6px;margin:8px 0}.account-kpi{display:flex;align-items:center;justify-content:space-between;gap:8px;border:1px solid var(--line);border-radius:4px;background:#0f1115;padding:8px 10px}.account-kpi span{color:var(--muted);font-size:9px;text-transform:uppercase;letter-spacing:.06em}.account-kpi strong{font-size:15px}.account-meta{display:flex;justify-content:space-between;gap:12px;color:var(--muted);font-size:10px;margin-top:7px;flex-wrap:wrap}
.tooltip{position:fixed;z-index:40;pointer-events:none;background:#181a20;border:1px solid #343741;border-radius:4px;padding:7px 9px;color:#dce2e8;font-size:10px;box-shadow:0 8px 24px rgba(0,0,0,.35);display:none}.audit-summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:6px}.audit-target{padding:8px;border:1px solid var(--line);background:#0f1115;border-radius:3px}.audit-target strong{display:block;font-size:11px}.audit-target small{color:var(--muted);font-size:10px}
.hero{border:1px solid var(--line2);border-radius:15px;padding:15px 17px;margin-bottom:10px;background:#10151c;box-shadow:0 12px 34px rgba(0,0,0,.18)}
.hero-head{display:flex;justify-content:space-between;align-items:flex-start;gap:18px}.hero-title{font-size:11px;text-transform:uppercase;letter-spacing:.11em;color:#9aa6b5;font-weight:800}.hero-sub{margin-top:3px;color:var(--muted);font-size:11px}
.hero-metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-top:12px}.hero-metric{padding:10px 11px;border:1px solid var(--line);border-radius:10px;background:#0e1319}.hero-metric span{display:block;color:var(--muted);font-size:9px;text-transform:uppercase;letter-spacing:.08em;font-weight:800}.hero-metric b{display:block;font-size:22px;line-height:1.1;margin-top:3px;letter-spacing:-.02em}.hero-metric small{display:block;color:var(--muted);margin-top:3px;font-size:10px}.hero-metric.clone b,.hero-metric.views b{color:var(--accent2)}.hero-metric.unique b,.hero-metric.visitors b{color:#c8d1dc}
.essential-strip{display:flex;align-items:center;justify-content:space-between;gap:12px;border:1px solid var(--line);border-radius:11px;padding:8px 10px;margin-bottom:11px;background:#0e1319}.essential-pills{display:flex;flex-wrap:wrap;gap:6px}.essential-note{color:var(--muted);font-size:11px;white-space:nowrap}
.section-title{grid-column:1/-1;display:flex;align-items:center;justify-content:space-between;margin:6px 2px -2px;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.11em;font-weight:850}.section-title span{font-size:10px;text-transform:none;letter-spacing:0;font-weight:500}
.ops-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.ops-grid .compact-card{min-height:116px}
.card.traffic-panel{border-color:rgba(103,232,249,.20);box-shadow:0 18px 60px rgba(0,0,0,.22)}
.hero-trends{display:flex;gap:8px;align-items:center;margin-top:9px}.trend-chip{display:inline-flex;align-items:center;gap:5px;color:var(--muted);font-size:10px;border-top:1px solid var(--line);padding-top:7px;min-width:0}.trend-chip b{color:#cbd5df;font-weight:700}.trend-up{color:var(--ok)!important}.trend-down{color:var(--warn)!important}.hero-spark{height:28px;display:flex;align-items:flex-end;gap:2px;margin-left:auto;min-width:160px;max-width:260px;flex:1}.hero-spark i{display:block;flex:1;min-width:2px;background:#3c5367;border-radius:2px 2px 0 0;opacity:.82}
details.card>summary{cursor:pointer;list-style:none;display:flex;align-items:center;justify-content:space-between;gap:12px;color:#a8b3c0;font-size:11px;text-transform:uppercase;letter-spacing:.09em;font-weight:800}details.card>summary::-webkit-details-marker{display:none}details.card>summary:after{content:"＋";font-size:14px;color:var(--muted)}details.card[open]>summary:after{content:"−"}details.card[open]>summary{margin-bottom:12px}.details-note{color:var(--muted);font-size:10px;text-transform:none;letter-spacing:0;font-weight:500}
\@media(max-width:900px){.stat-row{grid-template-columns:repeat(2,minmax(0,1fr))}.dashboard-row,.lower-grid{grid-template-columns:1fr}.chart-panel,.unique-chart-panel{min-height:275px}.pulse-strip,.ci-reliability-grid{grid-template-columns:repeat(3,minmax(0,1fr))}.audience-strip,.account-kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.pulse-panel{min-height:auto}}
\@media(max-width:560px){.stat-row{grid-template-columns:1fr 1fr}.stat-panel .stat-value{font-size:24px}.top{align-items:flex-start}.toolbar-right{justify-content:flex-start}.chart-wrap,.unique-chart-panel .chart-wrap{height:205px}.pulse-strip,.ci-reliability-grid,.audience-strip{grid-template-columns:repeat(2,minmax(0,1fr))}.audit-summary{grid-template-columns:repeat(2,minmax(0,1fr))}}
\@media(max-width:900px){.hero-metrics,.ops-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.essential-strip{align-items:flex-start;flex-direction:column}.essential-note{white-space:normal}}
\@media(max-width:900px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.stats,.traffic-kpis,.broadcast-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
\@media(max-width:520px){.grid,.stats,.traffic-kpis,.traffic-columns,.broadcast-grid,.hero-metrics,.ops-grid,.account-kpis{grid-template-columns:1fr}.full{grid-column:1}.hero{padding:15px}.top{align-items:flex-start}.hero-head{flex-direction:column}.essential-strip{padding:9px}}
</style>
</head>
<body><main>
<div class="top">
 <div class="toolbar-left"><div class="toolbar-mark">G</div><div class="toolbar-title"><h1>$app <span class="badge" id="version-badge">v$ver</span></h1><div class="repo" id="repo-name">$repo</div></div></div>
 <div class="toolbar-right"><span class="toolbar-chip"><span id="health-badge" class="$health_class">●</span><strong id="health-text">HEALTH $health_txt</strong></span><span class="toolbar-chip"><span class="live-dot"></span><strong id="live-badge">LIVE · connecting…</strong></span><span class="toolbar-chip">Latest <strong id="toolbar-latest-traffic">$latest_traffic->{clones} clones · $latest_traffic->{clone_uniques} unique</strong></span><span class="toolbar-chip">Audience <strong id="toolbar-audience">$audience->{clone_uniques} cloners · $audience->{view_uniques} visitors</strong></span><span class="toolbar-chip">UTC · rolling 14d</span></div>
</div>

<div class="stat-row">
 <section class="stat-panel clone"><div class="stat-title">Clones · 14 days</div><div class="stat-value" id="stat-clones">$audience->{clones}</div><div class="stat-meta"><span id="stat-clones-unique">$audience->{clone_uniques} unique cloners</span><span id="stat-clones-delta" class="stat-delta">@{[$hero_clone_delta>0?'+':'']}$hero_clone_delta today</span></div></section>
 <section class="stat-panel unique"><div class="stat-title">Unique cloners · 14 days</div><div class="stat-value" id="stat-clone-uniques">$audience->{clone_uniques}</div><div class="stat-meta"><span id="stat-clone-uniques-today">$audience->{today_clone_uniques} today</span><span id="stat-clone-uniques-delta" class="stat-delta">@{[$audience->{clone_unique_trend}{delta}>0?'+':'']}$audience->{clone_unique_trend}{delta} vs previous</span></div></section>
 <section class="stat-panel views"><div class="stat-title">Views · 14 days</div><div class="stat-value" id="stat-views">$audience->{views}</div><div class="stat-meta"><span id="stat-views-unique">$audience->{view_uniques} unique visitors</span><span id="stat-views-delta" class="stat-delta">@{[$hero_view_delta>0?'+':'']}$hero_view_delta today</span></div></section>
 <section class="stat-panel visitors"><div class="stat-title">Unique visitors · 14 days</div><div class="stat-value" id="stat-view-uniques">$audience->{view_uniques}</div><div class="stat-meta"><span id="stat-view-uniques-today">$audience->{today_view_uniques} today</span><span id="stat-view-uniques-delta" class="stat-delta">@{[$audience->{view_unique_trend}{delta}>0?'+':'']}$audience->{view_unique_trend}{delta} vs previous</span></div></section>
</div>

<div class="dashboard-row">
 <section class="card chart-panel"><div class="panel-title"><span>Repository traffic</span><div class="panel-toolbar"><button class="range-btn" data-range="7">7d</button><button class="range-btn active" data-range="14">14d</button><button class="range-btn" data-range="30">30d</button><button class="range-btn" data-range="90">90d</button></div></div><div class="chart-wrap"><svg id="traffic-chart" class="chart-svg" role="img" aria-label="GitHub clones and views over time"></svg><div id="chart-tooltip" class="tooltip"></div></div><div class="chart-legend"><span><i class="legend-blue"></i>Clones</span><span><i class="legend-cyan"></i>Views</span><span id="chart-updated">updated $hero_traffic_age · $traffic_history->{days}d retained</span></div></section>
 <section class="card unique-chart-panel"><div class="panel-title"><span>Unique audience</span><small id="unique-chart-range">14d daily curve</small></div><div class="chart-wrap"><svg id="unique-chart" class="chart-svg" role="img" aria-label="Daily unique cloners and unique visitors"></svg><div id="unique-chart-tooltip" class="tooltip"></div></div><div class="chart-legend"><span><i class="legend-unique-cloners"></i>Unique cloners</span><span><i class="legend-unique-visitors"></i>Unique visitors</span></div><div class="unique-chart-note">GitHub aggregates unique cloners and visitors; raw IP addresses are not exposed.</div></section>
</div>

<div class="audience-strip">
 <div class="audience-cell"><span>Clone depth</span><strong id="audience-clone-depth">@{[traffic_num($audience->{clones_per_unique},2)]} / cloner</strong></div>
 <div class="audience-cell"><span>Daily unique avg</span><strong id="audience-unique-average">@{[traffic_num($audience->{avg_daily_clone_uniques},1)]} cloners</strong></div>
 <div class="audience-cell"><span>Unique clone peak</span><strong id="audience-unique-peak">$aud_peak_value · $aud_peak_date</strong></div>
 <div class="audience-cell"><span>7d clones</span><strong id="audience-week-change" class="$aud_change_class">$aud_change_sign@{[traffic_num($aud_clone_change->{pct},1)]}% vs previous</strong></div>
</div>

<div class="pulse-strip">
 <div class="pulse-cell"><span class="pulse-label">Webhook</span><span class="pulse-value $hook_class" id="pulse-webhook">$hook</span></div>
 <div class="pulse-cell"><span class="pulse-label">CI</span><span class="pulse-value $ci_class" id="pulse-ci">$ci</span></div>
 <div class="pulse-cell"><span class="pulse-label">Fan-out</span><span class="pulse-value" id="pulse-fanout">$hero_fanout_joined/$hero_fanout_total</span></div>
 <div class="pulse-cell"><span class="pulse-label">Queue</span><span class="pulse-value" id="pulse-queue">$q</span></div>
 <div class="pulse-cell"><span class="pulse-label">Latest traffic</span><span class="pulse-value" id="pulse-today">$latest_traffic->{clones} clones · $latest_traffic->{clone_uniques} unique</span></div>
 <div class="pulse-cell"><span class="pulse-label">Latest</span><span class="pulse-value" id="pulse-latest">$last_age</span></div>
</div>

<section class="card ci-reliability-panel">
 <div class="panel-title"><span>CI reliability</span><small id="ci-rel-window">$ci_rel->{window_days}d window · $ci_rel->{runs} runs retained · $ci_rel->{coverage_days}d coverage</small></div>
 <div class="ci-reliability-grid">
  <div class="ci-reliability-cell"><span>Signal</span><strong id="ci-rel-state" class="$ci_rel_class">$ci_rel_state</strong><small id="ci-rel-state-note">$ci_rel_state_note</small></div>
  <div class="ci-reliability-cell"><span>Pass rate</span><strong id="ci-rel-pass" class="$ci_rel_pass_class">$ci_rel_pass</strong><small id="ci-rel-outcomes">$ci_rel->{success} success · $ci_rel->{failed} failed</small></div>
  <div class="ci-reliability-cell"><span>Incidents</span><strong id="ci-rel-incidents" class="$ci_rel_incident_class">$ci_rel->{active_incidents} / $ci_rel->{resolved_incidents}</strong><small>active / resolved</small></div>
  <div class="ci-reliability-cell"><span>Mean recovery</span><strong id="ci-rel-mttr">@{[$ci_rel->{resolved_incidents}?duration_text($ci_rel->{mttr_seconds}):'n/a']}</strong><small>failure to next green</small></div>
  <div class="ci-reliability-cell"><span>Runtime p95</span><strong id="ci-rel-p95">@{[$ci_rel->{p95_duration_seconds}?duration_text($ci_rel->{p95_duration_seconds}):'n/a']}</strong><small>completed runs</small></div>
  <div class="ci-reliability-cell"><span>Green streak</span><strong id="ci-rel-streak" class="@{[$ci_rel->{green_streak}?'ok':'off']}">$ci_rel->{green_streak}</strong><small>latest decisive runs</small></div>
 </div>
</section>

<div class="lower-grid"><section class="card list-panel"><div class="panel-title"><span>Top referrers</span><small>GitHub Traffic</small></div><div id="top-referrers">$initial_refs_html</div></section><section class="card list-panel"><div class="panel-title"><span>Popular content</span><small>GitHub Traffic</small></div><div id="top-paths">$initial_paths_html</div></section></div>

<section class="card full account-panel"><div class="panel-title"><span>$account_name · public project portfolio</span><small id="account-updated">$account_age</small></div>
 <div class="account-kpis">
  <div class="account-kpi"><span>Repositories</span><strong id="account-repositories">$account->{repositories}</strong></div>
  <div class="account-kpi"><span>Maintained</span><strong id="account-maintained" class="ok">$account->{maintained}</strong></div>
  <div class="account-kpi"><span>Active 30d</span><strong id="account-active">$account->{active_30d}</strong></div>
  <div class="account-kpi"><span>Stars</span><strong id="account-stars">$account->{stars}</strong></div>
  <div class="account-kpi"><span>Forks</span><strong id="account-forks">$account->{forks}</strong></div>
  <div class="account-kpi"><span>Stale &gt; $CFG{account_stale_days}d</span><strong id="account-stale" class="@{[$account->{stale}?'warn':'ok']}">$account->{stale}</strong></div>
 </div>
 <div class="lower-grid"><div><div class="panel-title"><span>Recently pushed</span><small>freshness</small></div><div id="account-recent">$account_recent_html</div></div><div><div class="panel-title"><span>Most starred</span><small>public signals</small></div><div id="account-starred">$account_starred_html</div></div></div>
 <div class="account-meta"><span id="account-hygiene">Missing: description $account->{missing_description} · license $account->{missing_license} · topics $account->{missing_topics} · archived $account->{archived} · forks $account->{forked}</span><span id="account-stars-delta" class="$account_star_class">$account_star_sign$account_star_delta vs $account_prev_label</span></div>
 <div class="panel-title" style="margin-top:10px"><span>Recent portfolio changes</span><small>silent audit · no broadcast</small></div><div id="account-changes">$account_changes_html</div>
</section>

<section class="card full" style="margin-bottom:8px"><div class="panel-title"><span>Delivery integrity</span><small>independent IRC target audit</small></div><div class="audit-summary" id="broadcast-targets">$broadcast_targets_html</div><div class="broadcast-recent" id="broadcast-recent">$broadcast_recent</div></section>
<section class="card full" style="margin-bottom:8px"><div class="panel-title"><span>Recent activity</span><small><span id="latest-source">$last_source</span> · <span id="latest-age">$last_age</span></small></div><div id="latest-text" class="value" style="font-size:14px;margin-bottom:8px">$le</div><div id="recent-activity">$history_html</div></section>

<details class="card full" style="margin-bottom:8px"><summary>Runtime diagnostics <span class="details-note">IRC · GitHub APIs · sources · state</span></summary><div class="ops-grid"><div class="card compact-card"><div class="label">IRC fan-out</div><div class="compact-lines" id="irc-pills">$irc_pills</div><div class="small" id="irc-detail">@{[scalar(@bt)]} delivery targets · one persistent queue</div></div><div class="card compact-card"><div class="label">GitHub</div><div class="compact-lines" id="github-pills">$gh_pills</div><div class="small" id="github-detail">$api_detail · $ci_detail</div></div><div class="card compact-card"><div class="label">Sources</div><div class="compact-lines" id="source-pills">$source_pills</div><div class="small" id="source-detail">$lh · RSS $rss_detail_txt</div></div><div class="card compact-card"><div class="label">Runtime</div><div class="compact-lines" id="runtime-pills">$sys_pills</div><div class="small" id="runtime-detail">$qdetail · $state_txt</div></div></div></details>
<details class="card full"><summary>Persistent counters <span class="details-note">technical diagnostics</span></summary><div class="stats"><div class="stat"><b>Webhook</b><span id="counter-webhook">$hook_stats</span></div><div class="stat"><b>GitHub events</b><span id="counter-events">$poll_stats</span></div><div class="stat"><b>GitHub Actions</b><span id="counter-actions">$actions_stats</span></div><div class="stat"><b>Broadcast</b><span id="counter-broadcast">enqueued $STATS{broadcast_enqueued} · complete $STATS{broadcast_completed} · attempts $STATS{broadcast_delivery_attempts} · failures $STATS{broadcast_delivery_failures}</span></div><div class="stat"><b>GitHub Traffic</b><span id="counter-traffic">cycles $STATS{traffic_cycles} · requests $STATS{traffic_requests} · 403 $STATS{traffic_forbidden} · errors $STATS{traffic_errors}</span></div><div class="stat"><b>$account_name portfolio</b><span id="counter-account">polls $STATS{account_polls} · pages $STATS{account_pages} · 304 $STATS{account_not_modified} · repositories observed $STATS{account_repos_seen} · changes $STATS{account_changes_detected} · errors $STATS{account_errors}</span></div><div class="stat"><b>Forum RSS</b><span id="counter-rss">$rss_stats</span></div></div></details>
<footer>$app · live dashboard · Exact GitHub totals use a rolling 14-day UTC window; daily curves retain up to @{[MAX_TRAFFIC_DAYS]} days. “Unique” means GitHub unique cloners/visitors, not IP addresses. Portfolio data is restricted to public repositories owned by $account_name. · <a href="?api=dashboard">dashboard JSON</a> · <a href="?api=ci">CI reliability JSON</a> · <a href="?api=broadcast">broadcast JSON</a> · <a href="?api=traffic">traffic JSON</a> · <a href="?api=account">account JSON</a></footer>
</main></body></html>
HTML
}
sub status_payload {
 my@targets=map{my$c=channel_config($_->{net},$_->{channel});{network=>$_->{net}{id},label=>$_->{net}{label},channel=>$_->{channel},transport=>$_->{net}{tls}?'tls':'tcp',joined=>$c&&$c->{joined}?1:0,join_error=>$c?clean($c->{join_error}||''):''}}enabled_targets();
 +{
  version=>VERSION,repo=>$CFG{repo},uptime=>uptime(),icon_mode=>$CFG{icon_mode},
  irc=>{
   epiknet=>(!$NET{epiknet}{enabled}?'off':$NET{epiknet}{up}?'online':'offline'),
   libera=>(!$NET{libera}{enabled}?'off':$NET{libera}{up}?'online':'offline'),
   undernet=>(!$NET{undernet}{enabled}?'off':$NET{undernet}{up}?'online':'offline'),
   targets=>\@targets,
   heartbeat=>{idle_ping_seconds=>$CFG{irc_idle_ping},pong_timeout_seconds=>$CFG{irc_pong_timeout},timeouts=>$STATS{irc_heartbeat_timeouts}},
  },
  webhook=>webhook_state(),webhook_detail=>{last_reject_reason=>$STATE{last_hook_reject_reason}||'',last_reject_at=>$STATE{last_hook_reject_at}||0,bad_signature=>$STATS{hook_bad_signature},missing_headers=>$STATS{hook_missing_headers},invalid_json=>$STATS{hook_bad_json},wrong_repo=>$STATS{hook_wrong_repo},read_rejected=>$STATS{hook_read_rejected}},
  github_api=>api_state(),github_actions=>actions_state(),ci_reliability=>ci_reliability_summary(),github_traffic=>{%{traffic_payload()},render_error=>$RUN{traffic_render_error}||''},github_account=>account_status_payload(),broadcast=>broadcast_payload(),
  current_ci_failures=>current_ci_failure_count(),current_ci_running=>current_ci_running_count(),current_ci_expected=>current_ci_expected_count(),current_ci_flaky=>current_ci_flaky_count(),auth=>auth_short(),rss=>rss_state(),
  health=>health_report(),http_listener=>{listening=>$RUN{listener}?1:0,started_at=>$RUN{http_listener_started}||0,error=>$RUN{http_listener_error}||'',bind=>$CFG{hook_bind},port=>$CFG{hook_port},last_at=>$RUN{http_last_at}||0,last_method=>$RUN{http_last_method}||'',last_path=>$RUN{http_last_path}||'',last_status=>$RUN{http_last_status}||0,root_post_alias=>$CFG{hook_root_alias}?1:0},state=>state_status(),ops_alerts=>{enabled=>$CFG{ops_alerts}?1:0,debounce_seconds=>$CFG{ops_debounce},degraded=>$STATS{ops_degraded_alerts},recovered=>$STATS{ops_recovery_alerts}},github_rate=>{remaining=>$RUN{rate_remaining},limit=>$RUN{rate_limit},reset=>$RUN{rate_reset},blocked_until=>$RUN{rate_block_until}||0,reason=>$RUN{rate_block_reason}||''},
  queue=>scalar(@{$STATE{pending}}),queue_detail=>queue_snapshot(),history_count=>scalar(@{$STATE{history}}),last_event_source=>$STATE{last_event_source}||'',last_event_at=>$STATE{last_event_at}||0,
  counters=>{
   webhook=>{received=>$STATS{hook_received},valid=>$STATS{hook_valid},sent=>$STATS{hook_sent},rejected=>$STATS{hook_invalid},bad_signature=>$STATS{hook_bad_signature},missing_headers=>$STATS{hook_missing_headers},invalid_json=>$STATS{hook_bad_json},wrong_repo=>$STATS{hook_wrong_repo},read_rejected=>$STATS{hook_read_rejected},disabled=>$STATS{hook_disabled_requests}},
   github_poll=>{runs=>$STATS{poll_runs},pages=>$STATS{poll_pages},gaps=>$STATS{poll_gap},new=>$STATS{poll_new},sent=>$STATS{poll_sent},not_modified=>$STATS{poll_not_modified},errors=>$STATS{poll_errors}},
   actions=>{polls=>$STATS{actions_polls},pages=>$STATS{actions_pages},gaps=>$STATS{actions_gap},new=>$STATS{actions_new},failures=>$STATS{actions_failures},recoveries=>$STATS{actions_recoveries},slow_alerts=>$STATS{actions_slow_alerts},missing_alerts=>$STATS{actions_missing_alerts},flaky_alerts=>$STATS{actions_flaky_alerts},expect_cleared=>$STATS{actions_expect_cleared},sent=>$STATS{actions_sent},enriched=>$STATS{actions_enriched},enrich_skipped=>$STATS{actions_enrich_skipped},not_modified=>$STATS{actions_not_modified},errors=>$STATS{actions_errors}},
   traffic=>{cycles=>$STATS{traffic_cycles},requests=>$STATS{traffic_requests},errors=>$STATS{traffic_errors},forbidden=>$STATS{traffic_forbidden}},
   account=>{polls=>$STATS{account_polls},pages=>$STATS{account_pages},not_modified=>$STATS{account_not_modified},errors=>$STATS{account_errors},repos_seen=>$STATS{account_repos_seen},changes_detected=>$STATS{account_changes_detected}},
   rss=>{polls=>$STATS{rss_polls},new=>$STATS{rss_new},sent=>$STATS{rss_sent},not_modified=>$STATS{rss_not_modified},unchanged=>$STATS{rss_unchanged},errors=>$STATS{rss_errors}},
   irc=>{epiknet_sent=>$STATS{irc_epiknet_sent},libera_sent=>$STATS{irc_libera_sent},undernet_sent=>$STATS{irc_undernet_sent},undernet_teuk_sent=>$STATS{irc_undernet_teuk_sent},undernet_miaw_sent=>$STATS{irc_undernet_miaw_sent},epiknet_reconnects=>$STATS{irc_epiknet_reconnects},libera_reconnects=>$STATS{irc_libera_reconnects},undernet_reconnects=>$STATS{irc_undernet_reconnects},heartbeat_pings=>$STATS{irc_heartbeat_pings},heartbeat_timeouts=>$STATS{irc_heartbeat_timeouts},join_retries=>$STATS{irc_join_retries},join_rejects=>$STATS{irc_join_rejects},command_throttled=>$STATS{command_throttled}},
   queue=>{dropped=>$STATS{queue_dropped},partial_dropped=>$STATS{queue_partial_dropped}},state=>{backups=>$STATS{state_backups},recoveries=>$STATS{state_recoveries},save_errors=>$STATS{state_save_errors}},ops=>{degraded=>$STATS{ops_degraded_alerts},recovered=>$STATS{ops_recovery_alerts}},rate_limit_hits=>$STATS{rate_limit_hits},
  },
  last_github_ok=>$RUN{last_api_ok}||0,last_actions_ok=>$STATE{last_actions_ok}||0,last_traffic_ok=>$STATE{last_traffic_ok}||0,last_account_ok=>$STATE{last_account_ok}||0,
  last_webhook_ok=>$STATE{last_hook_ok}||0,last_rss_ok=>$STATE{last_rss_ok}||0,
 };
}
sub prom_escape {
 my($s)=@_;$s//=q{};$s=clean($s);$s=~s/\\/\\\\/g;$s=~s/"/\\"/g;$s=~s/\n/\\n/g;$s;
}
sub prometheus_metrics {
 my$q=queue_snapshot();my$limited=github_rest_allowed()?0:1;my@out;my$tr=traffic_summary_data();my$aud=traffic_audience_summary();my$latest=traffic_latest_snapshot();my$hist=traffic_history_summary();my$acct=account_summary();
 push@out,'# HELP githubwatch_info IRC GitWatch build information';
 push@out,'# TYPE githubwatch_info gauge';
 push@out,'githubwatch_info{version="'.prom_escape(VERSION).'",repo="'.prom_escape($CFG{repo}).'",account="'.prom_escape($CFG{account}).'"} 1';
 push@out,'# TYPE githubwatch_uptime_seconds gauge';push@out,'githubwatch_uptime_seconds '.int(time-$RUN{started});
 push@out,'# TYPE githubwatch_http_listener_up gauge';push@out,'githubwatch_http_listener_up '.($RUN{listener}?1:0);
 push@out,'# TYPE githubwatch_irc_connected gauge';
 for my$n(enabled_nets()){push@out,'githubwatch_irc_connected{network="'.prom_escape($n->{id}).'"} '.($n->{up}?1:0)}
 push@out,'# TYPE githubwatch_irc_target_configured gauge';
 for my$t(enabled_targets()){push@out,'githubwatch_irc_target_configured{network="'.prom_escape($t->{net}{id}).'",channel="'.prom_escape($t->{channel}).'"} 1'}
 push@out,'# TYPE githubwatch_irc_target_joined gauge';
 for my$t(enabled_targets()){my$c=channel_config($t->{net},$t->{channel});push@out,'githubwatch_irc_target_joined{network="'.prom_escape($t->{net}{id}).'",channel="'.prom_escape($t->{channel}).'"} '.($c&&$c->{joined}?1:0)}
 push@out,'# TYPE githubwatch_queue_items gauge';push@out,'githubwatch_queue_items '.$q->{total};
 push@out,'# TYPE githubwatch_queue_pending gauge';
 for my$n(enabled_nets()){push@out,'githubwatch_queue_pending{network="'.prom_escape($n->{id}).'"} '.int($q->{$n->{id}}||0)}
 push@out,'# TYPE githubwatch_queue_target_pending gauge';
 for my$t(enabled_targets()){my$m=$t->{metric};push@out,'githubwatch_queue_target_pending{network="'.prom_escape($t->{net}{id}).'",channel="'.prom_escape($t->{channel}).'"} '.int($q->{$m}||0)}
 push@out,'# TYPE githubwatch_queue_oldest_seconds gauge';push@out,'githubwatch_queue_oldest_seconds '.($q->{oldest_at}?int(time-$q->{oldest_at}):0);
 push@out,'# TYPE githubwatch_queue_pending_oldest_seconds gauge';
 for my$n(enabled_nets()){my$k=$n->{id}.'_oldest_at';push@out,'githubwatch_queue_pending_oldest_seconds{network="'.prom_escape($n->{id}).'"} '.($q->{$k}?int(time-$q->{$k}):0)}
 push@out,'# TYPE githubwatch_queue_target_oldest_seconds gauge';
 for my$t(enabled_targets()){my$k=$t->{metric}.'_oldest_at';push@out,'githubwatch_queue_target_oldest_seconds{network="'.prom_escape($t->{net}{id}).'",channel="'.prom_escape($t->{channel}).'"} '.($q->{$k}?int(time-$q->{$k}):0)}
 push@out,'# TYPE githubwatch_broadcast_target_deliveries_total counter';
 push@out,'# TYPE githubwatch_broadcast_target_last_delivery_timestamp gauge';
 for my$t(enabled_targets()){
  my$d=$STATE{delivery_stats}{$t->{id}}; $d={}unless ref($d)eq'HASH';
  my$labels='{network="'.prom_escape($t->{net}{id}).'",channel="'.prom_escape($t->{channel}).'"}';
  push@out,'githubwatch_broadcast_target_deliveries_total'.$labels.' '.int($d->{sent}||0);
  push@out,'githubwatch_broadcast_target_last_delivery_timestamp'.$labels.' '.int($d->{last_at}||0);
 }
 push@out,'# TYPE githubwatch_ci_failures_current gauge';push@out,'githubwatch_ci_failures_current '.current_ci_failure_count();
 push@out,'# TYPE githubwatch_ci_running_current gauge';push@out,'githubwatch_ci_running_current '.current_ci_running_count();
 push@out,'# TYPE githubwatch_ci_expected_current gauge';push@out,'githubwatch_ci_expected_current '.current_ci_expected_count();
 push@out,'# TYPE githubwatch_ci_flaky_current gauge';push@out,'githubwatch_ci_flaky_current '.current_ci_flaky_count();
 my$rel=ci_reliability_summary();
 push@out,'# TYPE githubwatch_ci_runs_retained gauge';push@out,'githubwatch_ci_runs_retained '.scalar(@{$STATE{ci_run_history}});
 push@out,'# TYPE githubwatch_ci_reliability_window_runs gauge';push@out,'githubwatch_ci_reliability_window_runs '.int($rel->{runs}||0);
 push@out,'# TYPE githubwatch_ci_reliability_pass_ratio gauge';push@out,'githubwatch_ci_reliability_pass_ratio '.sprintf('%.6f',($rel->{pass_rate}||0)/100);
 push@out,'# TYPE githubwatch_ci_incidents_active gauge';push@out,'githubwatch_ci_incidents_active '.int($rel->{active_incidents}||0);
 push@out,'# TYPE githubwatch_ci_incidents_resolved gauge';push@out,'githubwatch_ci_incidents_resolved '.int($rel->{resolved_incidents}||0);
 push@out,'# TYPE githubwatch_ci_mttr_seconds gauge';push@out,'githubwatch_ci_mttr_seconds '.int($rel->{mttr_seconds}||0);
 push@out,'# TYPE githubwatch_ci_duration_p95_seconds gauge';push@out,'githubwatch_ci_duration_p95_seconds '.int($rel->{p95_duration_seconds}||0);
 push@out,'# TYPE githubwatch_ci_green_streak gauge';push@out,'githubwatch_ci_green_streak '.int($rel->{green_streak}||0);
 push@out,'# TYPE githubwatch_github_traffic_clones gauge';push@out,'githubwatch_github_traffic_clones '.int($tr->{clones}||0);
 push@out,'# TYPE githubwatch_github_traffic_clone_uniques gauge';push@out,'githubwatch_github_traffic_clone_uniques '.int($tr->{clone_uniques}||0);
 push@out,'# TYPE githubwatch_github_traffic_views gauge';push@out,'githubwatch_github_traffic_views '.int($tr->{views}||0);
 push@out,'# TYPE githubwatch_github_traffic_view_uniques gauge';push@out,'githubwatch_github_traffic_view_uniques '.int($tr->{view_uniques}||0);
 push@out,'# TYPE githubwatch_github_unique_cloners_14d gauge';push@out,'githubwatch_github_unique_cloners_14d '.int($tr->{clone_uniques}||0);
 push@out,'# TYPE githubwatch_github_unique_visitors_14d gauge';push@out,'githubwatch_github_unique_visitors_14d '.int($tr->{view_uniques}||0);
 push@out,'# TYPE githubwatch_github_unique_cloners_today gauge';push@out,'githubwatch_github_unique_cloners_today '.int($aud->{today_clone_uniques}||0);
 push@out,'# TYPE githubwatch_github_unique_visitors_today gauge';push@out,'githubwatch_github_unique_visitors_today '.int($aud->{today_view_uniques}||0);
 push@out,'# TYPE githubwatch_github_clones_per_unique_cloner gauge';push@out,'githubwatch_github_clones_per_unique_cloner '.sprintf('%.6f',$aud->{clones_per_unique}||0);
 push@out,'# TYPE githubwatch_github_views_per_unique_visitor gauge';push@out,'githubwatch_github_views_per_unique_visitor '.sprintf('%.6f',$aud->{views_per_unique}||0);
 push@out,'# TYPE githubwatch_github_clone_unique_ratio gauge';push@out,'githubwatch_github_clone_unique_ratio '.sprintf('%.6f',($aud->{clone_unique_rate}||0)/100);
 push@out,'# TYPE githubwatch_github_view_unique_ratio gauge';push@out,'githubwatch_github_view_unique_ratio '.sprintf('%.6f',($aud->{view_unique_rate}||0)/100);
 push@out,'# TYPE githubwatch_github_daily_unique_cloners_average gauge';push@out,'githubwatch_github_daily_unique_cloners_average '.sprintf('%.6f',$aud->{avg_daily_clone_uniques}||0);
 push@out,'# TYPE githubwatch_github_daily_unique_visitors_average gauge';push@out,'githubwatch_github_daily_unique_visitors_average '.sprintf('%.6f',$aud->{avg_daily_view_uniques}||0);
 push@out,'# TYPE githubwatch_github_latest_daily_clones gauge';push@out,'githubwatch_github_latest_daily_clones '.int($latest->{clones}||0);
 push@out,'# TYPE githubwatch_github_latest_daily_clone_uniques gauge';push@out,'githubwatch_github_latest_daily_clone_uniques '.int($latest->{clone_uniques}||0);
 push@out,'# TYPE githubwatch_github_latest_daily_views gauge';push@out,'githubwatch_github_latest_daily_views '.int($latest->{views}||0);
 push@out,'# TYPE githubwatch_github_latest_daily_view_uniques gauge';push@out,'githubwatch_github_latest_daily_view_uniques '.int($latest->{view_uniques}||0);
 push@out,'# TYPE githubwatch_github_latest_daily_partial gauge';push@out,'githubwatch_github_latest_daily_partial '.($latest->{partial}?1:0);
 push@out,'# TYPE githubwatch_github_traffic_history_days gauge';push@out,'githubwatch_github_traffic_history_days '.int($hist->{days}||0);
 push@out,'# TYPE githubwatch_github_traffic_last_ok_timestamp gauge';push@out,'githubwatch_github_traffic_last_ok_timestamp '.int($STATE{last_traffic_ok}||0);
 for my$m(qw(repositories maintained active_30d archived stale stars forks open_issues missing_description missing_license missing_topics)){
  push@out,'# TYPE githubwatch_github_account_'.$m.' gauge';push@out,'githubwatch_github_account_'.$m.' '.int($acct->{$m}||0);
 }
 push@out,'# TYPE githubwatch_github_account_last_ok_timestamp gauge';push@out,'githubwatch_github_account_last_ok_timestamp '.int($STATE{last_account_ok}||0);
 push@out,'# TYPE githubwatch_github_account_enabled gauge';push@out,'githubwatch_github_account_enabled '.($CFG{account_enabled}?1:0);
 push@out,'# TYPE githubwatch_github_account_changes_retained gauge';push@out,'githubwatch_github_account_changes_retained '.scalar(@{$STATE{account_changes}});
 push@out,'# TYPE githubwatch_github_account_repo_stars gauge';push@out,'# TYPE githubwatch_github_account_repo_forks gauge';push@out,'# TYPE githubwatch_github_account_repo_open_issues gauge';push@out,'# TYPE githubwatch_github_account_repo_last_push_timestamp gauge';
 for my$r(@{$STATE{account_repos}}){
  my$l='{account="'.prom_escape($CFG{account}).'",repo="'.prom_escape($r->{name}).'",language="'.prom_escape($r->{language}).'",archived="'.($r->{archived}?1:0).'",fork="'.($r->{fork}?1:0).'"}';
  push@out,'githubwatch_github_account_repo_stars'.$l.' '.int($r->{stars}||0);
  push@out,'githubwatch_github_account_repo_forks'.$l.' '.int($r->{forks}||0);
  push@out,'githubwatch_github_account_repo_open_issues'.$l.' '.int($r->{open_issues}||0);
  push@out,'githubwatch_github_account_repo_last_push_timestamp'.$l.' '.int(iso8601_epoch($r->{pushed_at}));
 }
 push@out,'# TYPE githubwatch_github_rest_limited gauge';push@out,'githubwatch_github_rest_limited '.$limited;
 my$ss=state_status();push@out,'# TYPE githubwatch_state_primary_valid gauge';push@out,'githubwatch_state_primary_valid '.($ss->{primary}eq'ok'?1:0);push@out,'# TYPE githubwatch_state_backup_valid gauge';push@out,'githubwatch_state_backup_valid '.($ss->{backup}eq'ok'?1:0);push@out,'# TYPE githubwatch_ops_alerts_enabled gauge';push@out,'githubwatch_ops_alerts_enabled '.($CFG{ops_alerts}?1:0);
 my@c=(
  ['githubwatch_http_requests_total',$STATS{http_requests}],['githubwatch_dashboard_api_requests_total',$STATS{dashboard_api_requests}],['githubwatch_dashboard_api_errors_total',$STATS{dashboard_api_errors}],['githubwatch_http_bad_requests_total',$STATS{http_bad_requests}],['githubwatch_http_chunked_requests_total',$STATS{http_chunked_requests}],['githubwatch_http_expect_continue_total',$STATS{http_expect_continue}],['githubwatch_webhook_root_alias_hits_total',$STATS{hook_root_alias_hits}],['githubwatch_webhook_received_total',$STATS{hook_received}],['githubwatch_webhook_valid_total',$STATS{hook_valid}],['githubwatch_webhook_rejected_total',$STATS{hook_invalid}],['githubwatch_webhook_bad_signature_total',$STATS{hook_bad_signature}],['githubwatch_webhook_missing_headers_total',$STATS{hook_missing_headers}],['githubwatch_webhook_invalid_json_total',$STATS{hook_bad_json}],['githubwatch_webhook_wrong_repo_total',$STATS{hook_wrong_repo}],['githubwatch_webhook_read_rejected_total',$STATS{hook_read_rejected}],
  ['githubwatch_events_polls_total',$STATS{poll_runs}],['githubwatch_events_errors_total',$STATS{poll_errors}],
  ['githubwatch_actions_polls_total',$STATS{actions_polls}],['githubwatch_actions_failures_total',$STATS{actions_failures}],['githubwatch_actions_recoveries_total',$STATS{actions_recoveries}],['githubwatch_actions_slow_alerts_total',$STATS{actions_slow_alerts}],['githubwatch_actions_missing_alerts_total',$STATS{actions_missing_alerts}],['githubwatch_actions_flaky_alerts_total',$STATS{actions_flaky_alerts}],['githubwatch_actions_errors_total',$STATS{actions_errors}],
  ['githubwatch_broadcast_enqueued_total',$STATS{broadcast_enqueued}],['githubwatch_broadcast_completed_total',$STATS{broadcast_completed}],['githubwatch_broadcast_delivery_attempts_total',$STATS{broadcast_delivery_attempts}],['githubwatch_broadcast_delivery_failures_total',$STATS{broadcast_delivery_failures}],
  ['githubwatch_traffic_cycles_total',$STATS{traffic_cycles}],['githubwatch_traffic_requests_total',$STATS{traffic_requests}],['githubwatch_traffic_errors_total',$STATS{traffic_errors}],['githubwatch_traffic_forbidden_total',$STATS{traffic_forbidden}],
  ['githubwatch_account_polls_total',$STATS{account_polls}],['githubwatch_account_pages_total',$STATS{account_pages}],['githubwatch_account_not_modified_total',$STATS{account_not_modified}],['githubwatch_account_errors_total',$STATS{account_errors}],['githubwatch_account_repositories_seen_total',$STATS{account_repos_seen}],['githubwatch_account_changes_detected_total',$STATS{account_changes_detected}],
  ['githubwatch_irc_heartbeat_pings_total',$STATS{irc_heartbeat_pings}],['githubwatch_irc_heartbeat_timeouts_total',$STATS{irc_heartbeat_timeouts}],['githubwatch_irc_join_retries_total',$STATS{irc_join_retries}],['githubwatch_irc_join_rejects_total',$STATS{irc_join_rejects}],['githubwatch_http_listener_starts_total',$STATS{http_listener_starts}],
  ['githubwatch_irc_undernet_sent_total',$STATS{irc_undernet_sent}],['githubwatch_irc_undernet_teuk_sent_total',$STATS{irc_undernet_teuk_sent}],['githubwatch_irc_undernet_miaw_sent_total',$STATS{irc_undernet_miaw_sent}],
  ['githubwatch_rss_polls_total',$STATS{rss_polls}],['githubwatch_rss_errors_total',$STATS{rss_errors}],['githubwatch_queue_dropped_total',$STATS{queue_dropped}],['githubwatch_state_backups_total',$STATS{state_backups}],['githubwatch_state_recoveries_total',$STATS{state_recoveries}],['githubwatch_state_save_errors_total',$STATS{state_save_errors}],['githubwatch_ops_degraded_alerts_total',$STATS{ops_degraded_alerts}],['githubwatch_ops_recovery_alerts_total',$STATS{ops_recovery_alerts}],['githubwatch_rate_limit_hits_total',$STATS{rate_limit_hits}],
 );
 for my$c(@c){push@out,'# TYPE '.$c->[0].' counter';push@out,$c->[0].' '.int($c->[1]||0)}
 join("\n",@out)."\n";
}
sub normalized_http_path {
 my($p)=@_;$p//=q{};$p=~s/[?#].*$//;$p=~s{/$}{} if length($p)>1;$p||'/';
}
sub http_url_decode {
 my($s)=@_;$s//=q{};$s=~tr/+/ /;$s=~s/%([0-9A-Fa-f]{2})/chr(hex($1))/ge;$s;
}
sub http_query_param {
 my($path,$want)=@_;return q{}unless defined$path&&$path=~/\?(.*?)(?:#.*)?$/;
 for my$p(split/[&;]/,$1){
  my($k,$v)=split/=/,$p,2;$k=http_url_decode($k);next unless$k eq$want;
  return http_url_decode($v//'');
 }
 q{};
}
sub dashboard_payload {
 my$s=status_payload();
 $s->{server_time}=int(time);
 $s->{last_event_text}=repair_activity_text($STATE{last_event_text}||'',$STATE{last_event_source});
 $s->{recent_activity}=[
  map{{source=>clean($_->{source}||'event'),at=>int($_->{at}||0),text=>repair_activity_text($_->{text}||'',$_->{source})}}
  recent_history($CFG{history_show})
 ];
 $s->{dashboard}={
  mode=>'component-poll',
  poll_seconds=>$CFG{dashboard_poll},
  hidden_poll_seconds=>$CFG{dashboard_hidden},
  timeout_seconds=>$CFG{dashboard_timeout},
  public_url=>$CFG{dashboard_public_url},
 };
 $s;
}

# ── Webhook HTTP ─────────────────────────────────────────────────────────────
sub cteq { my($a,$b)=@_;return 0 unless defined$a&&defined$b&&length$a==length$b;my@a=unpack'C*',$a;my@b=unpack'C*',$b;my$d=0;$d|=$a[$_]^$b[$_]for 0..$#a;!$d }
sub http_write_all {
 my($c,$bytes)=@_;return 0 unless$c;my$off=0;my$len=length($bytes);
 while($off<$len){
  my$n=syswrite($c,$bytes,$len-$off,$off);
  return 0 unless defined$n&&$n>0;$off+=$n;
 }
 1;
}
sub http_response {
 my($c,$code,$type,$body,$head_only,$body_is_bytes)=@_;
 my%r=(100=>'Continue',200=>'OK',202=>'Accepted',400=>'Bad Request',401=>'Unauthorized',404=>'Not Found',405=>'Method Not Allowed',411=>'Length Required',413=>'Payload Too Large',417=>'Expectation Failed',500=>'Internal Server Error',503=>'Service Unavailable');
 $body//=q{};my$b=$body_is_bytes?$body:encode('UTF-8',$body);
 my$h="HTTP/1.1 $code ".($r{$code}||'Status')."\r\n".
       "Content-Type: $type; charset=utf-8\r\n".
       "Content-Length: ".length($b)."\r\n".
       "Cache-Control: no-store\r\n".
       "X-Content-Type-Options: nosniff\r\n".
       "X-Frame-Options: DENY\r\n".
       "Referrer-Policy: no-referrer\r\n".
       "X-Robots-Tag: noindex, nofollow, noarchive\r\n".
       "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'\r\n".
       "Connection: close\r\n\r\n";
 $RUN{http_last_status}=$code if$code>=200;
 http_write_all($c,encode('UTF-8',$h)) or return 0;
 http_write_all($c,$b) unless$head_only;
 1;
}
sub http_continue {
 my($c)=@_;$STATS{http_expect_continue}++;
 http_write_all($c,"HTTP/1.1 100 Continue\r\n\r\n");
}
sub http_reply { my($c,$code,$body)=@_;$body//=q{};$body.="\n"unless$body=~/\n\z/;http_response($c,$code,'text/plain',$body,0) }

sub read_more_http {
 my($c,$bufref,$min)=@_;
 while(length($$bufref)<$min){
  my$x='';my$n=sysread($c,$x,8192);die"closed\n"unless defined$n&&$n>0;
  $$bufref.=$x;die"large\n"if length($$bufref)>$CFG{hook_max}+131072;
 }
 1;
}
sub read_http_line {
 my($c,$bufref)=@_;
 while(index($$bufref,"\r\n")<0){
  die"headers\n"if length($$bufref)>65536;
  my$x='';my$n=sysread($c,$x,8192);die"closed\n"unless defined$n&&$n>0;$$bufref.=$x;
 }
 my$pos=index($$bufref,"\r\n");my$line=substr($$bufref,0,$pos,'');substr($$bufref,0,2,'');$line;
}
sub decode_chunked_http_body {
 my($c,$bufref)=@_;my$body='';
 while(1){
  my$line=read_http_line($c,$bufref);$line=~s/;.*$//;
  die"chunk\n"unless$line=~/^[0-9A-Fa-f]+$/;my$size=hex($line);
  if($size==0){
   # Consume trailer headers until the empty line. GitHub does not currently
   # need them, but accepting them makes the parser proxy/RFC friendly.
   while(1){my$trailer=read_http_line($c,$bufref);last if$trailer eq''}
   last;
  }
  die"large\n"if length($body)+$size>$CFG{hook_max};
  read_more_http($c,$bufref,$size+2);
  $body.=substr($$bufref,0,$size,'');
  die"chunk\n"unless substr($$bufref,0,2,'') eq"\r\n";
 }
 $body;
}
sub read_http {
 my($c)=@_;my$buf='';local$SIG{ALRM}=sub{die"timeout\n"};alarm $CFG{http_read_timeout};
 while(index($buf,"\r\n\r\n")<0){
  die"headers\n"if length$buf>65536;
  my$x='';my$n=sysread($c,$x,8192);die"closed\n"unless defined$n&&$n>0;$buf.=$x
 }
 my($head,$body)=split(/\r\n\r\n/,$buf,2);$body//=q{};
 my@l=split(/\r\n/,$head);my($method,$path,$proto)=split(/\s+/,shift@l||'',3);
 die"request\n"unless$method&&$path&&$proto&&$proto=~m{^HTTP/1\.[01]$};
 $method=uc($method);
 my%h;
 for(@l){
  next if/^[ \t]/; # obsolete folded headers are ignored rather than trusted.
  if(/^([^:]+):\s*(.*)$/){my($k,$v)=(lc($1),$2);$h{$k}=exists$h{$k}?$h{$k}.','.$v:$v}
 }
 my$te=lc($h{'transfer-encoding'}||'');my$chunked=$te=~/(?:^|,)\s*chunked\s*(?:,|$)/?1:0;
 die"transfer\n"if$te ne''&&!$chunked;
 die"smuggle\n"if$chunked&&defined$h{'content-length'};

 my$expect=lc($h{expect}||'');
 if($expect ne''){
  die"expect\n"unless$expect eq'100-continue';
  http_continue($c) or die"continue\n";
 }

 if($chunked){
  $STATS{http_chunked_requests}++;$body=decode_chunked_http_body($c,\$body);
 }else{
  my$len=0;
  if(defined$h{'content-length'}){
   die"length\n"unless$h{'content-length'}=~/^\d+$/;$len=int$h{'content-length'};
  }elsif($method eq'POST'){
   die"length\n";
  }
  die"large\n"if$len>$CFG{hook_max};
  read_more_http($c,\$body,$len) if length($body)<$len;
  $body=substr($body,0,$len);
 }
 alarm 0;($method,$path,\%h,$body);
}
sub note_hook_reject {
 my($reason)=@_;$reason=clean($reason||'rejected');$STATE{last_hook_reject_reason}=$reason;$STATE{last_hook_reject_at}=int(time);
 my%map=(bad_signature=>'hook_bad_signature',missing_headers=>'hook_missing_headers',invalid_json=>'hook_bad_json',wrong_repository=>'hook_wrong_repo',read_rejected=>'hook_read_rejected',disabled=>'hook_disabled_requests');
 my$k=$map{$reason};$STATS{$k}++ if$k&&exists$STATS{$k};1;
}
sub hook_reject {
 my($c,$code,$reason,$body)=@_;$STATS{hook_invalid}++ unless$reason eq'disabled';note_hook_reject($reason);http_reply($c,$code,$body||'rejected');0;
}
sub handle_hook {
 my($c)=@_;my($m,$path,$h,$body);
 my$ok=eval{($m,$path,$h,$body)=read_http($c);1};alarm 0;
 if(!$ok){my$e=$@;$STATS{http_bad_requests}++;note_hook_reject('read_rejected');my$code=$e=~/large/?413:$e=~/length/?411:$e=~/expect/?417:400;http_reply($c,$code,'rejected');return}

 my$want=normalized_http_path($CFG{hook_path});
 my$got =normalized_http_path($path);
 my$api=http_query_param($path,'api');my$asset=http_query_param($path,'asset');
 $STATS{http_requests}++;
 my$is_dashboard_poll=($m eq'GET'||$m eq'HEAD')&&($got eq'/'||$got eq$want)&&($api eq'dashboard'||$asset eq'dashboard-js');
 unless($is_dashboard_poll){$RUN{http_last_at}=time;$RUN{http_last_method}=$m;$RUN{http_last_path}=clean($got)}

 # Same-path assets and JSON mean one Apache ProxyPass for the webhook path is enough.
 if(($m eq'GET'||$m eq'HEAD')&&($got eq'/'||$got eq$want)&&$asset eq'dashboard-js'){
  http_response($c,200,'application/javascript',dashboard_js(),$m eq'HEAD');return;
 }
 if(($m eq'GET'||$m eq'HEAD')&&($got eq'/'||$got eq$want)&&$api ne''){
  if($api eq'dashboard'){
   $STATS{dashboard_api_requests}++;
   my$json=eval{encode_json(dashboard_payload())};
   if(!defined($json)||$@){$STATS{dashboard_api_errors}++;http_reply($c,500,'dashboard API error');return}
   http_response($c,200,'application/json',$json,$m eq'HEAD',1);return;
  }
  if($api eq'broadcast'){http_response($c,200,'application/json',encode_json(broadcast_payload()),$m eq'HEAD',1);return}
  if($api eq'traffic'){http_response($c,200,'application/json',encode_json(traffic_payload()),$m eq'HEAD',1);return}
  if($api eq'account'){http_response($c,200,'application/json',encode_json(account_payload()),$m eq'HEAD',1);return}
  if($api eq'ci'){http_response($c,200,'application/json',encode_json(ci_reliability_payload()),$m eq'HEAD',1);return}
  http_reply($c,404,'unknown dashboard API');return;
 }

 # Progressive HTML shell. POST on the same path remains the HMAC webhook.
 if(($m eq'GET'||$m eq'HEAD')&&($got eq'/'||$got eq$want)){
  http_response($c,200,'text/html',dashboard_html(),$m eq'HEAD');
  return;
 }
 if(($m eq'GET'||$m eq'HEAD')&&$got eq'/status.json'){
  http_response($c,200,'application/json',encode_json(status_payload()),$m eq'HEAD',1);
  return;
 }
 if(($m eq'GET'||$m eq'HEAD')&&$got eq'/dashboard.json'){
  $STATS{dashboard_api_requests}++;
  my$json=eval{encode_json(dashboard_payload())};
  if(!defined($json)||$@){$STATS{dashboard_api_errors}++;http_reply($c,500,'dashboard API error');return}
  http_response($c,200,'application/json',$json,$m eq'HEAD',1);return;
 }
 if(($m eq'GET'||$m eq'HEAD')&&$got eq'/livez'){
  http_response($c,200,'text/plain',"OK\n",$m eq'HEAD');return;
 }
 if(($m eq'GET'||$m eq'HEAD')&&$got eq'/readyz'){
  my$h=health_report();my($code,$body)=$h->{status}eq'ok'?(200,"READY\n"):(503,"NOT READY: ".join("; ",@{$h->{issues}})."\n");
  http_response($c,$code,'text/plain',$body,$m eq'HEAD');return;
 }
 if(($m eq'GET'||$m eq'HEAD')&&$got eq'/healthz'){
  my$h=health_report();
  my($code,$body);
  if($h->{status} eq 'ok'){($code,$body)=(200,"OK\n")}
  else{($code,$body)=(503,"DEGRADED: ".join("; ",@{$h->{issues}})."\n")}
  http_response($c,$code,'text/plain',$body,$m eq'HEAD');
  return;
 }
 if(($m eq'GET'||$m eq'HEAD')&&$got eq'/broadcast.json'){
  http_response($c,200,'application/json',encode_json(broadcast_payload()),$m eq'HEAD',1);return;
 }
 if(($m eq'GET'||$m eq'HEAD')&&$got eq'/traffic.json'){
  http_response($c,200,'application/json',encode_json(traffic_payload()),$m eq'HEAD',1);return;
 }
 if(($m eq'GET'||$m eq'HEAD')&&$got eq'/account.json'){
  http_response($c,200,'application/json',encode_json(account_payload()),$m eq'HEAD',1);return;
 }
 if(($m eq'GET'||$m eq'HEAD')&&$got eq'/ci.json'){
  http_response($c,200,'application/json',encode_json(ci_reliability_payload()),$m eq'HEAD',1);return;
 }
 if(($m eq'GET'||$m eq'HEAD')&&$got eq'/metrics'){
  return http_reply($c,404,'not found') unless$CFG{metrics_enabled};
  http_response($c,200,'text/plain; version=0.0.4',prometheus_metrics(),$m eq'HEAD');
  return;
 }

 return http_reply($c,405,'POST only') if$m ne'POST';
 my$hook_route=($got eq$want)||($CFG{hook_root_alias}&&$got eq'/');
 return http_reply($c,404,'not found') unless$hook_route;
 $STATS{hook_root_alias_hits}++ if$got eq'/'&&$want ne'/';

 $STATS{hook_received}++;
 if($CFG{hook_secret}eq''){hook_reject($c,401,'disabled','webhook disabled');return}

 my$expected='sha256='.hmac_sha256_hex($body,$CFG{hook_secret});
 if(!cteq($h->{'x-hub-signature-256'}||'',$expected)){
  hook_reject($c,401,'bad_signature','bad signature');return
 }

 my$event=clean($h->{'x-github-event'}||'');
 my$delivery=clean($h->{'x-github-delivery'}||'');
 if(!$event||!$delivery){hook_reject($c,400,'missing_headers','missing headers');return}
 if($STATE{deliveries}{$delivery}){$STATS{hook_dupe}++;http_reply($c,200,'duplicate');return}

 my$p=eval{decode_json($body)};
 if(!$p||ref$p ne'HASH'){hook_reject($c,400,'invalid_json','invalid JSON');return}
 my$pr=$p->{repository}{full_name};
 if($event ne'ping'&&defined$pr&&$pr ne$CFG{repo}){hook_reject($c,401,'wrong_repository','wrong repository');return}

 $STATS{hook_valid}++;$STATE{last_hook_ok}=time;$STATE{last_hook_event}=$event;$STATE{deliveries}{$delivery}=time;
 if($event eq'ping'){save_state();http_reply($c,200,'pong');return}
 if(!public_event($event)){$STATS{hook_suppressed}++;save_state();http_reply($c,202,'accepted but hidden');return}

 my$n=normalize_hook($event,$p);kick_actions()if($n->{kind}||'')eq'push';
 if(($n->{kind}||'')eq'ci'){
  update_running_ci_event($n,1);
  my$recovered=ci_track_state($n);track_ci_flap($n,1);$STATS{actions_recoveries}++ if$recovered;kick_actions()
 }
 my$f=fingerprint($n);
 if($STATE{fingerprints}{$f}){$STATS{hook_dupe}++;save_state();http_reply($c,200,'already seen');return}
 expect_ci_for_push($n)if($n->{kind}||'')eq'push';
 $STATE{fingerprints}{$f}=time;
 if(!webhook_event_should_announce($n)){$STATS{hook_suppressed}++;save_state();http_reply($c,202,'accepted but not announced');return}
 enqueue(format_event($n),'hook');http_reply($c,202,'queued');
}
sub start_hook {
 my($quiet)=@_;return 1 if$RUN{listener};
 my$l=IO::Socket::INET->new(LocalAddr=>$CFG{hook_bind},LocalPort=>$CFG{hook_port},Proto=>'tcp',Listen=>16,ReuseAddr=>1);
 if(!$l){$RUN{http_listener_error}=clean($!||'bind failed');logmsg('ERROR',"HTTP listener bind failed on $CFG{hook_bind}:$CFG{hook_port}: $RUN{http_listener_error}");return 0}
 $l->autoflush(1);$RUN{listener}=$l;$RUN{http_listener_started}=time;$RUN{http_listener_error}='';$STATS{http_listener_starts}++;
 logmsg('INFO',"HTTP listener ready on http://$CFG{hook_bind}:$CFG{hook_port}/ — webhook POST ".($CFG{hook_secret}ne''?'enabled':'disabled')) unless$quiet;
 1;
}
sub drop_http_listener {
 my($why)=@_;logmsg('WARN',"HTTP listener reset: $why")if$why;
 eval{close$RUN{listener}if$RUN{listener}};$RUN{listener}=undef;$RUN{http_listener_error}=clean($why||'listener reset');$RUN{next_http_retry}=time+2;
}
sub ensure_http_listener {
 return 1 if$RUN{listener};return 0 if time<($RUN{next_http_retry}||0);
 my$ok=start_hook();$RUN{next_http_retry}=time+5 unless$ok;$ok;
}

# ── Reconciliation / lifecycle ───────────────────────────────────────────────
sub maintenance_once {
 my($fresh,$actions_fresh,$rss_fresh)=@_;my$now=time;

 # Local non-blocking timers run before HTTP maintenance.
 return 1 if check_missing_ci();
 return 1 if check_ops_alerts();

 # CI alerts take priority over catch-up. Enrichment gets one REST turn when
 # possible; if GitHub is rate-limited, the base failure is flushed immediately
 # instead of being held until the rate-limit window ends.
 return process_ci_enrichment() if @{$STATE{ci_enrich_pending}};

 # Multi-page catch-up is itself serialized: one page = one loop turn.
 return continue_events_scan($fresh) if$RUN{events_scan}&&github_rest_allowed();
 return continue_actions_scan($actions_fresh) if$RUN{actions_scan}&&github_rest_allowed();
 return continue_account_scan() if$RUN{account_scan}&&github_rest_allowed();

 my@jobs;
 push@jobs,[$RUN{next_poll},'events'] if$CFG{poll_enabled}&&github_rest_allowed();
 push@jobs,[$RUN{actions_next},'actions'] if$CFG{actions_enabled}&&github_rest_allowed();
 push@jobs,[$RUN{traffic_next},'traffic'] if$CFG{traffic_enabled}&&$CFG{token}ne''&&github_rest_allowed();
 push@jobs,[$RUN{account_next},'account'] if$CFG{account_enabled}&&github_rest_allowed();
 push@jobs,[$RUN{rss_next},'rss'] if$CFG{rss_enabled};
 return 0 unless@jobs;
 @jobs=sort{$a->[0]<=>$b->[0]}@jobs;
 return 0 if$jobs[0][0]>$now;

 my$job=$jobs[0][1];
 return reconcile($fresh) if$job eq'events';
 return reconcile_actions($actions_fresh) if$job eq'actions';
 return reconcile_traffic() if$job eq'traffic';
 return reconcile_account() if$job eq'account';
 return reconcile_rss($rss_fresh) if$job eq'rss';
 0;
}
sub reconnect_one {
 my$now=time;my@due=sort{$a->{next_reconnect}<=>$b->{next_reconnect}}
  grep{$_->{enabled}&&!$_->{up}&&$now>=$_->{next_reconnect}}@NETS;
 return 0 unless@due;
 my$net=$due[0];
 if(irc_connect($net)){startup_announce($net)}else{schedule_reconnect($net)}
 1;
}

sub graceful_shutdown { my($sig)=@_;return if$RUN{stopping};$RUN{stopping}=1;logmsg('INFO',"Shutdown requested by $sig");save_state();irc_raw($_,'QUIT :IRC GitWatch shutting down') for online_nets() }
$SIG{TERM}=sub{graceful_shutdown('SIGTERM')};$SIG{INT}=sub{graceful_shutdown('SIGINT')};

# ── Built-in tests / CLI ─────────────────────────────────────────────────────
sub selftest_names {
 grep{length}split/\n/,<<'SELFTEST_NAMES';
security.webhook.hmac-sha256
security.constant-time-compare
events.fingerprint.webhook-poll-equivalence
events.fingerprint.sha-difference
events.public-event-filter
irc.control-code-cleaning
events.push-zero-commit-format
utf8.encoded-byte-length
config.default-profile-valid
dashboard.shell-contract
security.dashboard-token-redacted
security.dashboard-secret-redacted
http.trailing-slash-normalization
rss.rss2-item-count
rss.rss2-cdata-title
rss.rss2-entity-decoding
rss.rss2-author-category
rss.rss2-link
rss.identity-stability
rss.atom-title
rss.atom-link
rss.irc-format
rss.dashboard-section
utf8.xml-decoding
utf8.windows1252-mojibake-repair
utf8.latin1-mojibake-repair
utf8.lossy-poll-repair
utf8.lossy-rss-repair
utf8.damaged-poll-repair
utf8.damaged-rss-repair
utf8.non-event-text-preserved
irc.plain-text-control-stripping
irc.compat-icons
irc.compat-content
irc.ascii-icons
irc.emoji-icons
security.bidi-control-removal
rss.identity-ignores-title-edit
dashboard.activity-control-stripping
dashboard.legacy-activity-healing
security.sha256-determinism
ci.failed-run-normalization
ci.webhook-poll-fingerprint
ci.failed-run-format
ci.success-announcement-policy
delivery.all-targets-complete
delivery.partial-target-detection
ci.recovery-state-transition
ci.recovery-announcement-policy
irc.sasl-short-frame
irc.sasl-long-frame-chunking
irc.reconnect-backoff
github.retry-after-rate-limit
github.pagination-next-link
ci.scope-key
ci.failure-registration
ci.failure-recovery-clear
state.atomic-save-mode-0600
state.v11-schema
health.report-contract
github.secondary-rate-limit-backoff
github.success-resets-rate-streak
github.expired-rate-limit-clear
queue.bounded-drop-accounting
ci.enrichment-rate-limit-fallback
scheduler.disabled-jobs-idle
history.recent-order-and-cleaning
time.iso8601-and-duration
ci.running-run-registration
ci.running-run-completion
ci.slow-run-format
ci.expected-run-registration
ci.expected-run-clear
ci.seen-sha-prevents-expectation
ci.missing-run-alert
ci.duration-and-attempt-format
ci.missing-run-format
irc.disabled-heartbeat-idle
ci.flaky-transition-detection
ci.flaky-run-format
webhook.rejection-accounting
queue.snapshot-contract
metrics.prometheus-contract-and-redaction
state.atomic-raw-write
state.document-read
state.backup-creation
state.status-primary-and-backup
ops.degraded-and-recovered-format
irc.undernet-two-channel-model
delivery.epiknet-target-id
delivery.undernet-target-id-uniqueness
irc.keyed-join-command
security.channel-key-redaction
traffic.summary-aggregates
traffic.daily-row-order
traffic.history-merge
traffic.history-retention
traffic.latest-snapshot
traffic.period-comparison
traffic.unique-peak-summary
traffic.github-unique-semantics
traffic.top-referrer-order
traffic.api-payload-contract
traffic.dashboard-latest-snapshot
traffic.irc-snapshot-command
irc.undernet-key-default
irc.channel-down-transition
irc.channel-join-transition
http.listener-without-webhook-secret
account.public-repository-normalization
account.private-and-foreign-filter
account.portfolio-summary
account.quality-and-trend-summary
account.change-detection
account.history-payload-contract
account.json-utf8-roundtrip
account.dashboard-contract
account.prometheus-contract
account.irc-command-contract
ci.reliability-pass-ratio
ci.reliability-recovery-summary
ci.reliability-duration-and-streak
ci.reliability-payload-retention
ci.history-deduplication
ci.reliability-dashboard-contract
ci.reliability-javascript-contract
ci.reliability-prometheus-contract
ci.reliability-status-contract
ci.reliability-irc-command-contract
ci.reliability-active-incident
dashboard.long-range-html-contract
dashboard.long-range-javascript-contract
dashboard.unique-audience-chart
dashboard.no-raw-ip-label
dashboard.audience-kpi-strip
dashboard.unique-audience-javascript
traffic.audience-trend-payload
dashboard.live-layout-contract
dashboard.component-poll-contract
dashboard.polling-javascript-contract
dashboard.chart-range-and-tooltip
traffic.audience-field-contract
traffic.trend-public-url-contract
http.query-parameter-parser
dashboard.api-payload-contract
delivery.four-target-enqueue
delivery.four-target-completion
delivery.epiknet-wire-format
delivery.libera-wire-format
delivery.undernet-wire-format
traffic.best-day-selection
traffic.dashboard-render-regression
http.sigpipe-ignored
http.root-alias-normalization
http.chunked-body-decoding
http.json-utf8-single-encoding
http.text-utf8-encoding
status.api-contract
SELFTEST_NAMES
}
sub active_selftest_names {
 my@names=selftest_names();
 push@names,'security.status-hook-secret-redacted'if$CFG{hook_secret}ne'';
 push@names,'security.status-token-redacted'if$CFG{token}ne'';
 @names;
}
sub selftest {
 my@t;
 push@t,hmac_sha256_hex('Hello, World!',q{It's a Secret to Everybody})eq'757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17';
 push@t,cteq('abc','abc')&&!cteq('abc','abd');
 my$wh=normalize_hook('push',{sender=>{login=>'octocat'},pusher=>{name=>'Different'},repository=>{full_name=>$CFG{repo}},ref=>'refs/heads/master',after=>'abc123',size=>1,commits=>[{id=>'abc123',message=>'hello'}],head_commit=>{id=>'abc123',message=>'hello'}});
 my$po=normalize_poll({type=>'PushEvent',actor=>{login=>'octocat'},repo=>{name=>$CFG{repo}},payload=>{ref=>'refs/heads/master',head=>'abc123',size=>1,commits=>[{sha=>'abc123',message=>'hello'}]}});
 my%other=%$wh;$other{sha}='different';push@t,fingerprint($wh)eq fingerprint($po);push@t,fingerprint($wh)ne fingerprint(\%other);push@t,public_event('push')&&!public_event('secret_scanning_alert');
 push@t,clean("hello\x03".'04evil' . "\x02")eq'hello 04evil';push@t,format_event({kind=>'push',repo=>$CFG{repo},actor=>'teuk',ref=>'master',sha=>'abc123',count=>0,url=>'https://x'})!~/0 commits/;push@t,length(encode('UTF-8','ANONYMOUS — UTF-8 ✓'))>length('ANONYMOUS — UTF-8 ✓');push@t,!config_errors();
 my$html=dashboard_html();push@t,!!($html=~/<title>IRC GitWatch/&&$html=~/<main>/);
 push@t,$CFG{token}eq''||index($html,$CFG{token})<0;
 push@t,$CFG{hook_secret}eq''||index($html,$CFG{hook_secret})<0;
 push@t,normalized_http_path('/githubhook/') eq normalized_http_path('/githubhook');

 my$rss_sample=q{<?xml version="1.0"?><rss version="2.0"><channel>
 <item><title><![CDATA[Hello & <friends>]]></title><link>https://teuk.org/forum/t/999</link><guid>topic-999</guid><pubDate>Sat, 08 Aug 2026 12:00:00 GMT</pubDate><category>Mediabot</category><dc:creator>TeuK</dc:creator></item>
 <item><title>Second &amp; safe</title><link>https://teuk.org/forum/t/998</link><guid>topic-998</guid></item>
 </channel></rss>};
 my$rp=parse_rss($rss_sample);
 push@t,ref($rp)eq'ARRAY'&&@$rp==2;
 push@t,$rp->[0]{title}eq'Hello & <friends>';
 push@t,$rp->[1]{title}eq'Second & safe';
 push@t,$rp->[0]{author}eq'TeuK'&&$rp->[0]{category}eq'Mediabot';
 push@t,$rp->[0]{link}eq'https://teuk.org/forum/t/999';
 push@t,rss_item_id($rp->[0])eq rss_item_id($rp->[0]);

 my$atom=q{<feed><entry><title>Atom title</title><id>urn:1</id><updated>2026-08-08T12:00:00Z</updated><author><name>TeuK</name></author><link href="https://teuk.org/forum/t/1"/></entry></feed>};
 my$ap=parse_rss($atom);
 push@t,ref($ap)eq'ARRAY'&&@$ap==1&&$ap->[0]{title}eq'Atom title';
 push@t,$ap->[0]{link}eq'https://teuk.org/forum/t/1';
 push@t,!!(format_rss($rp->[0])=~/Forum/&&format_rss($rp->[0])=~m{/t/999});
 push@t,index(dashboard_html(),'Forum RSS')>=0;

 my$utf8_original="📰 MB683 à Keep the Security Scroll";
 my$utf8_bytes=encode('UTF-8',$utf8_original);
 push@t,decode_xml_bytes($utf8_bytes,'application/rss+xml; charset=utf-8')eq$utf8_original;
 my$moji=decode('Windows-1252',$utf8_bytes);
 push@t,repair_mojibake($moji)eq$utf8_original;
 my$latin1_original="↑ GitHub: teuk updated master — https://example.test/commit/abc";
 my$latin1_moji=decode('ISO-8859-1',encode('UTF-8',$latin1_original));
 push@t,repair_mojibake($latin1_moji)eq$latin1_original;
 push@t,repair_activity_text('â GitHub: teuk updated master @ c592159 â https://example.test/commit/abc','poll')eq'↑ GitHub: teuk updated master @ c592159 — https://example.test/commit/abc';
 push@t,repair_activity_text('â Forum: MB709 â Lumos Maxima Stage â" by TeuK in Mediabot â https://example.test/t/281','rss')eq'◆ Forum: MB709 — Lumos Maxima Stage — by TeuK in Mediabot — https://example.test/t/281';
 my$damaged_poll='â'.chr(0x86).' GitHub: teuk updated master @ c592159 â'.chr(0x80).' https://example.test/commit/abc';
 my$damaged_rss='â'.chr(0x97).' Forum: MB709 â'.chr(0x80).' Lumos Maxima Stage â'.chr(0x94).'" by TeuK in Mediabot â'.chr(0x80).' https://example.test/t/281';
 push@t,repair_activity_text($damaged_poll,'poll')eq'↑ GitHub: teuk updated master @ c592159 — https://example.test/commit/abc';
 push@t,repair_activity_text($damaged_rss,'rss')eq'◆ Forum: MB709 — Lumos Maxima Stage — by TeuK in Mediabot — https://example.test/t/281';
 push@t,repair_activity_text('note â conserver','poll')eq'note â conserver';
 push@t,plain_irc("\x0311Forum\x0f : \x0310Title\x0f")eq'Forum : Title';

 my$old_mode=$CFG{icon_mode};
 $CFG{icon_mode}='compat';push@t,icon('forum')eq'◆'&&icon('health')eq'✓';
 push@t,irc_content("🛡️ MB683 à Keep")eq'MB683 à Keep';
 $CFG{icon_mode}='ascii';push@t,icon('forum')eq'F'&&icon('github')eq'*';
 $CFG{icon_mode}='emoji';push@t,length(icon('forum'))>=1;
 $CFG{icon_mode}=$old_mode;

 push@t,clean("safe\x{202e}evil")eq'safeevil';

 my%edited=%{$rp->[0]};$edited{title}='Edited title';
 push@t,rss_item_id($rp->[0])eq rss_item_id(\%edited);

 my$old_last=$STATE{last_event_text};my$old_src=$STATE{last_event_source};my$old_at=$STATE{last_event_at};
 $STATE{last_event_text}="\x0311Forum\x0f : \x0310Clean\x0f — https://example.test/x";$STATE{last_event_source}='rss';$STATE{last_event_at}=time-60;
 my$dh=dashboard_html();push@t,$dh=~/Forum : Clean/&&$dh!~/11Forum/&&$dh!~/10Clean/&&$dh=~/<a href="https:\/\/example\.test\/x"/;
 $STATE{last_event_text}='◆ Forum: ðŸ›¡, Broken — https://teuk.org/forum/t/999';$STATE{last_event_source}='legacy';$STATE{last_event_at}=0;
 push@t,heal_legacy_latest_from_rss($rp,1)&&$STATE{last_event_source}eq'rss'&&$STATE{last_event_text}=~/Hello/;
 $STATE{last_event_text}=$old_last;$STATE{last_event_source}=$old_src;$STATE{last_event_at}=$old_at;

 push@t,sha256_hex('same')eq sha256_hex('same')&&sha256_hex('same')ne sha256_hex('different');

 my$ci_api=normalize_action_run({
  id=>4242,run_attempt=>2,status=>'completed',conclusion=>'failure',name=>'debian13',
  display_title=>'MB test',head_branch=>'master',head_sha=>'abcdef0123456789',
  actor=>{login=>'teuk'},event=>'push',html_url=>'https://github.com/x/actions/runs/4242',
 });
 my$ci_hook=normalize_hook('workflow_run',{
  action=>'completed',sender=>{login=>'teuk'},repository=>{full_name=>$CFG{repo}},
  workflow_run=>{id=>4242,run_attempt=>2,conclusion=>'failure',name=>'debian13',
   display_title=>'MB test',head_branch=>'master',head_sha=>'abcdef0123456789',
   event=>'push',html_url=>'https://github.com/x/actions/runs/4242'},
 });
 push@t,$ci_api->{kind}eq'ci'&&ci_bad($ci_api->{conclusion})&&ci_should_announce($ci_api);
 push@t,fingerprint($ci_api)eq fingerprint($ci_hook);
 push@t,format_event($ci_api)=~/CI/&&format_event($ci_api)=~/FAILURE/;
 my$ci_ok={%$ci_api,conclusion=>'success'};push@t,!$CFG{actions_fail_only}||!ci_should_announce($ci_ok);

 my@targets=enabled_targets();my$item={delivered=>{map{($_->{id}=>1)}@targets}};
 push@t,all_networks_delivered($item);
 if(@targets>1){my$item2={delivered=>{%{$item->{delivered}}}};delete$item2->{delivered}{$targets[-1]{id}};push@t,!all_networks_delivered($item2)}else{push@t,1}

 my$badci={%$ci_api};ci_track_state($badci);
 my$goodci={%$ci_api,conclusion=>'success',id=>4243};push@t,ci_track_state($goodci)&&$goodci->{recovery};
 push@t,!$CFG{actions_recovery}||ci_should_announce($goodci);

 my@short_sasl=sasl_plain_lines('user','pass');push@t,@short_sasl==1&&length($short_sasl[0])<=400;
 my@long_sasl=sasl_plain_lines('u'x250,'p'x250);push@t,@long_sasl>=2&&!grep{length($_)>400}@long_sasl;

 my$tn={id=>'test',reconnect_delay=>10,next_reconnect=>0};schedule_reconnect($tn);
 push@t,$tn->{next_reconnect}>time&&$tn->{reconnect_delay}==20;

 my($old_block,$old_reason,$old_rem,$old_reset)=@RUN{qw(rate_block_until rate_block_reason rate_remaining rate_reset)};
 my$fake={status=>429,headers=>{'retry-after'=>'5','x-ratelimit-remaining'=>'0','x-ratelimit-reset'=>int(time)+60}};
 push@t,note_rate_limit($fake,'selftest',1)>=5&&!github_rest_allowed();
 @RUN{qw(rate_block_until rate_block_reason rate_remaining rate_reset)}=($old_block,$old_reason,$old_rem,$old_reset);

 my$nl=next_link({headers=>{link=>'<https://api.github.test/page=2>; rel="next", <https://api.github.test/page=3>; rel="last"'}});
 push@t,$nl eq'https://api.github.test/page=2';

 my$wid={%$ci_api,workflow_id=>12345,ref=>'master'};
 push@t,ci_scope_key($wid)=~/^id:12345\x1fmaster$/;
 my$old_bad={%{$STATE{ci_bad_state}}};$STATE{ci_bad_state}={};
 ci_track_state($wid);push@t,current_ci_failure_count()==1&&(current_ci_failures())[0]{name} ne'';
 my$wid_ok={%$wid,conclusion=>'success',id=>99999};ci_track_state($wid_ok);push@t,current_ci_failure_count()==0;
 $STATE{ci_bad_state}=$old_bad;

 my$old_state_file=$CFG{state_file};my$tmp_state="/tmp/githubwatch-selftest-$$.json";$CFG{state_file}=$tmp_state;
 unlink$tmp_state;push@t,save_state()&&-f$tmp_state&&sprintf('%04o',(stat($tmp_state))[2]&07777)eq'0600';my($saved_doc)=read_state_document($tmp_state);push@t,$saved_doc&&$saved_doc->{state_version}==11&&ref($saved_doc->{traffic_history})eq'HASH'&&ref($saved_doc->{account_history})eq'HASH'&&ref($saved_doc->{account_changes})eq'ARRAY';unlink$tmp_state;$CFG{state_file}=$old_state_file;

 my$hr=health_report();push@t,ref($hr)eq'HASH'&&($hr->{status}eq'ok'||$hr->{status}eq'degraded')&&ref($hr->{issues})eq'ARRAY';

 my($old_rl_until,$old_rl_reason,$old_rl_streak)=@RUN{qw(rate_block_until rate_block_reason rate_secondary_streak)};
 my$old_hits=$STATS{rate_limit_hits};my$fake429={status=>429,headers=>{},content=>'{"message":"You have exceeded a secondary rate limit"}'};
 push@t,note_rate_limit($fake429,'selftest',1)>=60&&$RUN{rate_block_until}>time;
 note_github_success({status=>200,headers=>{}});push@t,$RUN{rate_secondary_streak}==0;
 $RUN{rate_block_until}=time-1;$RUN{rate_block_reason}='old';push@t,github_rest_allowed()&&$RUN{rate_block_reason}eq'';
 @RUN{qw(rate_block_until rate_block_reason rate_secondary_streak)}=($old_rl_until,$old_rl_reason,$old_rl_streak);$STATS{rate_limit_hits}=$old_hits;

 my$old_pending=[@{$STATE{pending}}];my($old_drop,$old_partial)=@STATS{qw(queue_dropped queue_partial_dropped)};
 $STATE{pending}=[map{{text=>"q$_",source=>'test',created=>time,delivered=>($_==0?{epiknet=>time}:{}),counted=>0}}0..MAX_PENDING-1];
 drop_queue_for_space();push@t,@{$STATE{pending}}==MAX_PENDING-1&&$STATS{queue_dropped}==$old_drop+1&&$STATS{queue_partial_dropped}==$old_partial+1;
 $STATE{pending}=$old_pending;@STATS{qw(queue_dropped queue_partial_dropped)}=($old_drop,$old_partial);

 my$old_enrich=[@{$STATE{ci_enrich_pending}}];my$old_skip=$STATS{actions_enrich_skipped};my$old_block_until=$RUN{rate_block_until};my$old_sf=$CFG{state_file};
 my$self_sf="/tmp/githubwatch-enrich-selftest-$$.json";$CFG{state_file}=$self_sf;unlink$self_sf;
 $STATE{ci_enrich_pending}=[{event=>{%$ci_api},created=>time}];$RUN{rate_block_until}=time+60;
 push@t,flush_ci_enrichment_pending()&&@{$STATE{ci_enrich_pending}}==0&&$STATS{actions_enrich_skipped}==$old_skip+1;
 @{$STATE{pending}}=grep{($_->{source}||'') ne'actions'}@{$STATE{pending}};
 unlink$self_sf;$CFG{state_file}=$old_sf;$STATE{ci_enrich_pending}=$old_enrich;$STATS{actions_enrich_skipped}=$old_skip;$RUN{rate_block_until}=$old_block_until;

 my($old_poll_enabled,$old_actions_enabled,$old_rss_enabled,$old_traffic_enabled,$old_account_enabled)=@CFG{qw(poll_enabled actions_enabled rss_enabled traffic_enabled account_enabled)};
 @CFG{qw(poll_enabled actions_enabled rss_enabled traffic_enabled account_enabled)}=(0,0,0,0,0);push@t,maintenance_once(\my$f0,\my$a0,\my$r0)==0;
 @CFG{qw(poll_enabled actions_enabled rss_enabled traffic_enabled account_enabled)}=($old_poll_enabled,$old_actions_enabled,$old_rss_enabled,$old_traffic_enabled,$old_account_enabled);

 my$old_history=[map{{%$_}}@{$STATE{history}}];$STATE{history}=[];
 record_history("\x0311Hello\x0f world",'test',time-10);record_history('Second','rss',time);
 my@recent=recent_history(2);push@t,@recent==2&&$recent[0]{text}eq'Second'&&$recent[1]{text}eq'Hello world';
 $STATE{history}=$old_history;

 push@t,iso8601_epoch('2026-08-23T10:00:00Z')>0&&duration_text(3661)eq'1h 1m';

 my$old_running={%{$STATE{ci_running}}};my$old_slow_seen={%{$STATE{ci_slow_seen}}};my$old_slow_cfg=$CFG{actions_slow};
 $STATE{ci_running}={};$STATE{ci_slow_seen}={};$CFG{actions_slow}=0;
 my$run_raw={id=>777,status=>'in_progress',name=>'long-test',head_branch=>'master',head_sha=>'deadbeef',workflow_id=>88,run_attempt=>1,
  run_started_at=>'2026-08-23T10:00:00Z',html_url=>'https://github.com/x/actions/runs/777',actor=>{login=>'teuk'}};
 push@t,refresh_running_ci([$run_raw],0)&&current_ci_running_count()==1&&(current_ci_running())[0]{name}eq'long-test';
 my$done_raw={%$run_raw,status=>'completed',conclusion=>'success'};push@t,refresh_running_ci([$done_raw],0)&&current_ci_running_count()==0;
 $STATE{ci_running}=$old_running;$STATE{ci_slow_seen}=$old_slow_seen;$CFG{actions_slow}=$old_slow_cfg;

 push@t,format_event({kind=>'ci_slow',repo=>$CFG{repo},id=>9,attempt=>1,title=>'slow-test',ref=>'master',started_at=>time-3700,url=>'https://x'})=~/CI SLOW/;

 my$old_expect=$CFG{actions_expect};my$old_expected={%{$STATE{ci_expected}}};my$old_miss=$STATS{actions_missing_alerts};my$old_clear=$STATS{actions_expect_cleared};
 $CFG{actions_expect}=300;$STATE{ci_expected}={};
 my$pushx={kind=>'push',sha=>'abcdef1234567890',ref=>'master',actor=>'teuk',url=>'https://github.com/x/commit/abcdef1234567890'};
 push@t,expect_ci_for_push($pushx)&&current_ci_expected_count()==1;
 push@t,clear_ci_expectation('abcdef1234567890')&&current_ci_expected_count()==0;
 my$old_seen_sha={%{$STATE{ci_sha_seen}}};$STATE{ci_sha_seen}={};note_ci_sha_seen('abcdef1234567890');push@t,!expect_ci_for_push($pushx);$STATE{ci_sha_seen}={};
 expect_ci_for_push($pushx);$STATE{ci_expected}{'abcdef1234567890'}{at}=int(time)-301;
 my$old_pending_n=scalar@{$STATE{pending}};my$old_expect_sf=$CFG{state_file};my$expect_sf="/tmp/githubwatch-expect-selftest-$$.json";$CFG{state_file}=$expect_sf;unlink$expect_sf;
 push@t,check_missing_ci()&&$STATE{ci_expected}{'abcdef1234567890'}{alerted};
 splice@{$STATE{pending}},$old_pending_n if@{$STATE{pending}}>$old_pending_n;unlink$expect_sf;$CFG{state_file}=$old_expect_sf;
 $STATE{ci_expected}=$old_expected;$STATE{ci_sha_seen}=$old_seen_sha;$CFG{actions_expect}=$old_expect;$STATS{actions_missing_alerts}=$old_miss;$STATS{actions_expect_cleared}=$old_clear;

 my$durci=format_event({kind=>'ci',title=>'test-ci',conclusion=>'failure',ref=>'master',sha=>'abcdef123',attempt=>2,started_at=>100,completed_at=>165,url=>'https://x'});
 my$durci_plain=plain_irc($durci);push@t,!!($durci_plain=~/attempt 2/&&$durci_plain=~/\x{2014} 1m \x{2014}/);
 push@t,format_event({kind=>'ci_missing',sha=>'abcdef123',ref=>'master',started_at=>time-301,url=>'https://x'})=~/CI MISSING/;
 my$old_ping_cfg=$CFG{irc_idle_ping};$CFG{irc_idle_ping}=0;push@t,heartbeat_once()==0;$CFG{irc_idle_ping}=$old_ping_cfg;

 my$old_flaky_win=$CFG{actions_flaky_window};my$old_flaky_n=$CFG{actions_flaky_transitions};my$old_flap={%{$STATE{ci_flap_state}}};my$old_flaky_alerts=$STATS{actions_flaky_alerts};my$old_fp={%{$STATE{fingerprints}}};my$old_q_flap=[@{$STATE{pending}}];
 $CFG{actions_flaky_window}=600;$CFG{actions_flaky_transitions}=2;$STATE{ci_flap_state}={};
 my$f1={%$ci_api,workflow_id=>987,ref=>'master',conclusion=>'failure',id=>1001};my$f2={%$f1,conclusion=>'success',id=>1002};my$f3={%$f1,conclusion=>'failure',id=>1003};
 push@t,!track_ci_flap($f1,1)&&!track_ci_flap($f2,1)&&track_ci_flap($f3,1)&&current_ci_flaky_count()==1;
 push@t,format_event({kind=>'ci_flaky',title=>'test-ci',ref=>'master',transitions=>3,window=>600,url=>'https://x'})=~/CI FLAKY/;
 $CFG{actions_flaky_window}=$old_flaky_win;$CFG{actions_flaky_transitions}=$old_flaky_n;$STATE{ci_flap_state}=$old_flap;$STATS{actions_flaky_alerts}=$old_flaky_alerts;$STATE{fingerprints}=$old_fp;$STATE{pending}=$old_q_flap;

 my($old_rej_reason,$old_rej_at)=@STATE{qw(last_hook_reject_reason last_hook_reject_at)};my($old_invalid,$old_sig)=@STATS{qw(hook_invalid hook_bad_signature)};
 note_hook_reject('bad_signature');push@t,$STATE{last_hook_reject_reason}eq'bad_signature'&&$STATE{last_hook_reject_at}>0&&$STATS{hook_bad_signature}==$old_sig+1;
 @STATE{qw(last_hook_reject_reason last_hook_reject_at)}=($old_rej_reason,$old_rej_at);@STATS{qw(hook_invalid hook_bad_signature)}=($old_invalid,$old_sig);

 my$qcheck=queue_snapshot();push@t,ref($qcheck)eq'HASH'&&exists$qcheck->{total}&&exists$qcheck->{oldest_at}&&!(grep{!exists$qcheck->{$_->{id}}||!exists$qcheck->{$_->{id}.'_oldest_at'}}enabled_nets());
 my$pm=prometheus_metrics();push@t,$pm=~/githubwatch_info/&&$pm=~/githubwatch_ci_running_current/&&$pm=~/githubwatch_ci_expected_current/&&$pm=~/githubwatch_ci_flaky_current/&&$pm=~/githubwatch_webhook_bad_signature_total/&&$pm=~/githubwatch_queue_pending_oldest_seconds/&&$pm=~/githubwatch_irc_heartbeat_pings_total/&&$pm=~/githubwatch_github_latest_daily_clones/&&$pm=~/githubwatch_github_traffic_history_days/&&$pm!~/GITHUB_TOKEN/;

 my$old_state_sf=$CFG{state_file};my$old_sb=$CFG{state_backup};my$sf="/tmp/githubwatch-state-v018-selftest-$$.json";$CFG{state_file}=$sf;$CFG{state_backup}=1;unlink$sf;unlink"$sf.bak";
 my($wok,$werr)=write_raw_atomic_0600($sf,encode_json({state_version=>6,saved_at=>123,foo=>'bar'}));push@t,$wok;
 my($rd,undef,$rerr)=read_state_document($sf);push@t,$rd&&$rd->{foo}eq'bar'&&$rerr eq'';
 push@t,backup_current_state()&&-f"$sf.bak";my$ssx=state_status();push@t,$ssx->{primary}eq'ok'&&$ssx->{backup}eq'ok';
 unlink$sf;unlink"$sf.bak";$CFG{state_file}=$old_state_sf;$CFG{state_backup}=$old_sb;
 my$oph={status=>'degraded',issues=>['Libera offline']};push@t,ops_health_key($oph)=~/Libera offline/&&format_ops_alert('degraded',$oph)=~/DEGRADED/&&format_ops_alert('recovered',{status=>'ok',issues=>[]})=~/RECOVERED/;

 # v0.20 multi-network/multi-channel delivery invariants.
 push@t,$NET{undernet}&&scalar(net_channels($NET{undernet}))==2;
 push@t,delivery_target_id($NET{epiknet},$CFG{irc_channel})eq'epiknet';
 my@uc=net_channels($NET{undernet});push@t,delivery_target_id($NET{undernet},$uc[0]{name})ne delivery_target_id($NET{undernet},$uc[1]{name});
 my$sentinel='SELFTEST_CHANNEL_KEY_DO_NOT_EXPOSE';
 my$old_ukey=$NET{undernet}{channels}[0]{key};$NET{undernet}{channels}[0]{key}=$sentinel;
 push@t,join_command($NET{undernet},$NET{undernet}{channels}[0])=~/\Q$sentinel\E/;
 my$secret_surfaces=dashboard_html().encode_json(status_payload()).prometheus_metrics();
 push@t,index($secret_surfaces,$sentinel)<0;
 $NET{undernet}{channels}[0]{key}=$old_ukey;

 # v0.20 traffic calculations modeled on GitHub's 14-day traffic data.
 my$old_tc={%{$STATE{traffic_clones}}};my$old_tv={%{$STATE{traffic_views}}};my$old_th={map{($_=>{%{$STATE{traffic_history}{$_}}})}keys%{$STATE{traffic_history}}};
 my$old_tr=[map{{%$_}}@{$STATE{traffic_referrers}}];my$old_tp=[map{{%$_}}@{$STATE{traffic_paths}}];my$old_tat=$STATE{last_traffic_ok};
 $STATE{traffic_clones}={count=>12,uniques=>5,clones=>[
  {timestamp=>'2026-08-26T00:00:00Z',count=>4,uniques=>2},
  {timestamp=>'2026-08-27T00:00:00Z',count=>8,uniques=>3},
 ]};
 $STATE{traffic_views}={count=>30,uniques=>11,views=>[
  {timestamp=>'2026-08-26T00:00:00Z',count=>10,uniques=>4},
  {timestamp=>'2026-08-27T00:00:00Z',count=>20,uniques=>7},
 ]};
 $STATE{traffic_referrers}=[{referrer=>'small.test',count=>2,uniques=>1},{referrer=>'example.test',count=>9,uniques=>4}];
 $STATE{traffic_paths}=[{path=>'/' . $CFG{repo},title=>'repo',count=>12,uniques=>6}];
 $STATE{last_traffic_ok}=time;
 my$ts=traffic_summary_data();push@t,$ts->{clones}==12&&$ts->{clone_uniques}==5&&$ts->{views}==30&&$ts->{view_uniques}==11&&int($ts->{avg_clones})==6&&$ts->{avg_clone_uniques}==2.5&&$ts->{avg_view_uniques}==5.5;
 my@td=traffic_daily_rows();push@t,@td==2&&$td[1]{clones}==8&&$td[1]{views}==20;
 push@t,traffic_merge_history()==2&&scalar(keys%{$STATE{traffic_history}})==2;
 $STATE{traffic_history}{'2026-01-01'}={date=>'2026-01-01',clones=>3,clone_uniques=>1,views=>5,view_uniques=>2};
 my@long_td=traffic_daily_rows();my$ths=traffic_history_summary();push@t,@long_td==3&&$long_td[0]{date}eq'2026-01-01'&&$ths->{days}==3&&$ths->{retention_days}==MAX_TRAFFIC_DAYS;
 my$latest28=traffic_latest_snapshot();push@t,$latest28->{date}eq'2026-08-27'&&$latest28->{clones}==8&&$latest28->{clone_uniques}==3&&$latest28->{clone_delta}==4;
 my$pc=traffic_period_comparison(1);push@t,$pc->{current}{clones}==8&&$pc->{previous}{clones}==4&&$pc->{changes}{clones}{delta}==4;
 my$pk=traffic_peak_summary();push@t,$pk->{clone_uniques}{clone_uniques}==3&&$pk->{view_uniques}{view_uniques}==7;
 my$ta=traffic_audience_summary();push@t,$ta->{raw_ip_addresses_available}==0&&$ta->{unique_metric}eq'github_aggregated_unique'&&$ta->{clones_per_unique}>2;
 my@tt=traffic_top('referrers');push@t,@tt==2&&$tt[0]{referrer}eq'example.test'&&$tt[1]{referrer}eq'small.test';
 my$tpayload=traffic_payload();push@t,ref($tpayload)eq'HASH'&&ref($tpayload->{daily})eq'ARRAY'&&ref($tpayload->{audience})eq'HASH'&&ref($tpayload->{latest})eq'HASH'&&ref($tpayload->{history})eq'HASH'&&$tpayload->{history}{days}==3&&$tpayload->{semantics}{raw_ip_addresses_available}==0&&($CFG{token}eq''||index(encode_json($tpayload),$CFG{token})<0);
 my$snapshot_html=dashboard_html();push@t,$snapshot_html=~/id="toolbar-latest-traffic">8 clones · 3 unique/&&$snapshot_html=~/id="pulse-today">8 clones · 3 unique/;
 my$snapshot_wire='';open my$snapshot_fh,'>',\$snapshot_wire or die"snapshot selftest: $!";binmode$snapshot_fh,':raw';my$snapshot_net={id=>'snapshot-test',label=>'Snapshot test',up=>1,socket=>$snapshot_fh,nick=>'githubwatch'};my$old_cooldown=$CFG{cmd_cooldown};$CFG{cmd_cooldown}=0;command($snapshot_net,'tester','#test','!github snapshot');$CFG{cmd_cooldown}=$old_cooldown;close$snapshot_fh;my$snapshot_text=decode('UTF-8',$snapshot_wire);push@t,$snapshot_text=~/Latest GitHub traffic/&&$snapshot_text=~/clones .*8.*3 unique/s&&$snapshot_text=~/Since previous day/;
 $STATE{traffic_clones}=$old_tc;$STATE{traffic_views}=$old_tv;$STATE{traffic_history}=$old_th;$STATE{traffic_referrers}=$old_tr;$STATE{traffic_paths}=$old_tp;$STATE{last_traffic_ok}=$old_tat;

 # v0.20.1 regression tests: Undernet key fallback, partial membership,
 # and an HTTP listener that stays alive even when webhook POST is disabled.
 push@t,defined$CFG{undernet_teuk_key};
 my($old_joined0,$old_err0,$old_next0)=@{$NET{undernet}{channels}[0]}{qw(joined join_error next_join)};
 mark_channel_down($NET{undernet},$NET{undernet}{channels}[0]{name},'selftest');push@t,!$NET{undernet}{channels}[0]{joined}&&$NET{undernet}{channels}[0]{next_join}>time;
 push@t,mark_channel_joined($NET{undernet},$NET{undernet}{channels}[0]{name})&&$NET{undernet}{channels}[0]{joined};
 @{$NET{undernet}{channels}[0]}{qw(joined join_error next_join)}=($old_joined0,$old_err0,$old_next0);

 my($old_hbind,$old_hport,$old_hsecret)=@CFG{qw(hook_bind hook_port hook_secret)};my$old_listener=$RUN{listener};my$old_hstarts=$STATS{http_listener_starts};
 $CFG{hook_bind}='127.0.0.1';$CFG{hook_port}=0;$CFG{hook_secret}='';$RUN{listener}=undef;
 push@t,start_hook(1)&&$RUN{listener}&&eval{$RUN{listener}->sockport}>0;
 close$RUN{listener} if$RUN{listener};$RUN{listener}=$old_listener;@CFG{qw(hook_bind hook_port hook_secret)}=($old_hbind,$old_hport,$old_hsecret);$STATS{http_listener_starts}=$old_hstarts;

 # v0.29 public account portfolio: strict owner/privacy boundary, deterministic
 # analytics and read-only exposure across dashboard, JSON, IRC and metrics.
 my$owner=$CFG{account};
 my$good_repo=account_normalize_repo({id=>1,name=>'alpha',full_name=>$owner.'/alpha',owner=>{login=>$owner},private=>0,html_url=>'javascript:bad',description=>'Alpha ↑ — Perl',language=>'Perl',default_branch=>'main',archived=>0,disabled=>0,fork=>0,stargazers_count=>5,forks_count=>2,open_issues_count=>3,size=>10,created_at=>'2020-01-01T00:00:00Z',updated_at=>'2099-01-01T00:00:00Z',pushed_at=>'2099-01-01T00:00:00Z',license=>{spdx_id=>'MIT'},topics=>['bot','github']});
 my$stale_repo=account_normalize_repo({id=>2,name=>'old',full_name=>$owner.'/old',owner=>{login=>$owner},private=>0,description=>'',language=>'Perl',archived=>0,disabled=>0,fork=>0,stargazers_count=>1,forks_count=>0,open_issues_count=>0,pushed_at=>'2000-01-01T00:00:00Z',topics=>[]});
 my$archived_repo=account_normalize_repo({id=>3,name=>'archive',full_name=>$owner.'/archive',owner=>{login=>$owner},private=>0,description=>'Archive',archived=>1,disabled=>0,fork=>0,stargazers_count=>2,forks_count=>1,open_issues_count=>0,pushed_at=>'2001-01-01T00:00:00Z',license=>{spdx_id=>'GPL-3.0'},topics=>['archive']});
 push@t,$good_repo&&$good_repo->{html_url}eq'https://github.com/'.$owner.'/alpha'&&$good_repo->{stars}==5&&@{$good_repo->{topics}}==2;
 push@t,!account_normalize_repo({name=>'private',full_name=>$owner.'/private',owner=>{login=>$owner},private=>1})&&!account_normalize_repo({name=>'foreign',full_name=>'other/foreign',owner=>{login=>'other'},private=>0});
 my($old_ar,$old_ah,$old_ac,$old_aok,$old_ae,$old_aerr,$old_astale)=($STATE{account_repos},$STATE{account_history},$STATE{account_changes},$STATE{last_account_ok},$CFG{account_enabled},$RUN{account_error},$CFG{account_stale_days});
 $CFG{account_enabled}=1;$CFG{account_stale_days}=180;$RUN{account_error}='';$STATE{account_repos}=[$good_repo,$stale_repo,$archived_repo];$STATE{account_changes}=[];$STATE{last_account_ok}=time;
 $STATE{account_history}={utc_date(time-86400)=>{date=>utc_date(time-86400),repositories=>2,maintained=>2,active_30d=>0,archived=>0,stale=>1,stars=>6,forks=>2,open_issues=>2}};
 my$as=account_summary();push@t,$as->{repositories}==3&&$as->{maintained}==2&&$as->{active_30d}==1&&$as->{archived}==1&&$as->{stale}==1&&$as->{stars}==8&&$as->{forks}==3&&$as->{open_issues}==3;
 push@t,$as->{missing_description}==1&&$as->{missing_license}==1&&$as->{missing_topics}==1&&$as->{trend}{stars}{delta}==2&&$as->{most_starred}[0]{name}eq'alpha'&&$as->{recently_pushed}[0]{name}eq'alpha';
 my$changed_repo={%$good_repo,stars=>7,pushed_at=>'2099-02-01T00:00:00Z'};my$detected=account_record_changes([$changed_repo,$stale_repo]);my$change_rows=account_change_rows();push@t,$detected==3&&@$change_rows==3&&scalar(grep{$_->{kind}eq'stars'&&$_->{text}=~/5.*7/}@$change_rows)&&scalar(grep{$_->{kind}eq'removed'&&$_->{repo}eq$owner.'/archive'}@$change_rows);
 account_record_history();my$account_payload_test=account_payload();push@t,$account_payload_test->{scope}eq'public owner repositories only'&&ref($account_payload_test->{repos})eq'ARRAY'&&ref($account_payload_test->{history})eq'ARRAY'&&ref($account_payload_test->{history_summary})eq'HASH'&&ref($account_payload_test->{changes})eq'ARRAY'&&$account_payload_test->{history_summary}{retention_days}==MAX_ACCOUNT_DAYS&&$account_payload_test->{repos}[0]{full_name}=~m{^\Q$owner\E/}i;
 my$account_json_roundtrip=decode_json(encode_json($account_payload_test));push@t,$account_json_roundtrip->{repos}[0]{description}eq'Alpha ↑ — Perl';
 my$account_dash=dashboard_html();my$account_js=dashboard_js();push@t,index($account_dash,$owner.' · public project portfolio')>=0&&$account_dash=~/id="account-repositories"/&&$account_dash=~/\?api=account/&&$account_js=~/function renderAccount\(d\)/&&$account_js=~/github_account/;
 my$account_metrics=prometheus_metrics();push@t,$account_metrics=~/githubwatch_github_account_repositories 3/&&$account_metrics=~/githubwatch_github_account_repo_stars\{[^\n]*repo="alpha"[^\n]*\} 5/;
 my$account_wire='';open my$account_fh,'>',\$account_wire or die"account selftest: $!";binmode$account_fh,':raw';my$account_net={id=>'account-test',label=>'Account test',up=>1,socket=>$account_fh,nick=>'gitwatch'};my$account_cd=$CFG{cmd_cooldown};$CFG{cmd_cooldown}=0;command($account_net,'tester','#test','!github portfolio');command($account_net,'tester','#test','!github project alpha');command($account_net,'tester','#test','!github changes');$CFG{cmd_cooldown}=$account_cd;close$account_fh;my$account_text=decode('UTF-8',$account_wire);push@t,$account_text=~/public portfolio/&&index($account_text,$owner.'/alpha')>=0&&index($account_text,'https://github.com/'.$owner.'/alpha')>=0&&$account_text=~/portfolio changes/;
 ($STATE{account_repos},$STATE{account_history},$STATE{account_changes},$STATE{last_account_ok},$CFG{account_enabled},$RUN{account_error},$CFG{account_stale_days})=($old_ar,$old_ah,$old_ac,$old_aok,$old_ae,$old_aerr,$old_astale);

 # v0.30 retains a bounded Actions history and derives deterministic SRE-style
 # reliability, recovery and runtime signals without another GitHub API call.
 my($old_ci_history,$old_ci_bad,$old_ci_actions_enabled)=($STATE{ci_run_history},$STATE{ci_bad_state},$CFG{actions_enabled});
 my$ci_now=int(time);$CFG{actions_enabled}=1;$STATE{ci_bad_state}={};
 my$build_scope="id:101\x1fmain";my$lint_scope="id:202\x1fmain";my$ci_url='https://github.com/'.$CFG{repo}.'/actions/runs/';
 $STATE{ci_run_history}=[
  normalize_ci_history_entry({id=>1,workflow_id=>101,scope=>$build_scope,name=>'Build',branch=>'main',conclusion=>'failure',at=>$ci_now-1000,duration=>100,url=>$ci_url.'1'}),
  normalize_ci_history_entry({id=>2,workflow_id=>101,scope=>$build_scope,name=>'Build',branch=>'main',conclusion=>'failure',at=>$ci_now-800,duration=>120,url=>$ci_url.'2'}),
  normalize_ci_history_entry({id=>3,workflow_id=>101,scope=>$build_scope,name=>'Build',branch=>'main',conclusion=>'success',at=>$ci_now-400,duration=>90,url=>$ci_url.'3'}),
  normalize_ci_history_entry({id=>4,workflow_id=>202,scope=>$lint_scope,name=>'Lint',branch=>'main',conclusion=>'success',at=>$ci_now-300,duration=>30,url=>$ci_url.'4'}),
  normalize_ci_history_entry({id=>5,workflow_id=>101,scope=>$build_scope,name=>'Build',branch=>'main',conclusion=>'success',at=>$ci_now-200,duration=>80,url=>$ci_url.'5'}),
 ];
 my$rel30=ci_reliability_summary($ci_now);
 push@t,$rel30->{state}eq'watch'&&$rel30->{runs}==5&&$rel30->{decisive_runs}==5&&$rel30->{success}==3&&$rel30->{failed}==2&&$rel30->{pass_rate}==60;
 push@t,$rel30->{resolved_incidents}==1&&$rel30->{active_incidents}==0&&$rel30->{mttr_seconds}==600&&$rel30->{longest_recovery_seconds}==600;
 push@t,$rel30->{p50_duration_seconds}==90&&$rel30->{p95_duration_seconds}==120&&$rel30->{green_streak}==3&&$rel30->{resolved}[0]{failures}==2;
 my$rel_payload=ci_reliability_payload();push@t,$rel_payload->{retained_runs}==5&&$rel_payload->{retention}{days}==MAX_CI_DAYS&&$rel_payload->{retention}{max_runs}==MAX_CI_RUNS&&ref($rel_payload->{recent})eq'ARRAY';
 my@ci_done=gmtime($ci_now-10);my@ci_started=gmtime($ci_now-70);
 my$ci_done_iso=sprintf('%04d-%02d-%02dT%02d:%02d:%02dZ',$ci_done[5]+1900,$ci_done[4]+1,$ci_done[3],$ci_done[2],$ci_done[1],$ci_done[0]);
 my$ci_started_iso=sprintf('%04d-%02d-%02dT%02d:%02d:%02dZ',$ci_started[5]+1900,$ci_started[4]+1,$ci_started[3],$ci_started[2],$ci_started[1],$ci_started[0]);
 $STATE{ci_run_history}=[];my$raw_ci_run={id=>99,run_attempt=>2,workflow_id=>303,status=>'completed',conclusion=>'success',name=>'Release',head_branch=>'main',head_sha=>'abc123',run_started_at=>$ci_started_iso,updated_at=>$ci_done_iso,html_url=>$ci_url.'99',actor=>{login=>$owner}};
 push@t,record_ci_run_history([$raw_ci_run])==1&&record_ci_run_history([$raw_ci_run])==0&&@{$STATE{ci_run_history}}==1&&$STATE{ci_run_history}[0]{duration}==60&&$STATE{ci_run_history}[0]{attempt}==2;
 $STATE{ci_run_history}=[map{{%$_}}grep{defined}(@{$rel30->{recent}})];$STATE{ci_run_history}=[reverse@{$STATE{ci_run_history}}];
 my$ci_dash=dashboard_html();my$ci_js=dashboard_js();push@t,$ci_dash=~/CI reliability/&&$ci_dash=~/id="ci-rel-pass"/&&$ci_dash=~/id="ci-rel-incidents"/&&$ci_dash=~/\?api=ci/;
 push@t,$ci_js=~/function renderReliability\(d\)/&&$ci_js=~/ci_reliability/&&$ci_js=~/ci-rel-streak/&&$ci_js=~/const duration=/;
 my$ci_metrics=prometheus_metrics();push@t,$ci_metrics=~/githubwatch_ci_reliability_pass_ratio 0\.600000/&&$ci_metrics=~/githubwatch_ci_mttr_seconds 600/&&$ci_metrics=~/githubwatch_ci_duration_p95_seconds 120/;
 my$ci_status=status_payload();push@t,ref($ci_status->{ci_reliability})eq'HASH'&&$ci_status->{ci_reliability}{resolved_incidents}==1;
 my$ci_wire='';open my$ci_fh,'>',\$ci_wire or die"CI reliability selftest: $!";binmode$ci_fh,':raw';my$ci_net={id=>'ci-test',label=>'CI test',up=>1,socket=>$ci_fh,nick=>'gitwatch'};my$ci_cd=$CFG{cmd_cooldown};$CFG{cmd_cooldown}=0;command($ci_net,'tester','#test','!github reliability');command($ci_net,'tester','#test','!github incidents');$CFG{cmd_cooldown}=$ci_cd;close$ci_fh;my$ci_text=decode('UTF-8',$ci_wire);push@t,$ci_text=~/CI reliability/&&$ci_text=~/60%/&&$ci_text=~/CI recovery/&&$ci_text=~/Latest recovery/;
 $STATE{ci_bad_state}={$build_scope=>{run_id=>6,at=>$ci_now-60,conclusion=>'failure',name=>'Build',branch=>'main',url=>$ci_url.'6',attempt=>1,duration=>45}};my$rel_degraded=ci_reliability_summary($ci_now);push@t,$rel_degraded->{state}eq'degraded'&&$rel_degraded->{active_incidents}==1&&$rel_degraded->{active}[0]{name}eq'Build';
 ($STATE{ci_run_history},$STATE{ci_bad_state},$CFG{actions_enabled})=($old_ci_history,$old_ci_bad,$old_ci_actions_enabled);

 # v0.28 keeps exact 14-day aggregates separate from accumulated daily
 # history, and exposes the latest clone/unique snapshot immediately.
 my$dash28=dashboard_html();my$js28=dashboard_js();
 push@t,$dash28=~/id="toolbar-latest-traffic"/&&$dash28=~/Latest traffic/&&$dash28=~/data-range="30"/&&$dash28=~/data-range="90"/&&$dash28=~/retain up to 400 days/;
 push@t,$js28=~/rows\.slice\(-Math\.max\(1,chartRange\)\)/&&$js28=~/toolbar-latest-traffic/&&$js28=~/t\.latest/&&$js28=~/last\.clone_uniques/&&$js28=~/history\?\.days/;

 # v0.27 unique-audience graph and analysis: GitHub aggregates are visible,
 # useful and never mislabeled as raw-IP observations.
 my$dash27=dashboard_html();my$js27=dashboard_js();my$aud27=traffic_audience_summary();
 push@t,$dash27=~/id="unique-chart"/&&$dash27=~/Unique audience/&&$dash27=~/Unique cloners/&&$dash27=~/Unique visitors/;
 push@t,$dash27=~/raw IP addresses are not exposed/&&$dash27!~/Unique IP/i&&$dash27!~/IP uniques/i;
 push@t,$dash27=~/class="audience-strip"/&&$dash27=~/Clone depth/&&$dash27=~/Daily unique avg/&&$dash27=~/7d clones/;
 push@t,$js27=~/renderUniqueChart\(d\)/&&$js27=~/clone_uniques/&&$js27=~/view_uniques/&&$js27=~/clonerUniqueArea/&&$js27=~/audience-week-change/;
 push@t,ref($aud27->{clone_unique_trend})eq'HASH'&&ref($aud27->{view_unique_trend})eq'HASH'&&ref($aud27->{comparison_7d})eq'HASH';

 # v0.25 Grafana-inspired live dashboard / meaningful audience semantics.
 my$dash25=dashboard_html();my$js25=dashboard_js();my$dp25=dashboard_payload();my$aud25=traffic_audience_summary();
 push@t,$dash25=~/id="traffic-chart"/&&$dash25=~/class="stat-row"/&&$dash25=~/Top referrers/&&$dash25=~/Popular content/&&$dash25=~/<details class="card full"/;
 push@t,$dash25!~/<meta\s+http-equiv=["']refresh/i&&$dash25=~/\?asset=dashboard-js/&&$dash25=~/id="live-badge"/&&$dash25=~/Unique cloners/&&$dash25=~/Unique visitors/;
 push@t,$js25=~/fetch\(endpoint\(\)/&&$js25=~/visibilitychange/&&$js25=~/AbortController/&&$js25=~/requestAnimationFrame/&&$js25=~/renderChart\(d\)/&&$js25=~/createElementNS/&&$js25!~/location\.reload/;
 push@t,$js25=~/chartRange/&&$js25=~/range-btn/&&$js25=~/chart-tooltip/;
 push@t,ref($aud25)eq'HASH'&&exists$aud25->{clone_uniques}&&exists$aud25->{view_uniques}&&exists$aud25->{today_clone_uniques}&&exists$aud25->{today_view_uniques};
 push@t,traffic_trend_text('clones')=~/today/&&($CFG{dashboard_public_url}eq''||$CFG{dashboard_public_url}=~m{^https?://}i);
 push@t,http_query_param('/githubhook?api=dashboard&x=1','api')eq'dashboard'&&http_query_param('/githubhook?asset=dashboard-js','asset')eq'dashboard-js';
 push@t,ref($dp25)eq'HASH'&&ref($dp25->{recent_activity})eq'ARRAY'&&ref($dp25->{dashboard})eq'HASH'&&$dp25->{dashboard}{mode}eq'component-poll';

 # v0.21 deterministic 4-target broadcast regression.
 my@fan_save=map{{enabled=>$_->{enabled},up=>$_->{up},socket=>$_->{socket},next_send=>$_->{next_send},send_cursor=>$_->{send_cursor},
  joined=>[map{$_->{joined}}net_channels($_)]}}@NETS;
 my$old_send=$CFG{send_interval};my$old_fan_state=$CFG{state_file};my$old_fan_backup=$CFG{state_backup};
 my$old_pending_fan=$STATE{pending};my$old_bhist=$STATE{broadcast_history};my$old_dstats=$STATE{delivery_stats};
 my($old_bseq,$old_benq,$old_bdone,$old_battempt,$old_bfail)=($STATE{broadcast_seq},@STATS{qw(broadcast_enqueued broadcast_completed broadcast_delivery_attempts broadcast_delivery_failures)});
 my@fan_files;for my$i(0..2){my$f="/tmp/githubwatch-fanout-$$-$i.txt";unlink$f;open my$fh,'+>',$f or die"fanout file: $!";binmode$fh,':raw';push@fan_files,[$f,$fh]}
 for my$i(0..$#NETS){my$n=$NETS[$i];$n->{enabled}=1;$n->{up}=1;$n->{socket}=$fan_files[$i][1];$n->{next_send}=0;$n->{send_cursor}=0;$_->{joined}=1 for net_channels($n)}
 $CFG{send_interval}=0;$CFG{state_file}="/tmp/githubwatch-fanout-state-$$.json";$CFG{state_backup}=0;
 $STATE{pending}=[];$STATE{broadcast_history}=[];$STATE{delivery_stats}={};$STATE{broadcast_seq}=0;
 enqueue('FANOUT-REGRESSION','selftest',1);my@fan_ids=current_target_ids();push@t,@fan_ids==4&&@{$STATE{pending}}==1&&@{$STATE{pending}[0]{targets}}==4;
 drain_queue();drain_queue();drain_queue();
 push@t,@{$STATE{pending}}==0&&$STATS{broadcast_completed}>$old_bdone;
 my@fan_wire;for my$x(@fan_files){my($f,$fh)=@$x;seek$fh,0,0;local$/;push@fan_wire,<$fh>;close$fh;unlink$f}
 push@t,index($fan_wire[0],'PRIVMSG '.$CFG{irc_channel}.' :')>=0&&$fan_wire[0]=~/FANOUT-REGRESSION/s;
 push@t,index($fan_wire[1],'PRIVMSG '.$CFG{libera_channel}.' :')>=0&&$fan_wire[1]=~/FANOUT-REGRESSION/s;
 push@t,index($fan_wire[2],'PRIVMSG '.$CFG{undernet_teuk}.' :')>=0&&index($fan_wire[2],'PRIVMSG '.$CFG{undernet_miaw}.' :')>=0&&$fan_wire[2]=~/FANOUT-REGRESSION/s;
 unlink$CFG{state_file};unlink"$CFG{state_file}.bak";
 for my$i(0..$#NETS){my$n=$NETS[$i];my$s=$fan_save[$i];$n->{enabled}=$s->{enabled};$n->{up}=$s->{up};$n->{socket}=$s->{socket};$n->{next_send}=$s->{next_send};$n->{send_cursor}=$s->{send_cursor};my@c=net_channels($n);for my$j(0..$#c){$c[$j]{joined}=$s->{joined}[$j]}}
 $CFG{send_interval}=$old_send;$CFG{state_file}=$old_fan_state;$CFG{state_backup}=$old_fan_backup;
 $STATE{pending}=$old_pending_fan;$STATE{broadcast_history}=$old_bhist;$STATE{delivery_stats}=$old_dstats;$STATE{broadcast_seq}=$old_bseq;
 @STATS{qw(broadcast_enqueued broadcast_completed broadcast_delivery_attempts broadcast_delivery_failures)}=($old_benq,$old_bdone,$old_battempt,$old_bfail);

 # v0.20.3 exact regression for the production Traffic dashboard crash.
 my$best3=traffic_best_day([
  {timestamp=>'2026-08-26T00:00:00Z',count=>2,uniques=>1},
  {timestamp=>'2026-08-27T00:00:00Z',count=>7,uniques=>3},
 ],'count');
 push@t,ref($best3)eq'HASH'&&$best3->{count}==7&&$best3->{uniques}==3;
 my$old_render_tc={%{$STATE{traffic_clones}}};my$old_render_tv={%{$STATE{traffic_views}}};my$old_render_ok=$STATE{last_traffic_ok};my$old_render_token=$CFG{token};
 $STATE{traffic_clones}={count=>9,uniques=>4,clones=>[{timestamp=>'2026-08-27T00:00:00Z',count=>9,uniques=>4}]};
 $STATE{traffic_views}={count=>13,uniques=>6,views=>[{timestamp=>'2026-08-27T00:00:00Z',count=>13,uniques=>6}]};
 $STATE{last_traffic_ok}=time;$CFG{token}='selftest-token';
 my$render_regression=eval{traffic_dashboard_html()};
 push@t,!!(defined($render_regression)&&!$@&&$render_regression=~/Best view day/);
 $STATE{traffic_clones}=$old_render_tc;$STATE{traffic_views}=$old_render_tv;$STATE{last_traffic_ok}=$old_render_ok;$CFG{token}=$old_render_token;

 # v0.20.2 HTTP parser/proxy compatibility.
 push@t,defined($SIG{PIPE})&&$SIG{PIPE} eq'IGNORE';
 my$old_alias=$CFG{hook_root_alias};$CFG{hook_root_alias}=1;push@t,$CFG{hook_root_alias}&&normalized_http_path('/')eq'/';$CFG{hook_root_alias}=$old_alias;
 pipe(my$chunk_r,my$chunk_w);binmode$chunk_r,':raw';binmode$chunk_w,':raw';
 print{$chunk_w}"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";close$chunk_w;my$empty='';
 my$chunk_out=eval{decode_chunked_http_body($chunk_r,\$empty)};close$chunk_r;
 push@t,defined$chunk_out&&$chunk_out eq'Wikipedia';

 # JSON::PP encode_json already returns UTF-8 octets. The HTTP layer must not
 # encode those octets a second time, while character bodies still need one
 # UTF-8 encoding pass.
 pipe(my$json_r,my$json_w);binmode$json_r,':raw';binmode$json_w,':raw';
 my$json_chars="↑ — ◆ ✨";my$json_octets=encode_json({text=>$json_chars});
 http_response($json_w,200,'application/json',$json_octets,0,1);close$json_w;local$/;my$json_wire=<$json_r>;close$json_r;
 my($json_head,$json_body)=split/\r\n\r\n/,$json_wire,2;my$json_doc=eval{decode_json($json_body)};
 push@t,$json_doc&&$json_doc->{text}eq$json_chars&&$json_head=~/Content-Length:\s*\Q@{[length($json_body)]}\E\r/i;
 pipe(my$text_r,my$text_w);binmode$text_r,':raw';binmode$text_w,':raw';
 http_response($text_w,200,'text/plain',$json_chars,0);close$text_w;my$text_wire=<$text_r>;close$text_r;
 my(undef,$text_body)=split/\r\n\r\n/,$text_wire,2;my$text_decoded=eval{decode('UTF-8',$text_body,FB_CROAK)};
 push@t,defined($text_decoded)&&$text_decoded eq$json_chars;

 my$sp=status_payload();
 push@t,ref($sp)eq'HASH'&&$sp->{version}eq VERSION&&exists$sp->{rss}&&exists$sp->{github_api}&&exists$sp->{github_actions}&&exists$sp->{current_ci_running}&&exists$sp->{current_ci_expected}&&exists$sp->{current_ci_flaky}&&ref($sp->{webhook_detail})eq'HASH'&&!ref($sp->{queue})&&ref($sp->{queue_detail})eq'HASH'&&ref($sp->{irc})eq'HASH'&&exists$sp->{irc}{undernet}&&ref($sp->{irc}{targets})eq'ARRAY'&&!(grep{!exists$_->{joined}}@{$sp->{irc}{targets}})&&ref($sp->{http_listener})eq'HASH'&&ref($sp->{github_traffic})eq'HASH'&&ref($sp->{github_account})eq'HASH'&&ref($sp->{github_account}{changes})eq'ARRAY'&&ref($sp->{broadcast})eq'HASH'&&ref($sp->{broadcast}{targets})eq'ARRAY'&&ref($sp->{state})eq'HASH'&&ref($sp->{counters})eq'HASH'&&ref($sp->{counters}{traffic})eq'HASH'&&ref($sp->{counters}{account})eq'HASH'&&exists$sp->{last_event_at};
 push@t,index(encode_json($sp),$CFG{hook_secret})<0 if$CFG{hook_secret}ne'';
 push@t,index(encode_json($sp),$CFG{token})<0 if$CFG{token}ne'';

 my@names=active_selftest_names();
 if(@names!=@t){print APP_NAME.' '.VERSION.' selftest: FAILED (test registry '.scalar(@names).' != results '.scalar(@t).")\n";print "failed checks: selftest.registry-cardinality\n";return 1}
 my@bad=grep{!$t[$_]}0..$#t;my$bad=@bad;print APP_NAME.' '.VERSION.' selftest: '.($bad?'FAILED':'OK').' ('.(@t-$bad).'/'.scalar@t.")\n";
 print 'failed checks: '.join(',',map{($_+1).'('.$names[$_].')'}@bad)."\n"if$bad;
 $bad?1:0;
}
sub fixture_check {
 my($checks,$name,$value)=@_;
 push@$checks,[$name,$value?1:0];
}
sub state_fixture_check_cli {
 my($path,$expected)=@_;
 if(!defined$path||$path eq''||!defined$expected||$expected!~/^v0\.(?:29|30)$/){
  print STDERR "usage: ".APP_NAME." --state-fixture-check FILE v0.29|v0.30\n";
  return 64;
 }
 my@checks;my($doc,undef,$err)=read_state_document($path);
 fixture_check(\@checks,'fixture.document-readable',$doc&&$err eq'');
 if(!$doc){
  print APP_NAME." $expected state fixture: FAILED (0/1)\n";
  print "failed checks: fixture.document-readable ($err)\n";
  return 1;
 }
 fixture_check(\@checks,'fixture.schema-v11',int($doc->{state_version}||0)==11);
 fixture_check(\@checks,'fixture.release-marker',clean($doc->{version}||'')eq substr($expected,1));

 $CFG{account}='teuk';$CFG{state_file}=$path;$CFG{state_backup}=0;
 load_state();
 fixture_check(\@checks,'fixture.primary-load',$RUN{state_loaded_from}eq'primary');
 fixture_check(\@checks,'fixture.event-marker',exists$STATE{event_seen}{'fixture-event-'.($expected eq'v0.29'?'v029':'v030')});
 fixture_check(\@checks,'fixture.traffic-history-normalized',ref($STATE{traffic_history})eq'HASH'&&scalar(keys%{$STATE{traffic_history}})==1);
 fixture_check(\@checks,'fixture.stats-schema-migrated',$STATE{stats_version}==3);
 fixture_check(\@checks,'fixture.poll-counters-coherent',$STATS{poll_new}>=$STATS{poll_sent});

 if($expected eq'v0.29'){
  fixture_check(\@checks,'fixture.v029-array-traffic-source',ref($doc->{traffic_history})eq'ARRAY');
  fixture_check(\@checks,'fixture.v029-legacy-pending-normalized',@{$STATE{pending}}==1&&ref($STATE{pending}[0])eq'HASH'&&$STATE{pending}[0]{id}ne''&&$STATE{pending}[0]{text}=~/abc0290/);
  fixture_check(\@checks,'fixture.v029-history-preserved',@{$STATE{history}}==1&&$STATE{history}[0]{text}=~/abc0290/);
  fixture_check(\@checks,'fixture.v029-ci-history-optional',!exists($doc->{ci_run_history})&&@{$STATE{ci_run_history}}==0);
  fixture_check(\@checks,'fixture.v029-public-account-preserved',@{$STATE{account_repos}}==1&&$STATE{account_repos}[0]{full_name}eq'teuk/irc-gitwatch');
  fixture_check(\@checks,'fixture.v029-poll-new-migration',$STATS{poll_new}==4&&$STATS{poll_sent}==4);
 }else{
  fixture_check(\@checks,'fixture.v030-ci-source-has-duplicate',ref($doc->{ci_run_history})eq'ARRAY'&&@{$doc->{ci_run_history}}==3);
  fixture_check(\@checks,'fixture.v030-ci-history-deduplicated',@{$STATE{ci_run_history}}==2);
  fixture_check(\@checks,'fixture.v030-ci-history-sorted',$STATE{ci_run_history}[0]{id}==29&&$STATE{ci_run_history}[1]{id}==30);
  fixture_check(\@checks,'fixture.v030-ci-history-normalized',$STATE{ci_run_history}[1]{key}eq'30:1:success'&&$STATE{ci_run_history}[1]{duration}==60);
  fixture_check(\@checks,'fixture.v030-account-change-preserved',@{$STATE{account_changes}}==1&&$STATE{account_changes}[0]{kind}eq'stars');
  fixture_check(\@checks,'fixture.v030-map-traffic-source',ref($doc->{traffic_history})eq'HASH');
 }

 my@bad=grep{!$checks[$_][1]}0..$#checks;my$bad=@bad;
 print APP_NAME." $expected state fixture: ".($bad?'FAILED':'OK').' ('.(@checks-$bad).'/'.scalar(@checks).")\n";
 print 'failed checks: '.join(',',map{$checks[$_][0]}@bad)."\n"if$bad;
 $bad?1:0;
}
sub doctor_line {
 my($kind,$name,$detail)=@_;$detail//=q{};
 print sprintf("%-5s %-18s %s\n","[$kind]",$name,$detail);
}
sub doctor_tls {
 my($net)=@_;return(0,'network missing')unless$net;
 my$s;
 if($net->{tls}){
  $s=IO::Socket::SSL->new(PeerHost=>$net->{host},PeerPort=>$net->{port},Timeout=>8,SSL_verify_mode=>SSL_VERIFY_PEER,SSL_hostname=>$net->{host});
  return(0,clean(IO::Socket::SSL::errstr()||$!||'TLS failed'))unless$s;
  close$s;return(1,'TLS OK');
 }
 $s=IO::Socket::INET->new(PeerHost=>$net->{host},PeerPort=>$net->{port},Proto=>'tcp',Timeout=>8);
 return(0,clean($!||'TCP failed'))unless$s;close$s;(1,'TCP OK');
}
sub doctor {
 my($fail,$warn)=(0,0);
 my@ce=config_errors();
 if(@ce){doctor_line('FAIL','configuration',join('; ',@ce));$fail++}
 else{doctor_line('PASS','configuration','valid')}

 my$ss=state_status();
 if($ss->{primary}eq'ok'){
  my@st=stat($CFG{state_file});my$mode=@st?sprintf('%04o',$st[2]&07777):'?';doctor_line($mode eq'0600'?'PASS':'WARN','state',"primary JSON OK · mode $mode · backup $ss->{backup}");$warn++ if$mode ne'0600';
 }elsif($ss->{backup}eq'ok'){doctor_line('WARN','state',"primary $ss->{primary} · recoverable backup OK");$warn++}
 elsif($ss->{primary}eq'missing'&&$ss->{backup}eq'missing'){doctor_line('WARN','state','not created yet');$warn++}
 else{doctor_line('FAIL','state',"primary $ss->{primary} · backup $ss->{backup}");$fail++}

 auth_check();
 if($RUN{auth_state}eq'verified'&&$RUN{auth_events}eq'ok'){doctor_line('PASS','GitHub auth',"TOKEN OK · $RUN{auth_login}")}
 elsif($RUN{auth_state}eq'anonymous'){doctor_line('WARN','GitHub auth','anonymous public mode');$warn++}
 else{doctor_line('FAIL','GitHub auth',auth_short().' · '.clean($RUN{auth_error}));$fail++}

 if(github_rest_allowed()){
  my$r=eval{$HTTP->get("https://api.github.com/repos/$CFG{repo}/events?per_page=1",{headers=>api_headers($RUN{token},0)})};
  if($r&&ref$r eq'HASH'){note_rate_limit($r,'doctor events')}
  if($r&&ref$r eq'HASH'&&$r->{status}==200){doctor_line('PASS','Events API',"$RUN{rate_remaining}/$RUN{rate_limit} remaining")}
  else{doctor_line('FAIL','Events API',$r&&ref$r eq'HASH'?"HTTP $r->{status} $r->{reason}":clean($@||'request failed'));$fail++}
 }else{doctor_line('WARN','Events API','rate limited · resume '.rate_resume_text());$warn++}

 if($CFG{actions_enabled}){
  if(github_rest_allowed()){
   my$token=$RUN{actions_auth_mode}eq'anonymous-fallback'?'':$RUN{token};
   my$r=eval{$HTTP->get("https://api.github.com/repos/$CFG{repo}/actions/runs?per_page=1",{headers=>api_headers($token,0)})};
   note_rate_limit($r,'doctor actions') if$r&&ref$r eq'HASH';
   if($r&&ref$r eq'HASH'&&$r->{status}==200){doctor_line('PASS','Actions API','readable')}
   elsif($token ne''){doctor_line('WARN','Actions API','authenticated access unavailable; public fallback may still work');$warn++}
   else{doctor_line('FAIL','Actions API',$r&&ref$r eq'HASH'?"HTTP $r->{status} $r->{reason}":clean($@||'request failed'));$fail++}
  }else{doctor_line('WARN','Actions API','rate limited · skipped');$warn++}
 }else{doctor_line('PASS','Actions API','disabled')}

 if($CFG{traffic_enabled}){
  if($CFG{token}eq''){doctor_line('WARN','GitHub Traffic','token required for repository traffic stats');$warn++}
  elsif(!github_rest_allowed()){doctor_line('WARN','GitHub Traffic','rate limited · skipped');$warn++}
  else{
   my$d=traffic_fetch_stage('clones');
   if(defined$d){doctor_line('PASS','GitHub Traffic','clones endpoint readable')}
   elsif($RUN{traffic_permission}eq'forbidden'){doctor_line('WARN','GitHub Traffic','HTTP 403 · token needs repository traffic permission');$warn++}
   else{doctor_line('WARN','GitHub Traffic',clean($RUN{traffic_error}||'unavailable'));$warn++}
  }
 }else{doctor_line('PASS','GitHub Traffic','disabled')}

 if($CFG{account_enabled}){
  if(!github_rest_allowed()){doctor_line('WARN',$CFG{account}.' portfolio','rate limited · skipped');$warn++}
  else{
   my$r=account_fetch_page($CFG{account_url},0);
   if($r){doctor_line('PASS',$CFG{account}.' portfolio',scalar(@{$r->{repos}}).' public owner repository record(s) on first page')}
   else{doctor_line('WARN',$CFG{account}.' portfolio',clean($RUN{account_error}||'unavailable'));$warn++}
  }
 }else{doctor_line('PASS',$CFG{account}.' portfolio','disabled')}

 if($CFG{rss_enabled}){
  my$i=fetch_rss();
  if(defined$i){doctor_line('PASS','Forum RSS',scalar(@$i).' item(s) or unchanged')}
  else{doctor_line('FAIL','Forum RSS',$RUN{rss_error});$fail++}
 }else{doctor_line('PASS','Forum RSS','disabled')}

 for my$net(enabled_nets()){
  my($ok,$d)=doctor_tls($net);my$transport=$net->{tls}?'TLS':'TCP';
  doctor_line($ok?'PASS':'FAIL',"IRC $transport $net->{label}",$d);
  $fail++ unless$ok;
 }

 doctor_line($fail?'FAIL':$warn?'WARN':'PASS','result',$fail?"$fail failure(s), $warn warning(s)":$warn?"$warn warning(s)":'all checks passed');
 $fail?2:0;
}

sub http_check_cli {
 return 1 if config_check();
 if(!start_hook()){print "HTTP listener: ERROR — $RUN{http_listener_error}\n";return 2}
 my$port=eval{$RUN{listener}->sockport}||$CFG{hook_port};
 print "HTTP listener: OK — $CFG{hook_bind}:$port — webhook POST ".($CFG{hook_secret}ne''?'enabled':'disabled')."\n";
 close$RUN{listener};$RUN{listener}=undef;0;
}
sub undernet_check_cli {
 return 1 if config_check();return 3 unless$CFG{undernet_enabled};
 my$net=$NET{undernet};my$old_start=$CFG{startup_announce};$CFG{startup_announce}=0;
 for my$ch(net_channels($net)){$ch->{joined}=0;$ch->{join_error}='';$ch->{next_join}=0;$ch->{startup_sent}=0}
 if(!irc_connect($net)){$CFG{startup_announce}=$old_start;print "Undernet: ERROR — registration/connect failed\n";return 2}
 my$deadline=time+20;
 while(time<$deadline&&$net->{up}){
  if($net->{buf}=~/\n/){read_irc($net)}
  else{
   my$sel=IO::Select->new($net->{socket});my@r=$sel->can_read(.25);read_irc($net)if@r;
  }
  rejoin_channels_once();
  my@c=net_channels($net);last if@c&&scalar(grep{$_->{joined}}@c)==scalar@c;
 }
 my@c=net_channels($net);my$ok=@c&&scalar(grep{$_->{joined}}@c)==scalar@c;
 my@parts=map{$_->{name}.'='.($_->{joined}?'joined':'not-joined'.($_->{join_error} ne''?'('.$_->{join_error}.')':''))}@c;
 print "Undernet: ".($ok?'OK':'ERROR')." — nick=$net->{nick} — ".join(' — ',@parts)."\n";
 irc_raw($net,'QUIT :IRC GitWatch check complete') if$net->{up};eval{close$net->{socket}if$net->{socket}};$net->{socket}=undef;$net->{up}=0;$CFG{startup_announce}=$old_start;
 $ok?0:2;
}

sub summary {
 print APP_NAME.' '.VERSION."\n".
  "repo=$CFG{repo}\n".
  "token=".($CFG{token}ne''?'configured':'empty')."\n".
  "http=$CFG{hook_bind}:$CFG{hook_port}; webhook_post=".($CFG{hook_secret}ne''?'enabled':'disabled')."; root_alias=".($CFG{hook_root_alias}?'on':'off')."\n".
  "events_poll=".($CFG{poll_enabled}?$CFG{reconcile}."s, catch-up <=$CFG{events_max_pages} pages":'disabled')."\n".
  "actions=".($CFG{actions_enabled}?"adaptive $CFG{actions_fast}s/$CFG{actions_idle}s, catch-up <=$CFG{actions_max_pages} pages, ".($CFG{actions_fail_only}?'failures + recovery':'all completed').", enrichment=".($CFG{actions_enrich}?'on':'off').", slow=".($CFG{actions_slow}?duration_text($CFG{actions_slow}):'off').", expect=".($CFG{actions_expect}?duration_text($CFG{actions_expect}).($CFG{actions_expect_branches} ne''?' ['.$CFG{actions_expect_branches}.']':''):'off').", flaky=".($CFG{actions_flaky_window}?duration_text($CFG{actions_flaky_window}).'/'.$CFG{actions_flaky_transitions}:'off'):'disabled')."\n".
  "account=".($CFG{account_enabled}?$CFG{account}." public owner repositories every $CFG{account_interval}s, catch-up <=$CFG{account_max_pages} pages, stale=$CFG{account_stale_days}d, changes<=$CFG{account_changes_max}":'disabled')."\n".
  "history=$CFG{history_max} entries, show=$CFG{history_show}; metrics=".($CFG{metrics_enabled}?'on':'off')."; traffic=".($CFG{traffic_enabled}?$CFG{traffic_interval}.'s':'off')."; dashboard=$CFG{dashboard_poll}s/$CFG{dashboard_hidden}s".($CFG{dashboard_public_url}?" public":" local-only")."\n".
  "state_backup=".($CFG{state_backup}?'on':'off')."; ops_alerts=".($CFG{ops_alerts}?'on':'off').($CFG{ops_alerts}?" debounce=$CFG{ops_debounce}s":'')."\n".
  "rss=".($CFG{rss_enabled}?$CFG{rss_url}.' every '.$CFG{rss_interval}.'s':'disabled')."\n".
  "epiknet=".($CFG{epiknet_enabled}?"$CFG{irc_host}:$CFG{irc_port} $CFG{irc_channel} as $CFG{irc_nick}":'disabled')."\n".
  "libera=".($CFG{libera_enabled}?"$CFG{libera_host}:$CFG{libera_port} $CFG{libera_channel} as $CFG{libera_nick}":'disabled')."\n".
  "undernet=".($CFG{undernet_enabled}?"$CFG{undernet_host}:$CFG{undernet_port} ".($CFG{undernet_tls}?'TLS':'TCP')." $CFG{undernet_teuk},$CFG{undernet_miaw} as $CFG{undernet_nick}":'disabled')."\n".
  "icons=$CFG{icon_mode}\n".
  "limits=secondary<=$CFG{secondary_max}s http-read=$CFG{http_read_timeout}s heartbeat=".($CFG{irc_idle_ping}?"$CFG{irc_idle_ping}s/$CFG{irc_pong_timeout}s":'off')."\n";
}

if(@ARGV){
 if($ARGV[0]eq'--version'){print APP_NAME.' '.VERSION."\n";exit 0}
 if($ARGV[0]eq'--selftest-list'){my@names=active_selftest_names();printf "%03d %s\n",$_+1,$names[$_]for 0..$#names;exit 0}
 if($ARGV[0]eq'--selftest'){exit selftest()}
 if($ARGV[0]eq'--state-fixture-check'){exit state_fixture_check_cli($ARGV[1],$ARGV[2])}
 if($ARGV[0]eq'--config-check'){summary();exit config_check()}
 if($ARGV[0]eq'--doctor'){exit doctor()}
 if($ARGV[0]eq'--http-check'){exit http_check_cli()}
 if($ARGV[0]eq'--undernet-check'){exit undernet_check_cli()}
 if($ARGV[0]eq'--state-check'){exit state_check_cli()}
 if($ARGV[0]eq'--auth-check'){exit 1 if config_check();auth_check();exit 0 if$RUN{auth_state}eq'verified'&&$RUN{auth_events}eq'ok';exit 3 if$RUN{auth_state}eq'anonymous';exit 2}
 if($ARGV[0]eq'--actions-check'){
  exit 1 if config_check();exit 3 unless$CFG{actions_enabled};auth_check();
  my$x=fetch_actions_page($CFG{actions_url},1);if(!$x){print "GitHub Actions: ERROR — $RUN{actions_error}\n";exit 2}
  my$r=$x->{runs};my@c=grep{clean($_->{status}//'')eq'completed'}@$r;
  if(@c){my$e=normalize_action_run($c[0]);print "GitHub Actions: OK — ".scalar(@$r)." run(s) — latest=$e->{title} — $e->{conclusion}\n"}
  else{print "GitHub Actions: OK — ".scalar(@$r)." run(s) — no completed run in window\n"}
  exit 0;
 }
 if($ARGV[0]eq'--traffic-check'){exit 1 if config_check();exit traffic_check_cli()}
 if($ARGV[0]eq'--account-check'){exit 1 if config_check();exit account_check_cli()}
 if($ARGV[0]eq'--rss-check'){
  exit 1 if config_check();exit 3 unless$CFG{rss_enabled};
  my$i=fetch_rss();if(!defined$i){print "Forum RSS: ERROR — $RUN{rss_error}\n";exit 2}
  my$newest=@$i?clean($i->[0]{title}):'no items';
  print "Forum RSS: OK — ".scalar(@$i)." item(s) — newest=$newest\n";exit 0;
 }
}

# ── Daemon ───────────────────────────────────────────────────────────────────
exit 1 if config_check();
load_state();start_hook() or die "Cannot start local HTTP/webhook listener\n";auth_check();
logmsg('INFO',APP_NAME.' '.VERSION." ready — repo=$CFG{repo} — auth=".auth_short().
 ' — networks='.join(',',map{$_->{label}}enabled_nets()).
 ' — webhook='.hook_status().' — events='.maxn($CFG{reconcile},$RUN{poll_min}).'s'.
 ' — actions='.($CFG{actions_enabled}?"adaptive $CFG{actions_fast}s/$CFG{actions_idle}s":'off').
 ' — account='.($CFG{account_enabled}?$CFG{account}.'/'.$CFG{account_interval}.'s':'off').
 ' — rss='.($CFG{rss_enabled}?$CFG{rss_interval}.'s':'off'));

my$fresh=keys(%{$STATE{event_seen}})?0:1;
my$actions_fresh=keys(%{$STATE{actions_seen}})?0:1;
my$rss_fresh=$STATE{rss_id_version}==2&&keys(%{$STATE{rss_seen}})?0:1;
$_->{next_reconnect}=time for enabled_nets();

while(!$RUN{stopping}){
 my$did=0;
 $did+=ensure_http_listener()?0:0;

 # Serve already-arrived IRC and HTTP/webhook traffic before attempting a
 # reconnect. A failing optional IRC network must never starve the local HTTP
 # listener again.
 my$pending_net;
 for my$net(online_nets()){
  if($net->{buf}=~/\n/||($net->{tls}&&(eval{$net->{socket}->pending}||0)>0)){$pending_net=$net;last}
 }
 if($pending_net){read_irc($pending_net);$did++}

 my@watch;
 push@watch,map{$_->{socket}}online_nets();
 push@watch,$RUN{listener}if$RUN{listener};
 if(@watch){
  my$sel=IO::Select->new(@watch);
  for my$fh($sel->can_read(0)){
   if($RUN{listener}&&fileno($fh)==fileno($RUN{listener})){
    my$c=$RUN{listener}->accept();
    if(!$c){drop_http_listener('accept failed: '.clean($!));$did++;next}
    $c->autoflush(1);
    my$ok=eval{handle_hook($c);1};
    if(!$ok){my$e=clean($@||'handler failure');logmsg('WARN','HTTP/webhook handler error ['.($RUN{http_last_method}||'?').' '.($RUN{http_last_path}||'?').']: '.$e);eval{http_reply($c,500,'internal error')}}
    close$c;$did++;next;
   }
   for my$net(online_nets()){
    if(fileno($fh)==fileno($net->{socket})){read_irc($net);$did++;last}
   }
  }
 }

 $did+=heartbeat_once();
 $did+=rejoin_channels_once();
 drain_queue();

 # One network reconnect per turn. Undernet returns as soon as registration is
 # complete; its channel JOIN confirmations are handled asynchronously above.
 $did+=reconnect_one();

 # Exactly one maintenance family per turn.
 $did+=maintenance_once(\$fresh,\$actions_fresh,\$rss_fresh);

 sleep .10 unless$did;
}
save_state();logmsg('INFO',APP_NAME.' stopped cleanly');exit 0;
