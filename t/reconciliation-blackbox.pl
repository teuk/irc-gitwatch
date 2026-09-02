#!/usr/bin/env perl
use strict;
use warnings;

use Digest::SHA qw(hmac_sha256_hex);
use File::Temp qw(tempdir);
use IO::Select;
use IO::Socket::INET;
use JSON::PP qw(decode_json);
use POSIX qw(_exit);

my $repo='octocat/Hello-World';
my $secret='synthetic-local-reconciliation-secret';
my $webhook_dir='t/fixtures/webhooks';
my $reconcile_dir='t/fixtures/reconciliation';
my $temp_dir=tempdir('irc-gitwatch-reconcile-XXXXXX',TMPDIR=>1,CLEANUP=>1);
my $diagnostic_file="$temp_dir/children.stderr";
my $server_pid=0;
my $server_sequence=0;
my @checks;

sub record_check {
 my($name,$ok)=@_;push@checks,[$name,$ok?1:0];
}

sub slurp {
 my($path)=@_;open my$fh,'<:raw',$path or die"cannot read $path: $!\n";
 local$/;my$raw=<$fh>;close$fh;$raw;
}

sub state_document {
 my($path)=@_;my$raw=slurp($path);my$doc=eval{decode_json($raw)};
 die"invalid state JSON: $path\n"unless$doc&&ref($doc)eq'HASH';$doc;
}

sub configure_test_environment {
 my($state)=@_;
 $ENV{GITHUB_REPO}=$repo;
 $ENV{GITHUB_TOKEN}='';
 $ENV{IRC_GITWATCH_TEST_MODE}=1;
 $ENV{GITHUB_WEBHOOK_SECRET}=$secret;
 $ENV{GITHUB_STATE_FILE}=$state;
 $ENV{STATE_BACKUP_ENABLED}=0;
 $ENV{GITHUB_WEBHOOK_MAX_BODY}=1024;
 $ENV{GITHUB_WEBHOOK_ROOT_ALIAS}=0;
 $ENV{GITHUB_POLL_ENABLED}=0;
 $ENV{GITHUB_ACTIONS_ENABLED}=0;
 $ENV{GITHUB_TRAFFIC_ENABLED}=0;
 $ENV{GITHUB_ACCOUNT_ENABLED}=0;
 $ENV{RSS_ENABLED}=0;
 $ENV{EPIKNET_ENABLED}=1;
 $ENV{LIBERA_ENABLED}=0;
 $ENV{UNDERNET_ENABLED}=0;
 $ENV{METRICS_ENABLED}=1;
}

sub stop_server_hard {
 return unless$server_pid;
 kill'KILL',$server_pid;waitpid($server_pid,0);$server_pid=0;
}
END{stop_server_hard()}

sub start_server {
 my($state,$requests)=@_;$server_sequence++;
 pipe(my$ready_r,my$ready_w)or die"pipe: $!\n";
 $server_pid=fork();die"fork: $!\n"unless defined$server_pid;
 if(!$server_pid){
  close$ready_r;open STDOUT,'>&',$ready_w or _exit(125);close$ready_w;
  open STDERR,'>>:raw',$diagnostic_file or _exit(125);
  configure_test_environment($state);
  exec{$^X}$^X,'irc-gitwatch.pl','--webhook-test-server',$requests or _exit(126);
 }
 close$ready_w;my$select=IO::Select->new($ready_r);
 die"webhook test server readiness timeout\n"unless$select->can_read(10);
 my$line=<$ready_r>;close$ready_r;
 die"invalid webhook test server readiness\n"unless defined$line&&$line=~/^READY (\d+)\s*$/;
 int($1);
}

sub wait_server {
 waitpid($server_pid,0);my$rc=$?>>8;$server_pid=0;$rc;
}

sub exchange {
 my($port,$method,$path,$headers,$body)=@_;$headers||={};$body=''unless defined$body;
 my$s=IO::Socket::INET->new(PeerAddr=>'127.0.0.1',PeerPort=>$port,Proto=>'tcp',Timeout=>5)
  or die"connect to webhook test server: $!\n";
 binmode$s,':raw';$s->autoflush(1);
 my%h=%$headers;$h{'Content-Length'}=length$body if$method eq'POST'||length$body;
 my$wire="$method $path HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n";
 $wire.="$_: $h{$_}\r\n"for sort keys%h;$wire.="\r\n$body";
 my$off=0;while($off<length$wire){my$n=syswrite($s,$wire,length($wire)-$off,$off);die"request write failed\n"unless defined$n&&$n>0;$off+=$n}
 shutdown($s,1);my$response='';
 while(1){my$chunk='';my$n=sysread($s,$chunk,8192);last if defined$n&&$n==0;die"response read failed\n"unless defined$n;$response.=$chunk}
 close$s;my($head,$response_body)=split/\r\n\r\n/,$response,2;$response_body=''unless defined$response_body;
 my($status)=$head=~m{^HTTP/1\.[01]\s+(\d{3})\b};die"malformed HTTP response\n"unless$status;
 +{status=>int($status),body=>$response_body};
}

sub webhook {
 my($port,$event,$delivery,$fixture)=@_;my$body=slurp("$webhook_dir/$fixture.json");
 my%headers=(
  'Content-Type'=>'application/json',
  'X-GitHub-Event'=>$event,
  'X-GitHub-Delivery'=>$delivery,
  'X-Hub-Signature-256'=>'sha256='.hmac_sha256_hex($body,$secret),
 );
 exchange($port,'POST','/githubhook',\%headers,$body);
}

sub run_reconciliation {
 my($state,$fixture,$mode)=@_;pipe(my$out_r,my$out_w)or die"pipe: $!\n";
 my$pid=fork();die"fork: $!\n"unless defined$pid;
 if(!$pid){
  close$out_r;open STDOUT,'>&',$out_w or _exit(125);close$out_w;
  open STDERR,'>>:raw',$diagnostic_file or _exit(125);
  configure_test_environment($state);
  exec{$^X}$^X,'irc-gitwatch.pl','--reconciliation-test-fixture',"$reconcile_dir/$fixture.json",$mode or _exit(126);
 }
 close$out_w;local$/;my$raw=<$out_r>;close$out_r;waitpid($pid,0);my$rc=$?>>8;
 my$doc=eval{decode_json($raw//'')};my$out={rc=>$rc,raw=>$raw//''};
 $out->{doc}=$doc if$doc&&ref($doc)eq'HASH';$out;
}

sub response_is {
 my($response,$status,$fragment)=@_;
 $response->{status}==$status&&index($response->{body},$fragment)>=0;
}

sub targets_are_epiknet {
 my($rows)=@_;return 0 unless ref($rows)eq'ARRAY'&&@$rows;
 for my$row(@$rows){return 0 unless ref($row)eq'ARRAY'&&@$row==1&&$row->[0]eq'epiknet'}
 1;
}

my$ok=eval{
 # Webhook first: polling must only enqueue the release that webhook has not
 # already fingerprinted. A second poll and a restart must remain idempotent.
 my$state_a="$temp_dir/webhook-first.json";
 my$port=start_server($state_a,2);
 record_check('hook-first.push-queued',response_is(webhook($port,'push','delivery-push','push'),202,'queued'));
 record_check('hook-first.issue-queued',response_is(webhook($port,'issues','delivery-issue','issues'),202,'queued'));
 record_check('hook-first.initial-server-exit',wait_server()==0);

 my$overlap=run_reconciliation($state_a,'overlap','incremental');my$a=$overlap->{doc};
 record_check('hook-first.poll-cli-exit',$overlap->{rc}==0&&$a);
 record_check('hook-first.shared-dedupe',$a&&$a->{pending}==3&&$a->{broadcast_enqueued}==3&&$a->{fingerprints}==3);
 record_check('hook-first.poll-observation',$a&&$a->{event_seen}==3&&$a->{poll_new}==3&&$a->{poll_sent}==0);
 record_check('hook-first.source-order',$a&&join(',',@{$a->{pending_sources}||[]})eq'hook,hook,poll');
 record_check('hook-first.target-snapshots',$a&&targets_are_epiknet($a->{pending_targets}));

 my$again=run_reconciliation($state_a,'overlap','incremental');my$a2=$again->{doc};
 record_check('hook-first.second-poll-exit',$again->{rc}==0&&$a2);
 record_check('hook-first.second-poll-idempotent',$a2&&$a2->{pending}==3&&$a2->{broadcast_enqueued}==3&&$a2->{poll_new}==3&&$a2->{fingerprints}==3);

 $port=start_server($state_a,3);
 record_check('hook-first.delivery-survives-restart',response_is(webhook($port,'push','delivery-push','push'),200,'duplicate'));
 record_check('hook-first.fingerprint-survives-restart',response_is(webhook($port,'release','delivery-release-after-poll','release'),200,'already seen'));
 my$broadcast=exchange($port,'GET','/broadcast.json',{},'');my$broadcast_doc=eval{decode_json($broadcast->{body})};
 record_check('hook-first.broadcast-surface',$broadcast->{status}==200&&$broadcast_doc&&$broadcast_doc->{pending_events}==3&&$broadcast_doc->{enqueued}==3&&$broadcast_doc->{configured_targets}==1);
 record_check('hook-first.restart-server-exit',wait_server()==0);

 my$state_a_doc=state_document($state_a);my@mode_a=stat($state_a);
 record_check('hook-first.state-mode',@mode_a&&($mode_a[2]&07777)==0600);
 record_check('hook-first.queue-persisted',@{$state_a_doc->{pending}||[]}==3&&@{$state_a_doc->{history}||[]}==3);
 record_check('hook-first.target-persisted',targets_are_epiknet([map{$_->{targets}}@{$state_a_doc->{pending}||[]} ]));
 record_check('hook-first.counters-persisted',$state_a_doc->{stats}{hook_valid}==3&&$state_a_doc->{stats}{hook_dupe}==2&&$state_a_doc->{stats}{poll_new}==3&&$state_a_doc->{stats}{broadcast_enqueued}==3);

 # Polling first: the initial page seeds event IDs without replay. A later
 # event is queued once and its matching webhook is suppressed after restart.
 my$state_b="$temp_dir/poll-first.json";
 my$baseline=run_reconciliation($state_b,'baseline','baseline');my$b0=$baseline->{doc};
 record_check('poll-first.baseline-cli-exit',$baseline->{rc}==0&&$b0);
 record_check('poll-first.baseline-no-replay',$b0&&$b0->{event_seen}==2&&$b0->{pending}==0&&$b0->{fingerprints}==0&&$b0->{poll_new}==0&&$b0->{broadcast_enqueued}==0);

 my$baseline_again=run_reconciliation($state_b,'baseline','incremental');my$b1=$baseline_again->{doc};
 record_check('poll-first.baseline-idempotent',$baseline_again->{rc}==0&&$b1&&$b1->{event_seen}==2&&$b1->{pending}==0&&$b1->{poll_new}==0);

 my$new_push=run_reconciliation($state_b,'new_push','incremental');my$b2=$new_push->{doc};
 record_check('poll-first.new-event-cli-exit',$new_push->{rc}==0&&$b2);
 record_check('poll-first.new-event-enqueued',$b2&&$b2->{event_seen}==3&&$b2->{pending}==1&&$b2->{fingerprints}==1&&$b2->{poll_new}==1&&$b2->{broadcast_enqueued}==1);
 record_check('poll-first.source-and-target',$b2&&join(',',@{$b2->{pending_sources}||[]})eq'poll'&&targets_are_epiknet($b2->{pending_targets}));

 $port=start_server($state_b,2);
 record_check('poll-first.webhook-replay-suppressed',response_is(webhook($port,'push','delivery-push-after-poll','push'),200,'already seen'));
 my$status=exchange($port,'GET','/status.json',{},'');my$status_doc=eval{decode_json($status->{body})};
 record_check('poll-first.status-surface',$status->{status}==200&&$status_doc&&$status_doc->{queue}==1&&$status_doc->{counters}{webhook}{valid}==1&&$status_doc->{counters}{webhook}{duplicates}==1);
 record_check('poll-first.server-exit',wait_server()==0);

 my$state_b_doc=state_document($state_b);my@mode_b=stat($state_b);
 record_check('poll-first.state-mode',@mode_b&&($mode_b[2]&07777)==0600);
 record_check('poll-first.queue-persisted',@{$state_b_doc->{pending}||[]}==1&&$state_b_doc->{pending}[0]{source}eq'poll'&&join(',',@{$state_b_doc->{pending}[0]{targets}||[]})eq'epiknet');
 record_check('poll-first.counters-persisted',$state_b_doc->{stats}{hook_valid}==1&&$state_b_doc->{stats}{hook_dupe}==1&&$state_b_doc->{stats}{poll_new}==1&&$state_b_doc->{stats}{broadcast_enqueued}==1);
 1;
};

if(!$ok){my$error=$@||'unknown reconciliation black-box failure';stop_server_hard();print STDERR $error}
if(-f$diagnostic_file){my$stderr=slurp($diagnostic_file);print STDERR $stderr if$stderr ne''}

my@failed=grep{!$_->[1]}@checks;my$passed=@checks-@failed;
print "IRC GitWatch reconciliation black-box: ".(!$ok||@failed?'FAILED':'OK')." ($passed/".scalar(@checks).")\n";
print 'failed checks: '.join(',',map{$_->[0]}@failed)."\n"if@failed;
exit(!$ok||@failed?1:0);
