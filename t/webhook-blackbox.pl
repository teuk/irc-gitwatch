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
my $secret='synthetic-local-webhook-secret';
my $fixture_dir='t/fixtures/webhooks';
my $temp_dir=tempdir('irc-gitwatch-webhook-XXXXXX',TMPDIR=>1,CLEANUP=>1);
my $stderr_file="$temp_dir/server.stderr";
my $state_file="$temp_dir/state.json";
my $expected_requests=29;
my $sent_requests=0;
my $server_pid=0;
my @checks;

sub record_check {
 my($name,$ok)=@_;push@checks,[$name,$ok?1:0];
}

sub fixture {
 my($name)=@_;my$path="$fixture_dir/$name.json";
 open my$fh,'<:raw',$path or die"cannot read $path: $!\n";local$/;my$body=<$fh>;close$fh;$body;
}

sub start_server {
 pipe(my$ready_r,my$ready_w)or die"pipe: $!\n";
 $server_pid=fork();die"fork: $!\n"unless defined$server_pid;
 if(!$server_pid){
  close$ready_r;
  open STDOUT,'>&',$ready_w or _exit(125);close$ready_w;
  open STDERR,'>:raw',$stderr_file or _exit(125);
  $ENV{GITHUB_REPO}=$repo;
  $ENV{GITHUB_TOKEN}='';
  $ENV{IRC_GITWATCH_TEST_MODE}=1;
  $ENV{GITHUB_WEBHOOK_SECRET}=$secret;
  $ENV{GITHUB_STATE_FILE}=$state_file;
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
  exec{$^X}$^X,'irc-gitwatch.pl','--webhook-test-server',$expected_requests or _exit(126);
 }
 close$ready_w;
 my$select=IO::Select->new($ready_r);
 die"webhook test server readiness timeout\n"unless$select->can_read(10);
 my$line=<$ready_r>;close$ready_r;
 die"invalid webhook test server readiness\n"unless defined$line&&$line=~/^READY (\d+)\s*$/;
 int($1);
}

sub stop_server_hard {
 return unless$server_pid;
 kill'KILL',$server_pid;waitpid($server_pid,0);$server_pid=0;
}
END{stop_server_hard()}

sub exchange {
 my($port,$method,$path,$headers,$body,$declared_length)=@_;
 $headers||={};$body=''unless defined$body;$sent_requests++;
 my$s=IO::Socket::INET->new(PeerAddr=>'127.0.0.1',PeerPort=>$port,Proto=>'tcp',Timeout=>5)
  or die"connect to webhook test server: $!\n";
 binmode$s,':raw';$s->autoflush(1);
 my$wire="$method $path HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n";
 my%h=%$headers;
 if(defined$declared_length){$h{'Content-Length'}=$declared_length}
 elsif($method eq'POST'||length$body){$h{'Content-Length'}=length$body}
 $wire.="$_: $h{$_}\r\n"for sort keys%h;$wire.="\r\n$body";
 my$off=0;while($off<length$wire){my$n=syswrite($s,$wire,length($wire)-$off,$off);die"request write failed\n"unless defined$n&&$n>0;$off+=$n}
 shutdown($s,1);
 my$response='';while(1){my$chunk='';my$n=sysread($s,$chunk,8192);last if defined$n&&$n==0;die"response read failed\n"unless defined$n;$response.=$chunk}
 close$s;
 my($head,$response_body)=split/\r\n\r\n/,$response,2;$response_body=''unless defined$response_body;
 my($status)=$head=~m{^HTTP/1\.[01]\s+(\d{3})\b};die"malformed HTTP response\n"unless$status;
 +{status=>int($status),head=>$head,body=>$response_body};
}

sub signed_webhook {
 my($port,$event,$delivery,$fixture_name,%opt)=@_;
 my$body=exists$opt{body}?$opt{body}:fixture($fixture_name);
 my$sign_body=exists$opt{sign_body}?$opt{sign_body}:$body;
 my%headers;
 $headers{'Content-Type'}=$opt{content_type}//'application/json'unless$opt{omit_content_type};
 $headers{'X-GitHub-Event'}=$event unless$opt{omit_event};
 $headers{'X-GitHub-Delivery'}=$delivery unless$opt{omit_delivery};
 unless($opt{omit_signature}){
  $headers{'X-Hub-Signature-256'}=$opt{bad_signature}?'sha256='.('0'x64):'sha256='.hmac_sha256_hex($sign_body,$secret);
 }
 exchange($port,'POST','/githubhook',\%headers,$body,undef);
}

sub response_check {
 my($name,$response,$status,$body_fragment)=@_;
 record_check($name,$response->{status}==$status&&(!defined$body_fragment||index($response->{body},$body_fragment)>=0));
}

my $ok=eval{
 my$port=start_server();

 response_check('http.livez',exchange($port,'GET','/livez',{},'',undef),200,"OK\n");
 my$initial=exchange($port,'GET','/status.json',{},'',undef);my$initial_json=eval{decode_json($initial->{body})};
 record_check('http.initial-status-json',$initial->{status}==200&&$initial_json&&$initial_json->{http_listener}{listening});

 response_check('webhook.ping',signed_webhook($port,'ping','delivery-ping','ping'),200,'pong');
 response_check('webhook.push-queued',signed_webhook($port,'push','delivery-push','push'),202,'queued');
 response_check('webhook.delivery-replay',signed_webhook($port,'push','delivery-push','push'),200,'duplicate');
 response_check('webhook.fingerprint-replay',signed_webhook($port,'push','delivery-push-fingerprint','push'),200,'already seen');
 response_check('webhook.bad-signature',signed_webhook($port,'issues','delivery-bad-signature','issues',bad_signature=>1),401,'bad signature');
 response_check('webhook.missing-signature',signed_webhook($port,'issues','delivery-missing-signature','issues',omit_signature=>1),401,'bad signature');
 my$original=fixture('ping');
 response_check('webhook.altered-body',signed_webhook($port,'ping','delivery-altered','ping',body=>'{"zen":"tampered"}',sign_body=>$original),401,'bad signature');
 response_check('webhook.missing-event-header',signed_webhook($port,'issues','delivery-missing-event','issues',omit_event=>1),400,'missing headers');
 response_check('webhook.missing-delivery-header',signed_webhook($port,'issues','delivery-unused','issues',omit_delivery=>1),400,'missing headers');
 response_check('webhook.invalid-json',signed_webhook($port,'issues','delivery-invalid-json','issues',body=>'{"broken":'),400,'invalid JSON');
 response_check('webhook.wrong-repository',signed_webhook($port,'issues','delivery-wrong-repo','wrong_repository'),401,'wrong repository');
 response_check('webhook.missing-repository',signed_webhook($port,'issues','delivery-missing-repo','missing_repository'),401,'wrong repository');
 response_check('webhook.unsupported-media-type',signed_webhook($port,'issues','delivery-text-plain','issues',content_type=>'text/plain'),415,'application/json required');
 response_check('webhook.missing-content-type',signed_webhook($port,'issues','delivery-no-media','issues',omit_content_type=>1),415,'application/json required');
 response_check('webhook.issue-queued',signed_webhook($port,'issues','delivery-issue','issues',content_type=>'application/vnd.github+json; charset=utf-8'),202,'queued');
 response_check('webhook.pull-request-queued',signed_webhook($port,'pull_request','delivery-pr','pull_request'),202,'queued');
 response_check('webhook.release-queued',signed_webhook($port,'release','delivery-release','release'),202,'queued');
 response_check('webhook.workflow-failure-queued',signed_webhook($port,'workflow_run','delivery-workflow','workflow_run'),202,'queued');
 response_check('webhook.private-event-hidden',signed_webhook($port,'secret_scanning_alert','delivery-private','private_event'),202,'accepted but hidden');
 response_check('webhook.unknown-event-hidden',signed_webhook($port,'synthetic_unknown_event','delivery-unknown','unknown_event'),202,'accepted but hidden');
 response_check('http.wrong-webhook-path',exchange($port,'POST','/wrong',{'Content-Type'=>'application/json'},'{}',undef),404,'not found');
 response_check('http.method-rejected',exchange($port,'PUT','/githubhook',{},'',undef),405,'POST only');
 response_check('http.oversized-body',exchange($port,'POST','/githubhook',{'Content-Type'=>'application/json'},'',1025),413,'rejected');

 my$dashboard=exchange($port,'GET','/?api=dashboard',{},'',undef);my$dashboard_json=eval{decode_json($dashboard->{body})};
 record_check('surface.dashboard-json',$dashboard->{status}==200&&$dashboard_json&&ref($dashboard_json->{recent_activity})eq'ARRAY'&&@{$dashboard_json->{recent_activity}}==5);
 my$broadcast=exchange($port,'GET','/broadcast.json',{},'',undef);my$broadcast_json=eval{decode_json($broadcast->{body})};
 record_check('surface.broadcast-queue',$broadcast->{status}==200&&$broadcast_json&&$broadcast_json->{configured_targets}==1&&$broadcast_json->{pending_events}==5&&$broadcast_json->{enqueued}==5);
 my$metrics=exchange($port,'GET','/metrics',{},'',undef);
 record_check('surface.prometheus-counters',$metrics->{status}==200&&$metrics->{body}=~/githubwatch_webhook_received_total 20\n/&&$metrics->{body}=~/githubwatch_webhook_valid_total 9\n/&&$metrics->{body}=~/githubwatch_webhook_duplicate_total 2\n/&&$metrics->{body}=~/githubwatch_webhook_suppressed_total 2\n/&&$metrics->{body}=~/githubwatch_webhook_rejected_total 10\n/&&$metrics->{body}=~/githubwatch_webhook_bad_content_type_total 2\n/&&$metrics->{body}=~/githubwatch_webhook_wrong_repo_total 2\n/&&$metrics->{body}=~/githubwatch_webhook_read_rejected_total 1\n/&&$metrics->{body}=~/githubwatch_broadcast_enqueued_total 5\n/);
 my$final=exchange($port,'GET','/status.json',{},'',undef);my$final_json=eval{decode_json($final->{body})};my$w=$final_json&&$final_json->{counters}{webhook};
 record_check('surface.status-counters',$final->{status}==200&&$w&&$w->{received}==20&&$w->{valid}==9&&$w->{duplicates}==2&&$w->{suppressed}==2&&$w->{rejected}==10&&$w->{bad_signature}==3&&$w->{bad_content_type}==2&&$w->{missing_headers}==2&&$w->{invalid_json}==1&&$w->{wrong_repo}==2&&$w->{read_rejected}==1&&$final_json->{queue}==5);

 record_check('harness.request-cardinality',$sent_requests==$expected_requests);
 waitpid($server_pid,0);my$server_rc=$?>>8;$server_pid=0;
 record_check('harness.server-clean-exit',$server_rc==0);
 1;
};

if(!$ok){my$error=$@||'unknown black-box failure';stop_server_hard();print STDERR $error}
if(-f$stderr_file){open my$fh,'<:raw',$stderr_file;local$/;my$stderr=<$fh>;close$fh;print STDERR $stderr if defined$stderr&&$stderr ne''}

my@failed=grep{!$_->[1]}@checks;
my$passed=@checks-@failed;
print "IRC GitWatch webhook black-box: ".(!$ok||@failed?'FAILED':'OK')." ($passed/".scalar(@checks).")\n";
print 'failed checks: '.join(',',map{$_->[0]}@failed)."\n"if@failed;
exit(!$ok||@failed?1:0);
