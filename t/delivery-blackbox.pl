#!/usr/bin/env perl
use strict;
use warnings;

use File::Path qw(make_path);
use File::Temp qw(tempdir);
use JSON::PP qw(decode_json);
use POSIX qw(_exit);

my$temp_dir=tempdir('irc-gitwatch-delivery-XXXXXX',TMPDIR=>1,CLEANUP=>1);
my$state_file="$temp_dir/state.json";
my@checks;

sub record_check {
 my($name,$ok)=@_;push@checks,[$name,$ok?1:0];
}

sub slurp {
 my($path)=@_;return''unless-f$path;open my$fh,'<:raw',$path or die"cannot read $path: $!\n";
 local$/;my$raw=<$fh>;close$fh;$raw;
}

sub state_document {
 my$doc=eval{decode_json(slurp($state_file))};die"invalid delivery state JSON\n"unless$doc&&ref($doc)eq'HASH';$doc;
}

sub configure_environment {
 $ENV{GITHUB_REPO}='octocat/Hello-World';
 $ENV{GITHUB_TOKEN}='';
 $ENV{IRC_GITWATCH_TEST_MODE}=1;
 $ENV{GITHUB_STATE_FILE}=$state_file;
 $ENV{STATE_BACKUP_ENABLED}=0;
 $ENV{GITHUB_POLL_ENABLED}=0;
 $ENV{GITHUB_ACTIONS_ENABLED}=0;
 $ENV{GITHUB_TRAFFIC_ENABLED}=0;
 $ENV{GITHUB_ACCOUNT_ENABLED}=0;
 $ENV{RSS_ENABLED}=0;
 $ENV{EPIKNET_ENABLED}=1;
 $ENV{IRC_CHANNEL}='#epiknet-test';
 $ENV{LIBERA_ENABLED}=1;
 $ENV{LIBERA_CHANNEL}='#libera-test';
 $ENV{UNDERNET_ENABLED}=1;
 $ENV{UNDERNET_CHANNEL_PRIMARY}='#under-primary';
 $ENV{UNDERNET_CHANNEL_SECONDARY}='#under-secondary';
 $ENV{IRC_REQUIRED_TARGETS}='epiknet,libera,undernet:#under-primary,undernet:#under-secondary';
 $ENV{IRC_ICON_MODE}='ascii';
}

sub run_config_check {
 my($epiknet_enabled)=@_;
 pipe(my$out_r,my$out_w)or die"stdout pipe: $!\n";pipe(my$err_r,my$err_w)or die"stderr pipe: $!\n";
 my$pid=fork();die"fork: $!\n"unless defined$pid;
 if(!$pid){
  close$out_r;close$err_r;open STDOUT,'>&',$out_w or _exit(125);open STDERR,'>&',$err_w or _exit(125);close$out_w;close$err_w;
  configure_environment();$ENV{EPIKNET_ENABLED}=$epiknet_enabled?1:0;
  exec{$^X}$^X,'irc-gitwatch.pl','--config-check' or _exit(126);
 }
 close$out_w;close$err_w;local$/;my$out=<$out_r>;my$err=<$err_r>;close$out_r;close$err_r;
 waitpid($pid,0);+{rc=>$?>>8,out=>$out//'',err=>$err//''};
}

sub run_three_target_config_check {
 pipe(my$out_r,my$out_w)or die"stdout pipe: $!\n";pipe(my$err_r,my$err_w)or die"stderr pipe: $!\n";
 my$pid=fork();die"fork: $!\n"unless defined$pid;
 if(!$pid){
  close$out_r;close$err_r;open STDOUT,'>&',$out_w or _exit(125);open STDERR,'>&',$err_w or _exit(125);close$out_w;close$err_w;
  configure_environment();$ENV{UNDERNET_CHANNEL_SECONDARY}='';
  $ENV{IRC_REQUIRED_TARGETS}='epiknet,libera,undernet:#under-primary';
  exec{$^X}$^X,'irc-gitwatch.pl','--config-check' or _exit(126);
 }
 close$out_w;close$err_w;local$/;my$out=<$out_r>;my$err=<$err_r>;close$out_r;close$err_r;
 waitpid($pid,0);+{rc=>$?>>8,out=>$out//'',err=>$err//''};
}

sub run_step {
 my($phase,$wire_dir,$three_targets)=@_;make_path($wire_dir,{mode=>0700});
 pipe(my$out_r,my$out_w)or die"stdout pipe: $!\n";pipe(my$err_r,my$err_w)or die"stderr pipe: $!\n";
 my$pid=fork();die"fork: $!\n"unless defined$pid;
 if(!$pid){
  close$out_r;close$err_r;open STDOUT,'>&',$out_w or _exit(125);open STDERR,'>&',$err_w or _exit(125);close$out_w;close$err_w;
  configure_environment();
  if($three_targets){
   $ENV{UNDERNET_CHANNEL_SECONDARY}='';
   $ENV{IRC_REQUIRED_TARGETS}='epiknet,libera,undernet:#under-primary';
  }
  exec{$^X}$^X,'irc-gitwatch.pl','--delivery-test-step',$phase,$wire_dir or _exit(126);
 }
 close$out_w;close$err_w;local$/;my$out=<$out_r>;my$err=<$err_r>;close$out_r;close$err_r;
 waitpid($pid,0);my$rc=$?>>8;my$doc=eval{decode_json($out//'')};
 +{rc=>$rc,out=>$out//'',err=>$err//'',doc=>$doc&&ref($doc)eq'HASH'?$doc:undef};
}

sub marker_count {
 my($text)=@_;my$n=0;$n++while$text=~/IRC-GITWATCH-DELIVERY-RESUME/g;$n;
}

sub sent_map_is_one {
 my($map,$expected)=@_;$expected//=4;return 0 unless ref($map)eq'HASH'&&keys(%$map)==$expected;
 for my$v(values%$map){return 0 unless$v==1}1;
}

my$ok=eval{
 my$contract_ok=run_config_check(1);my$contract_bad=run_config_check(0);
 record_check('contract.exact-four-targets',$contract_ok->{rc}==0&&$contract_ok->{err}=~/Configuration check: OK/);
 record_check('contract.missing-target-rejected',$contract_bad->{rc}==1&&$contract_bad->{err}=~/IRC_REQUIRED_TARGETS requires missing target epiknet/);
 my$three=run_three_target_config_check();
 record_check('contract.optional-secondary-disabled',$three->{rc}==0&&$three->{err}=~/Configuration check: OK/);
 record_check('contract.primary-id-preserved',$three->{out}=~/undernet=.*#under-primary as/&&$three->{out}!~/#under-secondary/);

 my$seed_dir="$temp_dir/seed";my$partial_dir="$temp_dir/partial";my$resume_dir="$temp_dir/resume";my$again_dir="$temp_dir/again";
 my$seed=run_step('seed',$seed_dir);my$s=$seed->{doc};
 record_check('seed.exit',$seed->{rc}==0&&$s);
 record_check('seed.queue-contract',$s&&$s->{pending}==1&&$s->{history}==1&&$s->{broadcast_enqueued}==1&&$s->{delivery_attempts}==0);
 record_check('seed.target-snapshot',$s&&@{$s->{item_targets}||[]}==4&&$s->{item_source}eq'hook'&&$s->{audit_status}eq'pending');
 my@state_mode=stat($state_file);record_check('seed.state-mode',@state_mode&&($state_mode[2]&07777)==0600);

 my$partial=run_step('partial',$partial_dir);my$p=$partial->{doc};
 record_check('partial.exit',$partial->{rc}==0&&$p);
 record_check('partial.expected-disconnect',$partial->{err}=~/\[WARN\] \[Libera\] IRC write failed/);
 record_check('partial.queue-retained',$p&&$p->{pending}==1&&$p->{item_counted}==1&&@{$p->{item_delivered}||[]}==2&&$p->{audit_status}eq'pending'&&$p->{audit_delivered}==2);
 record_check('partial.attempt-counters',$p&&$p->{delivery_attempts}==3&&$p->{delivery_failures}==1&&$p->{hook_sent}==1&&$p->{broadcast_completed}==0);
 my$epi_partial=slurp("$partial_dir/epiknet.partial.wire");my$under_partial=slurp("$partial_dir/undernet.partial.wire");
 record_check('partial.epiknet-once',marker_count($epi_partial)==1&&$epi_partial=~/PRIVMSG #epiknet-test :/);
 record_check('partial.undernet-primary-once',marker_count($under_partial)==1&&$under_partial=~/PRIVMSG #under-primary :/&&$under_partial!~/PRIVMSG #under-secondary :/);

 my$mid=state_document();my$item=$mid->{pending}[0];
 record_check('partial.state-targets',@{$item->{targets}||[]}==4&&keys(%{$item->{delivered}||{}})==2&&$item->{source}eq'hook');
 record_check('partial.audit-pending',$mid->{broadcast_history}[0]{status}eq'pending'&&scalar(grep{$_>0}values%{$mid->{broadcast_history}[0]{targets}})==2);

 my$resume=run_step('resume',$resume_dir);my$r=$resume->{doc};
 record_check('resume.exit',$resume->{rc}==0&&$r&&$resume->{err}eq'');
 record_check('resume.queue-complete',$r&&$r->{pending}==0&&$r->{broadcast_completed}==1&&$r->{audit_status}eq'complete'&&$r->{audit_delivered}==4);
 record_check('resume.counter-contract',$r&&$r->{delivery_attempts}==5&&$r->{delivery_failures}==1&&$r->{hook_sent}==1&&sent_map_is_one($r->{delivery_sent}));
 my$epi_resume=slurp("$resume_dir/epiknet.resume.wire");my$libera_resume=slurp("$resume_dir/libera.resume.wire");my$under_resume=slurp("$resume_dir/undernet.resume.wire");
 record_check('resume.no-epiknet-duplicate',$epi_resume eq'');
 record_check('resume.libera-missing-only',marker_count($libera_resume)==1&&$libera_resume=~/PRIVMSG #libera-test :/);
 record_check('resume.undernet-secondary-only',marker_count($under_resume)==1&&$under_resume=~/PRIVMSG #under-secondary :/&&$under_resume!~/PRIVMSG #under-primary :/);
 record_check('resume.exact-total-fanout',marker_count($epi_partial.$under_partial.$epi_resume.$libera_resume.$under_resume)==4);

 my$final=state_document();my$history=$final->{broadcast_history}[0];
 record_check('resume.state-complete',@{$final->{pending}||[]}==0&&$history->{status}eq'complete'&&scalar(grep{$_>0}values%{$history->{targets}})==4);
 record_check('resume.delivery-stats',scalar(keys%{$final->{delivery_stats}||{}})==4&&!grep{int($_->{sent}||0)!=1}values%{$final->{delivery_stats}});

 my$again=run_step('resume',$again_dir);my$a=$again->{doc};
 record_check('idempotent.exit',$again->{rc}==0&&$a&&$again->{err}eq'');
 record_check('idempotent.counters',$a&&$a->{pending}==0&&$a->{broadcast_completed}==1&&$a->{delivery_attempts}==5&&$a->{delivery_failures}==1&&$a->{hook_sent}==1);
 record_check('idempotent.no-wire',slurp("$again_dir/epiknet.resume.wire")eq''&&slurp("$again_dir/libera.resume.wire")eq''&&slurp("$again_dir/undernet.resume.wire")eq'');

 # A server-side ERR_CANNOTSENDTOCHAN arrives after the socket write. The
 # secondary target must remain pending and be the only target retried after a
 # fresh process starts.
 $state_file="$temp_dir/reject-state.json";
 my$reject_seed=run_step('seed',"$temp_dir/reject-seed");
 record_check('reject.seed',$reject_seed->{rc}==0&&$reject_seed->{doc}&&$reject_seed->{doc}{pending}==1);
 my$reject_dir="$temp_dir/reject";my$reject=run_step('reject-secondary',$reject_dir);my$j=$reject->{doc};
 record_check('reject.exit',$reject->{rc}==0&&$j);
 record_check('reject.numeric-observed',$reject->{err}=~/delivery to #under-secondary rejected \(numeric 404\)/);
 record_check('reject.queue-retained',$j&&$j->{pending}==1&&@{$j->{item_delivered}||[]}==3&&$j->{audit_status}eq'pending'&&$j->{audit_delivered}==3&&$j->{awaiting}==0);
 record_check('reject.counters',$j&&$j->{delivery_attempts}==4&&$j->{delivery_failures}==1&&$j->{delivery_rejected}==1&&$j->{broadcast_completed}==0);
 record_check('reject.target-error',$j&&($j->{target_errors}{'undernet:#under-secondary'}||'')=~/IRC 404/);
 my$reject_under=slurp("$reject_dir/undernet.reject-secondary.wire");
 record_check('reject.secondary-attempted-once',marker_count($reject_under)==2&&$reject_under=~/PRIVMSG #under-primary :/&&$reject_under=~/PRIVMSG #under-secondary :/);

 my$retry_dir="$temp_dir/retry";my$retry=run_step('resume',$retry_dir);my$y=$retry->{doc};
 record_check('reject.retry-exit',$retry->{rc}==0&&$y&&$retry->{err}eq'');
 record_check('reject.retry-complete',$y&&$y->{pending}==0&&$y->{broadcast_completed}==1&&$y->{audit_status}eq'complete'&&$y->{audit_delivered}==4);
 record_check('reject.retry-counters',$y&&$y->{delivery_attempts}==5&&$y->{delivery_failures}==1&&$y->{delivery_rejected}==1&&$y->{hook_sent}==1&&sent_map_is_one($y->{delivery_sent}));
 record_check('reject.retry-secondary-only',slurp("$retry_dir/epiknet.resume.wire")eq''&&slurp("$retry_dir/libera.resume.wire")eq''&&marker_count(slurp("$retry_dir/undernet.resume.wire"))==1&&slurp("$retry_dir/undernet.resume.wire")=~/PRIVMSG #under-secondary :/&&slurp("$retry_dir/undernet.resume.wire")!~/PRIVMSG #under-primary :/);

 # A deployment may intentionally retire an optional channel while a saved
 # queue record still names it. If every target that remains configured was
 # already acknowledged, startup must complete the record without replaying
 # another target or leaving the queue permanently blocked.
 $state_file="$temp_dir/migration-state.json";
 my$migration_seed=run_step('seed',"$temp_dir/migration-seed");
 record_check('migration.seed',$migration_seed->{rc}==0&&$migration_seed->{doc}&&$migration_seed->{doc}{pending}==1);
 my$migration_reject=run_step('reject-secondary',"$temp_dir/migration-reject");my$m0=$migration_reject->{doc};
 record_check('migration.reject-prerequisite',$migration_reject->{rc}==0&&$m0&&$m0->{pending}==1&&$m0->{audit_delivered}==3&&$m0->{delivery_rejected}==1);
 my$migration_before=state_document();
 record_check('migration.persisted-four-target-contract',@{$migration_before->{pending}[0]{targets}||[]}==4&&scalar(grep{$_>0}values%{$migration_before->{broadcast_history}[0]{targets}})==3);
 my$migration_dir="$temp_dir/migration-three";my$migration=run_step('resume',$migration_dir,1);my$m=$migration->{doc};
 record_check('migration.exit',$migration->{rc}==0&&$m&&$migration->{err}eq'');
 record_check('migration.queue-reconciled',$m&&$m->{pending}==0&&$m->{broadcast_completed}==1);
 record_check('migration.audit-truth',$m&&$m->{audit_status}eq'complete'&&$m->{audit_delivered}==3&&@{$m->{audit_targets}||[]}==4);
 record_check('migration.delivery-stats',$m&&sent_map_is_one($m->{delivery_sent},3));
 record_check('migration.no-replay',slurp("$migration_dir/epiknet.resume.wire")eq''&&slurp("$migration_dir/libera.resume.wire")eq''&&slurp("$migration_dir/undernet.resume.wire")eq'');
 record_check('migration.primary-id-preserved',$m&&exists($m->{delivery_sent}{'undernet:#under-primary'})&&!exists($m->{delivery_sent}{'undernet:#under-secondary'}));

 # Startup announcements use the same delayed truth model. A rejected
 # secondary-channel announcement is retried without duplicating the primary.
 $state_file="$temp_dir/startup-state.json";
 my$startup_dir="$temp_dir/startup";my$startup=run_step('startup-reject',$startup_dir);my$u=$startup->{doc};
 record_check('startup.reject-exit',$startup->{rc}==0&&$u);
 record_check('startup.reject-observed',$startup->{err}=~/delivery to #under-secondary rejected \(numeric 404\)/&&$u->{delivery_rejected}==1);
 record_check('startup.retry-settled',$u&&$u->{startup_sent}{'undernet:#under-primary'}==1&&$u->{startup_sent}{'undernet:#under-secondary'}==1&&!$u->{startup_pending}{'undernet:#under-primary'}&&!$u->{startup_pending}{'undernet:#under-secondary'}&&($u->{target_errors}{'undernet:#under-secondary'}||'')eq'');
 my$startup_wire=slurp("$startup_dir/undernet.startup-reject.wire");
 my$primary_count=()=$startup_wire=~/PRIVMSG #under-primary :/g;my$secondary_count=()=$startup_wire=~/PRIVMSG #under-secondary :/g;
 record_check('startup.retry-exact-wire',$primary_count==1&&$secondary_count==2);
 my@secondary_lines=grep{/^PRIVMSG #under-secondary :/}split/\r?\n/,$startup_wire;
 record_check('startup.retry-is-plain',@secondary_lines==2&&$secondary_lines[0]=~/[\x02\x03\x0f\x16\x1d\x1f]/&&$secondary_lines[1]!~/[\x02\x03\x0f\x16\x1d\x1f]/);

 # If the server also rejects the plain retry, do not manufacture success.
 # Keep the target degraded and leave the successful primary untouched.
 $state_file="$temp_dir/startup-double-state.json";
 my$double_dir="$temp_dir/startup-double";my$double=run_step('startup-double-reject',$double_dir);my$v=$double->{doc};
 record_check('startup.double-reject-exit',$double->{rc}==0&&$v);
 record_check('startup.double-reject-observed',$double->{err}=~/formatted delivery to #under-secondary rejected/&&$double->{err}=~/delivery to #under-secondary rejected/&&$v->{delivery_rejected}==2);
 record_check('startup.double-reject-honest',$v&&$v->{startup_sent}{'undernet:#under-primary'}==1&&!$v->{startup_sent}{'undernet:#under-secondary'}&&($v->{target_errors}{'undernet:#under-secondary'}||'')=~/IRC 404/);
 my$double_wire=slurp("$double_dir/undernet.startup-double-reject.wire");
 my@double_secondary=grep{/^PRIVMSG #under-secondary :/}split/\r?\n/,$double_wire;
 record_check('startup.double-reject-exact-wire',@double_secondary==2&&$double_secondary[0]=~/[\x02\x03\x0f\x16\x1d\x1f]/&&$double_secondary[1]!~/[\x02\x03\x0f\x16\x1d\x1f]/);
 1;
};

print STDERR($@||'unknown delivery black-box failure')unless$ok;
my@failed=grep{!$_->[1]}@checks;my$passed=@checks-@failed;
print "IRC GitWatch delivery black-box: ".(!$ok||@failed?'FAILED':'OK')." ($passed/".scalar(@checks).")\n";
print 'failed checks: '.join(',',map{$_->[0]}@failed)."\n"if@failed;
exit(!$ok||@failed?1:0);
