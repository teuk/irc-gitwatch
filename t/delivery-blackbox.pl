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
 $ENV{IRC_ICON_MODE}='ascii';
}

sub run_step {
 my($phase,$wire_dir)=@_;make_path($wire_dir,{mode=>0700});
 pipe(my$out_r,my$out_w)or die"stdout pipe: $!\n";pipe(my$err_r,my$err_w)or die"stderr pipe: $!\n";
 my$pid=fork();die"fork: $!\n"unless defined$pid;
 if(!$pid){
  close$out_r;close$err_r;open STDOUT,'>&',$out_w or _exit(125);open STDERR,'>&',$err_w or _exit(125);close$out_w;close$err_w;
  configure_environment();
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
 my($map)=@_;return 0 unless ref($map)eq'HASH'&&keys(%$map)==4;
 for my$v(values%$map){return 0 unless$v==1}1;
}

my$ok=eval{
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
 1;
};

print STDERR($@||'unknown delivery black-box failure')unless$ok;
my@failed=grep{!$_->[1]}@checks;my$passed=@checks-@failed;
print "IRC GitWatch delivery black-box: ".(!$ok||@failed?'FAILED':'OK')." ($passed/".scalar(@checks).")\n";
print 'failed checks: '.join(',',map{$_->[0]}@failed)."\n"if@failed;
exit(!$ok||@failed?1:0);
