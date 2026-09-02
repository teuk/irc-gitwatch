#!/usr/bin/env perl
use strict;
use warnings;

use Digest::SHA qw(sha256_hex);
use File::Temp qw(tempdir);
use JSON::PP qw(decode_json);
use POSIX qw(_exit);

my$temp_dir=tempdir('irc-gitwatch-state-recovery-XXXXXX',TMPDIR=>1,CLEANUP=>1);
my$state_file="$temp_dir/state.json";my$backup_file="$state_file.bak";my@checks;

sub record_check { my($name,$ok)=@_;push@checks,[$name,$ok?1:0] }
sub slurp {
 my($path)=@_;return''unless-f$path;open my$fh,'<:raw',$path or die"cannot read $path: $!\n";
 local$/;my$raw=<$fh>;close$fh;$raw;
}
sub write_raw {
 my($path,$raw)=@_;open my$fh,'>:raw',$path or die"cannot write $path: $!\n";
 print{$fh}$raw or die"cannot populate $path: $!\n";close$fh or die"cannot close $path: $!\n";
}
sub json_document {
 my($path)=@_;my$d=eval{decode_json(slurp($path))};$d&&ref($d)eq'HASH'?$d:undef;
}
sub mode_is_0600 {
 my($path)=@_;my@s=stat($path);@s&&($s[2]&07777)==0600;
}
sub configure_environment {
 $ENV{GITHUB_REPO}='octocat/Hello-World';$ENV{GITHUB_TOKEN}='';$ENV{IRC_GITWATCH_TEST_MODE}=1;
 $ENV{GITHUB_STATE_FILE}=$state_file;$ENV{STATE_BACKUP_ENABLED}=1;$ENV{GITHUB_POLL_ENABLED}=0;
 $ENV{GITHUB_ACTIONS_ENABLED}=0;$ENV{GITHUB_TRAFFIC_ENABLED}=0;$ENV{GITHUB_ACCOUNT_ENABLED}=0;$ENV{RSS_ENABLED}=0;
 $ENV{EPIKNET_ENABLED}=1;$ENV{IRC_CHANNEL}='#epiknet-test';$ENV{LIBERA_ENABLED}=1;$ENV{LIBERA_CHANNEL}='#libera-test';
 $ENV{UNDERNET_ENABLED}=1;$ENV{UNDERNET_CHANNEL_PRIMARY}='#under-primary';$ENV{UNDERNET_CHANNEL_SECONDARY}='#under-secondary';
 $ENV{IRC_ICON_MODE}='ascii';
}
sub run_step {
 my($phase)=@_;pipe(my$out_r,my$out_w)or die"stdout pipe: $!\n";pipe(my$err_r,my$err_w)or die"stderr pipe: $!\n";
 my$pid=fork();die"fork: $!\n"unless defined$pid;
 if(!$pid){
  close$out_r;close$err_r;open STDOUT,'>&',$out_w or _exit(125);open STDERR,'>&',$err_w or _exit(125);close$out_w;close$err_w;
  configure_environment();exec{$^X}$^X,'irc-gitwatch.pl','--state-recovery-test-step',$phase or _exit(126);
 }
 close$out_w;close$err_w;local$/;my$out=<$out_r>;my$err=<$err_r>;close$out_r;close$err_r;
 waitpid($pid,0);my$rc=$?>>8;my$doc=eval{decode_json($out//'')};
 +{rc=>$rc,out=>$out//'',err=>$err//'',doc=>$doc&&ref($doc)eq'HASH'?$doc:undef};
}
sub core_state_ok {
 my($s)=@_;return 0 unless ref($s)eq'HASH';
 $s->{pending}==1&&$s->{history}==1&&$s->{item_source}eq'hook'&&$s->{item_counted}==1&&
 @{$s->{item_targets}||[]}==4&&@{$s->{item_delivered}||[]}==2&&$s->{audit_status}eq'pending'&&$s->{audit_delivered}==2&&
 $s->{event_seen}&&$s->{delivery_seen}&&$s->{fingerprint_seen}&&$s->{history_marker}==1&&
 $s->{hook_sent}==1&&$s->{broadcast_enqueued}==1;
}

my$ok=eval{
 my$seed=run_step('seed');my$s=$seed->{doc};
 record_check('seed.exit',$seed->{rc}==0&&$s&&$seed->{err}eq'');
 record_check('seed.core-state',core_state_ok($s));
 record_check('seed.primary-valid',$s&&$s->{primary}eq'ok'&&$s->{primary_version}==11&&mode_is_0600($state_file));
 record_check('seed.backup-valid',$s&&$s->{backup}eq'ok'&&$s->{backup_version}==11&&mode_is_0600($backup_file));
 record_check('seed.backup-recorded',$s&&$s->{state_backups}==1&&$s->{state_recoveries}==0);
 my$backup_raw=slurp($backup_file);my$backup_sha=sha256_hex($backup_raw);my$backup=json_document($backup_file);
 record_check('seed.backup-core',$backup&&@{$backup->{pending}||[]}==1&&keys(%{$backup->{fingerprints}||{}})==1&&keys(%{$backup->{deliveries}||{}})==1);

 write_raw($state_file,"{\"state_version\":11,\"pending\":");
 record_check('corrupt.primary-invalid',!json_document($state_file));
 record_check('corrupt.backup-unchanged',sha256_hex(slurp($backup_file))eq$backup_sha);
 my$corrupt=run_step('recover');my$c=$corrupt->{doc};my$cb=$c&&$c->{before};my$ca=$c&&$c->{after};
 record_check('corrupt.exit',$corrupt->{rc}==0&&$c);
 record_check('corrupt.warning',$corrupt->{err}=~/Primary state invalid JSON; recovered from backup/);
 record_check('corrupt.refused-backup-poison',$corrupt->{err}=~/State backup skipped: primary invalid JSON/&&sha256_hex(slurp($backup_file))eq$backup_sha);
 record_check('corrupt.loaded-backup',$cb&&$cb->{loaded_from}eq'backup'&&$cb->{primary}eq'invalid JSON'&&$cb->{backup}eq'ok'&&$cb->{state_recoveries}==1);
 record_check('corrupt.core-restored-before-save',core_state_ok($cb));
 record_check('corrupt.atomic-repair',$ca&&$ca->{save_ok}&&$ca->{primary}eq'ok'&&$ca->{backup}eq'ok'&&$ca->{primary_version}==11&&mode_is_0600($state_file));
 record_check('corrupt.core-restored-after-save',core_state_ok($ca));
 my$repaired=json_document($state_file);
 record_check('corrupt.recovery-persisted',$repaired&&$repaired->{stats}{state_recoveries}==1&&@{$repaired->{pending}||[]}==1);

 unlink$state_file or die"cannot remove repaired primary: $!\n";
 record_check('missing.primary-removed',!-e$state_file&&json_document($backup_file));
 my$missing=run_step('recover');my$m=$missing->{doc};my$mb=$m&&$m->{before};my$ma=$m&&$m->{after};
 record_check('missing.exit',$missing->{rc}==0&&$m);
 record_check('missing.warning',$missing->{err}=~/Primary state missing; recovered from backup/);
 record_check('missing.loaded-backup',$mb&&$mb->{loaded_from}eq'backup'&&$mb->{primary}eq'missing'&&$mb->{backup}eq'ok'&&$mb->{state_recoveries}==1);
 record_check('missing.core-restored-before-save',core_state_ok($mb));
 record_check('missing.atomic-repair',$ma&&$ma->{save_ok}&&$ma->{primary}eq'ok'&&$ma->{backup}eq'ok'&&$ma->{primary_version}==11&&mode_is_0600($state_file));
 record_check('missing.core-restored-after-save',core_state_ok($ma));
 record_check('missing.backup-unchanged',sha256_hex(slurp($backup_file))eq$backup_sha&&mode_is_0600($backup_file));
 my$final=json_document($state_file);
 record_check('final.state-contract',$final&&$final->{state_version}==11&&$final->{stats}{state_recoveries}==1&&@{$final->{pending}||[]}==1&&@{$final->{history}||[]}==1);
 1;
};

print STDERR($@||'unknown state recovery black-box failure')unless$ok;
my@failed=grep{!$_->[1]}@checks;my$passed=@checks-@failed;
print "IRC GitWatch state recovery black-box: ".(!$ok||@failed?'FAILED':'OK')." ($passed/".scalar(@checks).")\n";
print 'failed checks: '.join(',',map{$_->[0]}@failed)."\n"if@failed;
exit(!$ok||@failed?1:0);
