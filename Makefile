PERL ?= perl

.PHONY: all check syntax selftest selftest-list test-targeted test-fast test-full config-check doctor install

all: check

syntax:
	$(PERL) -c irc-gitwatch.pl

selftest:
	$(PERL) irc-gitwatch.pl --selftest
	GITHUB_REPO=octocat/Hello-World GITHUB_ACCOUNT=octocat $(PERL) irc-gitwatch.pl --selftest
	GITHUB_REPO=octocat/Hello-World GITHUB_ACCOUNT= $(PERL) irc-gitwatch.pl --selftest

selftest-list:
	$(PERL) irc-gitwatch.pl --selftest-list

test-targeted:
	PERL='$(PERL)' sh ./scripts/test.sh --profile targeted --progress

test-fast:
	PERL='$(PERL)' sh ./scripts/test.sh --profile fast --progress

test-full:
	PERL='$(PERL)' sh ./scripts/test.sh --profile full --progress

config-check:
	$(PERL) irc-gitwatch.pl --config-check

check: test-full

doctor:
	$(PERL) irc-gitwatch.pl --doctor

install:
	sh ./scripts/install.sh
