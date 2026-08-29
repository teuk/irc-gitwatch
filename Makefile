PERL ?= perl

.PHONY: all check syntax selftest config-check doctor install

all: check

syntax:
	$(PERL) -c irc-gitwatch.pl

selftest:
	$(PERL) irc-gitwatch.pl --selftest
	GITHUB_REPO=octocat/Hello-World GITHUB_ACCOUNT=octocat $(PERL) irc-gitwatch.pl --selftest
	GITHUB_REPO=octocat/Hello-World GITHUB_ACCOUNT= $(PERL) irc-gitwatch.pl --selftest

config-check:
	$(PERL) irc-gitwatch.pl --config-check

check:
	sh ./scripts/check.sh

doctor:
	$(PERL) irc-gitwatch.pl --doctor

install:
	sh ./scripts/install.sh
