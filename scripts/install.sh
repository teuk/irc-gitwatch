#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo 'Run this installer as root.' >&2
  exit 1
fi

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

perl -MIO::Socket::SSL -e 'exit 0' || {
  echo 'IO::Socket::SSL is missing. Install libio-socket-ssl-perl first.' >&2
  exit 1
}

if ! getent group irc-gitwatch >/dev/null 2>&1; then
  groupadd --system irc-gitwatch
fi
if ! getent passwd irc-gitwatch >/dev/null 2>&1; then
  useradd --system --gid irc-gitwatch --home-dir /var/lib/irc-gitwatch --shell /usr/sbin/nologin irc-gitwatch
fi

install -d -m 0755 /opt/irc-gitwatch
install -m 0755 "$project_dir/irc-gitwatch.pl" /opt/irc-gitwatch/irc-gitwatch.pl
install -m 0644 "$project_dir/systemd/irc-gitwatch.service" /etc/systemd/system/irc-gitwatch.service
install -d -o irc-gitwatch -g irc-gitwatch -m 0700 /var/lib/irc-gitwatch

if [ ! -e /etc/irc-gitwatch.env ]; then
  install -m 0600 "$project_dir/.env.example" /etc/irc-gitwatch.env
  echo 'Created /etc/irc-gitwatch.env; edit it before starting the service.'
else
  echo 'Kept existing /etc/irc-gitwatch.env unchanged.'
fi

systemctl daemon-reload

echo 'Installation complete.'
echo 'Next: edit /etc/irc-gitwatch.env'
echo 'Then: systemctl enable --now irc-gitwatch.service'
