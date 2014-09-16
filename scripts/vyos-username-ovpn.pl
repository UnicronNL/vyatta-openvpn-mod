#!/usr/bin/perl
#
# Module: vyos-username-ovpn.pl
#
# **** License ****
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# This code was originally developed by Vyos maintainers.
# All Rights Reserved.
#
# Author: Kim Hagen
# Date: September 2014
# Description: Script to configure openvpn local users
#
# **** End License ****
#

use Getopt::Long;
use POSIX;

use lib "/opt/vyatta/share/perl5/";
use Vyatta::Config;
use Vyatta::Interface;

use strict;
use warnings;

my ($set_user, $tun);
my ($pid, $exists) = undef;

sub usage {
  print <<EOF;
Usage:
  $0 --set_user --tun <tunnel>
EOF
  exit 1;
}

sub configure_users {
  my $config = new Vyatta::Config;
  my $iftype = "interfaces openvpn";
  my $passwdCommand = "/usr/bin/ovpnauth";
  my $passwdDB = "/opt/vyatta/etc/openvpn/plugin/users${tun}.db";
  my $pidfile = "/var/run/openvpn-${tun}.pid";

  if (-e $pidfile) {
    $pid= `cat $pidfile`;
    $exists = kill 0, $pid;
  }

  $config->setLevel("$iftype $tun server authentication local username");
  my @users = $config->listNodes();

  unlink $passwdDB;
  foreach my $user(@users) {
    my $password = $config->returnValue("$user password");
    system("sudo $passwdCommand -a -u $user -p $password $passwdDB >/dev/null  2>&1");
  }
  system("sudo kill -HUP $pid") if ( $exists );
  exit 0;
}

#
# main
#

GetOptions (
  "set_user"		=> \$set_user,
  "tun=s"     		=> \$tun
) or usage ();

configure_users() if $set_user;

# end of file
