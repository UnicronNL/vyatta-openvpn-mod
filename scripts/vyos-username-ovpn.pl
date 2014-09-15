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

my ($set_user, $userName, $tun);

sub usage {
	print <<EOF;
Usage:
	$0 --set_user --tun <tunnel> --username <name>
EOF
	exit 1;
}

sub configure_users {
	my $config = new Vyatta::Config;
	my $iftype = "interfaces openvpn";
	my $passwdCommand = "/usr/bin/ovpnauth";
	my $passwdDB = "/opt/vyatta/etc/openvpn/users${tun}.db";
	
	$config->setLevel("$iftype $tun server authentication local username");
	my @users = $config->listNodes();

	unlink $passwdDB;

	foreach my $user(@users) {
		my $password = $config->returnValue("$userName password");
		system("sudo $passwdCommand -a -u $user -p $password $passwdDB >/dev/null  2>&1");
	}
	
	exit 0;
}

#
# main
#

GetOptions (
	"set_user"		=> \$set_user,
	"username=s"		=> \$userName,
	"tun=s"     		=> \$tun
) or usage ();

configure_users() if $set_user;

# end of file
