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

my ($set_user, $set_web, $user_cn, $genovpn, $tun, $phpuser);
my ($pid, $exists) = undef;
my $iftype = "interfaces openvpn";
  
sub usage {
  print <<EOF;
Usage:
  $0 --set_user --tun <tunnel>
EOF
  exit 1;
}

sub gen_ovpn {
  my $config = new Vyatta::Config;
  my @conf_file = ();
  my $easyrsavar    = "EASYRSA=/etc/openvpn/easy-rsa";
  my $easyrsapkivar = "EASYRSA_PKI=/config/auth/${tun}/pki";
  my $easyrsaexec   = "/etc/openvpn/easy-rsa/easyrsa";
  my $authdir       = "/config/auth/${tun}";
  
  $config->setLevel("$iftype $tun");
  
  unless (-e "${authdir}/pki/private/${phpuser}.key") { 
    system("sudo $easyrsavar $easyrsapkivar $easyrsaexec build-client-full $phpuser nopass");
  }

  my @ca = do {
    open my $fh, "<$authdir/pki/ca.crt"
        or die "could not open $authdir/pki/ca.crt: $!";
    <$fh>;
  };
  my @crt = do {
    open my $fh, "<$authdir/pki/issued/${phpuser}.crt"
        or die "could not open $authdir/pki/issued/${phpuser}.crt: $!";
    <$fh>;
  };
  my @key = do {
    open my $fh, "<$authdir/pki/private/${phpuser}.key"
        or die "could not open $authdir/pki/private/${phpuser}.key: $!";
    <$fh>;
  };

  unless (-e "${authdir}/${phpuser}.ovpn") {
    open (my $fh,">${authdir}/${phpuser}.ovpn") or die("Can't open ${authdir}/${phpuser}.ovpn: $!\n");
    print $fh "";
    close $fh;

    push(@conf_file, 'client', "\n");
    push(@conf_file, 'dev tun', "\n");
    push(@conf_file, 'resolv-retry infinite', "\n");
    push(@conf_file, 'nobind', "\n");
    push(@conf_file, 'persist-key', "\n");
    push(@conf_file, 'persist-tun', "\n");
    push(@conf_file, 'auth-user-pass', "\n");
    push(@conf_file, 'ca [inline]', "\n");
    push(@conf_file, 'cert [inline]', "\n");
    push(@conf_file, 'key [inline]', "\n");
    push(@conf_file, 'verb 3', "\n");
    push(@conf_file, 'keepalive 10 900', "\n");
    push(@conf_file, 'inactive 3600', "\n");
    push(@conf_file, '<ca>', "\n");
    foreach (@ca) {
      push(@conf_file, "$_");
    }
    push(@conf_file, '</ca>', "\n");
    push(@conf_file, '<cert>', "\n");
    foreach (@crt) {
      push(@conf_file, "$_");
    }
    push(@conf_file, '</cert>', "\n");
    push(@conf_file, '<key>', "\n");
    foreach (@key) {
      push(@conf_file, "$_");
    }
    push(@conf_file, '</key>', "\n");

    open ($fh,">${authdir}/${phpuser}.ovpn");
    foreach (@conf_file) {
      print $fh "$_";
    }
    close $fh;
    exit 0;
  }
}

sub user_cn {
  my $username = $ENV{'username'};
  my $common_name = $ENV{'common_name'};

  exit !(length($username) > 0 && length($common_name) > 0 && $username eq $common_name);
  exit 0;
}

sub configure_users {
  my $config          = new Vyatta::Config;
  my $passwdCommand   = "/usr/bin/ovpnauth";
  my $htPasswdCommand = "/usr/bin/htpasswd";
  my $htPasswdFile    = "/opt/vyatta/etc/openvpn/plugin/.htpasswd${tun}";
  my $passwdDB        = "/opt/vyatta/etc/openvpn/plugin/users${tun}.db";
  my $pidfile         = "/var/run/openvpn-${tun}.pid";

  if (-e $pidfile) {
    $pid= `cat $pidfile`;
    $exists = kill 0, $pid;
  }

  $config->setLevel("$iftype $tun server authentication local username");
  my @users = $config->listNodes();

  unlink $passwdDB;
  unlink $htPasswdFile;
  system("sudo touch $htPasswdFile >/dev/null  2>&1");
  foreach my $user(@users) {
    my $password = $config->returnValue("$user password");
    system("sudo $passwdCommand -a -u $user -p $password $passwdDB >/dev/null  2>&1");
    system("sudo $htPasswdCommand -m -b $htPasswdFile $user $password >/dev/null  2>&1");
  }
  system("sudo kill -HUP $pid") if ( $exists );
  exit 0;
}

sub configure_web {
  my $config = new Vyatta::Config;
  my $iftype = "interfaces openvpn";
  my @conf_file = ();
  my $lighttpconf = "/etc/lighttpd/lighttp${tun}.conf";
  my $indexfile = "/var/www/ovpn-client-web/index${tun}.php";
  my $authfile = "/var/www/ovpn-client-web/include/auth${tun}.php";
  my $htPasswdFile = "/opt/vyatta/etc/openvpn/plugin/.htpasswd${tun}";
  #my $phpini = "/etc/php5/cgi/php.ini";
  #my $pathinfo = `cat $phpini | grep '^cgi\.fix_pathinfo=1$' || echo false`; 

  #if ($pathinfo eq "false") {
  #  open (my $fh,">>$phpini") or die("Can't open $phpini: $!\n");
  #  print $fh "cgi.fix_pathinfo=1";
  #  close $fh;
  #}
  $config->setLevel("$iftype $tun server client-web");
  
  open (my $fh,">$lighttpconf") or die("Can't open $lighttpconf: $!\n");
  print $fh "";
  close $fh;

  my @addrs = $config->returnValues("listen-address");
  my $port = $config->returnValue("port");
  
  my $x = 1;
  foreach my $addr(@addrs) {
    if (($addr =~ /:/) && ($x == 1)) {
      push(@conf_file, "server.bind = \"[$addr]\"", "\n");
      push(@conf_file, "server.port = \"$port\"", "\n");
      ++$x;
    }
    elsif ($x == 1) {
      push(@conf_file, "server.bind = \"$addr\"", "\n");
      push(@conf_file, "server.port = \"$port\"", "\n");
      ++$x;
    }
    elsif ($addr =~ /:/) {
      push(@conf_file, "\$SERVER[\"socket\"] == \"[$addr]:$port\" {\n");
      push(@conf_file, "ssl.engine = \"enable\"", "\n");
      push(@conf_file, "ssl.pemfile = \"/etc/lighttpd/server${tun}.pem\"}", "\n");
    }
    else {
      push(@conf_file, "\$SERVER[\"socket\"] == \"$addr:$port\" {\n");
      push(@conf_file, "ssl.engine = \"enable\"", "\n");
      push(@conf_file, "ssl.pemfile = \"/etc/lighttpd/server${tun}.pem\"}", "\n");
    }
  }
  push(@conf_file, "server.username = \"www-data\"", "\n");
  push(@conf_file, "server.groupname = \"www-data\"", "\n");
  push(@conf_file, "ssl.engine = \"enable\"", "\n");
  push(@conf_file, "ssl.pemfile = \"/etc/lighttpd/server${tun}.pem\"", "\n");
  push(@conf_file, "server.modules = (\"mod_fastcgi\", \"mod_alias\", \"mod_accesslog\")", "\n");
  push(@conf_file, "server.document-root = \"/var/www/ovpn-client-web/\"", "\n");
  push(@conf_file, "server.errorlog = \"/var/log/lighttpd/ovpn${tun}web-error.log\"", "\n");
  push(@conf_file, "server.breakagelog = \"/var/log/lighttpd/ovpn${tun}web-error.log\"", "\n");
  push(@conf_file, "accesslog.filename = \"/var/log/lighttpd/ovpn${tun}web-access.log\"", "\n");
  push(@conf_file, "index-file.names = (\"index${tun}.php\")", "\n");
  if ($config->exists("alias-url")) {
    my $alias_url = $config->returnValue("alias-url");
    push(@conf_file, "alias.url = (\"/$alias_url/\" => \"/var/www/ovpn-client-web/\")", "\n");
  }
  push(@conf_file, "mimetype.assign = (\".html\" => \"text/html\", \".gif\" => \"image/gif\", \".jpeg\" => \"image/jpeg\", \".jpg\" => \"image/jpeg\", \".png\" => \"image/png\", \".ico\" => \"image/x-icon\", \".css\" => \"text/css\", \".json\" => \"text/plain\", \".js\" => \"application/javascript\",)");
  push(@conf_file, "fastcgi.server = (\".php\" => (\"localhost\" => (\"socket\" => \"/var/run/php-fastcgi.socket\", \"bin-path\" => \"/usr/bin/php-cgi\")))", "\n");

  open ($fh,">$lighttpconf");
  foreach (@conf_file) {
    print $fh "$_";
  }
  close $fh;

  open ($fh,">$indexfile") or die("Can't open $indexfile: $!\n");
  print $fh "";
  close $fh;
  
  @conf_file = ();
  push(@conf_file, "<?php", "\n");
  push(@conf_file, "  require 'include/auth${tun}.php';", "\n");
  push(@conf_file, "  include 'include/login.php';", "\n");
  push(@conf_file, "?>", "\n");
  open ($fh,">$indexfile");
  foreach (@conf_file) {
    print $fh "$_";
  }
  close $fh;
  
  open ($fh,">$authfile") or die("Can't open $authfile: $!\n");
  print $fh "";
  close $fh;
  
  @conf_file = ();
  my @conf_file0 = ();
  my @conf_file1 = ();
  my @conf_file2 = ();
  push(@conf_file, "<?php", "\n");
  push(@conf_file, 'function auth($username, $password) {', "\n");
  $config->setLevel("$iftype $tun server authentication");
  my @user_auth = $config->listNodes();
  foreach my $auth_opt(@user_auth) {
    push(@conf_file, "  require '${auth_opt}.php';", "\n");
    push(@conf_file, '  $tunnel = \'', $tun, "';", "\n");
    if ($auth_opt eq "ldap") {
      if ($config->exists("ldap server-url")) {
        push(@conf_file, '  $ldapurl = \'', $config->returnValue("ldap server-url"), "';", "\n"); 
      }
      else {
        push(@conf_file, '  $ldapurl = " ";', "\n");
      }
      if ($config->exists("ldap bind-dn")) {
        push(@conf_file, '  $ldapbinddn = \'', $config->returnValue("ldap bind-dn"), "';", "\n"); 
      }
      else {
        push(@conf_file, '  $ldapbinddn = " ";', "\n");
      }
      if ($config->exists("ldap bind-pass")) {
        push(@conf_file, '  $ldapbindpass = \'', $config->returnValue("ldap bind-pass"), "';", "\n"); 
      }
      else {
      push(@conf_file, '  $ldapbindpass = " ";', "\n");
      }
      if ($config->exists("ldap ca-cert-dir")) {
        push(@conf_file, '  $ldapcacertdir = \'', $config->returnValue("ldap ca-cert-dir"), "';", "\n"); 
      }
      else {
        push(@conf_file, '  $ldapcacertdir = " ";', "\n");
      }
      if ($config->exists("ldap ca-cert-file")) {
        push(@conf_file, '  $ldapcacertfile = \'', $config->returnValue("ldap ca-cert-file"), "';", "\n"); 
      }
      else {
      push(@conf_file, '  $ldapcacertfile = " ";', "\n");
      }
      if ($config->exists("ldap cipher-suite")) {
        push(@conf_file, '  $ldapciphersuite = \'', $config->returnValue("ldap cipher-suite"), "';", "\n"); 
      }
      else {
        push(@conf_file, '  $ldapciphersuite = " ";', "\n");
      }
      if ($config->exists("ldap client-key")) {
        push(@conf_file, '  $ldapclientkey = \'', $config->returnValue("ldap client-key"), "';", "\n"); 
      }
      else {
      push(@conf_file, '  $ldapclientkey = " ";', "\n");
      }
      if ($config->exists("ldap client-cert")) {
        push(@conf_file, '  $ldapclientcert = \'', $config->returnValue("ldap client-cert"), "';", "\n"); 
      }
      else {
        push(@conf_file, '  $ldapclientcert = " ";', "\n");
      }
      if ($config->exists("ldap enable-tls")) {
        push(@conf_file, '  $ldapentls = \'', $config->returnValue("ldap enable-tls"), "';", "\n"); 
      }
      else {
        push(@conf_file, '  $ldapentls = " ";', "\n");
      }
      if ($config->exists("ldap follow-referrals")) {
        push(@conf_file, '  $ldapfolref = \'', $config->returnValue("ldap follow-referrals"), "';", "\n"); 
      }
      else {
        push(@conf_file, '  $ldapfolref = " ";', "\n");
      }
      if ($config->exists("ldap network-timeout")) {
        push(@conf_file, '  $ldapnettime = \'', $config->returnValue("ldap network-timeout"), "';", "\n"); 
      }
      else {
        push(@conf_file, '  $ldapnettime = " ";', "\n");
      }
      if ($config->exists("ldap authorize base-dn")) {
        push(@conf_file, '  $ldapauthbasedn = \'', $config->returnValue("ldap authorize base-dn"), "';", "\n"); 
      }
      else {
        push(@conf_file, '  $ldapauthbasedn = " ";', "\n");
      }
      if ($config->exists("ldap authorize search-filter")) {
        my $str = $config->returnValue("ldap authorize search-filter");
        my $find = '%u';
        my $replace = '$username';
        $str =~ s/$find/$replace/g;
        push(@conf_file, '  $ldapauthseflt = "', $str, "\";", "\n"); 
      }
      else {
        push(@conf_file, '  $ldapauthseflt = " ";', "\n");
      }
      if ($config->exists("ldap authorize use-group")) {
        push(@conf_file, '  $ldapauthusegrp = \'', $config->returnValue("ldap authorize use-group"), "';", "\n"); 
      }
      else {
        push(@conf_file, '  $ldapauthusegrp = " ";', "\n");
      }
      if ($config->exists("ldap authorize group base-dn")) {
        push(@conf_file, '  $ldapgrpbasedn = \'', $config->returnValue("ldap authorize group base-dn"), "';", "\n"); 
      }
      else {
        push(@conf_file, '  $ldapgrpbasedn = " ";', "\n");
      }
      if ($config->exists("ldap authorize group member-attr")) {
        push(@conf_file, '  $ldapgrpmemattr = \'', $config->returnValue("ldap authorize group member-attr"), "';", "\n"); 
      }
      else {
        push(@conf_file, '  $ldapgrpmemattr = " ";', "\n");
      }
      if ($config->exists("ldap authorize group search-filter")) {
        push(@conf_file, '  $ldapgrpseflt = \'', $config->returnValue("ldap authorize group search-filter"), "';", "\n"); 
      }
      else {
        push(@conf_file, '  $ldapgrpseflt = " ";', "\n");
      }
      push(@conf_file, '  $ldaparray = array();', "\n");
      push(@conf_file, '  $ldaparray[0] = $tunnel;', "\n");
      push(@conf_file, '  $ldaparray[1] = $username;', "\n");
      push(@conf_file, '  $ldaparray[2] = $password;', "\n");
      push(@conf_file, '  $ldaparray[3] = $ldapurl;', "\n");
      push(@conf_file, '  $ldaparray[4] = $ldapbinddn;', "\n");
      push(@conf_file, '  $ldaparray[5] = $ldapbindpass;', "\n");
      push(@conf_file, '  $ldaparray[6] = $ldapcacertdir;', "\n");
      push(@conf_file, '  $ldaparray[7] = $ldapcacertfile;', "\n");
      push(@conf_file, '  $ldaparray[8] = $ldapciphersuite;', "\n");
      push(@conf_file, '  $ldaparray[9] = $ldapclientkey;', "\n");
      push(@conf_file, '  $ldaparray[10] = $ldapclientcert;', "\n");
      push(@conf_file, '  $ldaparray[11] = $ldapentls;', "\n");
      push(@conf_file, '  $ldaparray[12] = $ldapfolref;', "\n");
      push(@conf_file, '  $ldaparray[13] = $ldapnettime;', "\n");
      push(@conf_file, '  $ldaparray[14] = $ldapauthbasedn;', "\n");
      push(@conf_file, '  $ldaparray[15] = $ldapauthseflt;', "\n");
      push(@conf_file, '  $ldaparray[16] = $ldapauthusegrp;', "\n");
      push(@conf_file, '  $ldaparray[17] = $ldapgrpbasedn;', "\n");
      push(@conf_file, '  $ldaparray[18] = $ldapgrpmemattr;', "\n");
      push(@conf_file, '  $ldaparray[19] = $ldapgrpseflt;', "\n");
    }
      if ($auth_opt eq "radius") {
        if ($config->exists("radius framed-protocol")) {
          push(@conf_file, '  $radframedprt = \'', $config->returnValue("radius framed-protocol"), "';", "\n"); 
        }
      else {
        push(@conf_file, '  $radframedprt = " ";', "\n");
      }
      if ($config->exists("radius nas address")) {
        push(@conf_file, '  $radnasaddr = \'', $config->returnValue("radius nas address"), "';", "\n"); 
      }
      else {
        push(@conf_file, '  $radnasaddr = " ";', "\n");
      }
      if ($config->exists("radius nas identifier")) {
        push(@conf_file, '  $radnasid = \'', $config->returnValue("radius nas identifier"), "';", "\n"); 
      }
      else {
        push(@conf_file, '  $radnasid = " ";', "\n");
      }
      if ($config->exists("radius nas port-type")) {
        push(@conf_file, '  $radnasprttype = \'', $config->returnValue("radius nas port-type"), "';", "\n"); 
      }
      else {
        push(@conf_file, '  $radnasprttype = " ";', "\n");
      }
      if ($config->exists("radius service-type")) {
        push(@conf_file, '  $radsrvtype = \'', $config->returnValue("radius service-type"), "';", "\n"); 
      }
      else {
        push(@conf_file, '  $radsrvtype = " ";', "\n");
      }
      push(@conf_file, '  $radarray = array();', "\n");
      push(@conf_file, '  $radarray[0] = $tunnel;', "\n");
      push(@conf_file, '  $radarray[1] = $username;', "\n");
      push(@conf_file, '  $radarray[2] = $password;', "\n");
      push(@conf_file, '  $radarray[3] = $radframedprt;', "\n");
      push(@conf_file, '  $radarray[4] = $radnasaddr;', "\n");
      push(@conf_file, '  $radarray[5] = $radnasid;', "\n");
      push(@conf_file, '  $radarray[6] = $radnasprttype;', "\n");
      push(@conf_file, '  $radarray[7] = $radsrvtype;', "\n");

      my @server_rad = $config->listNodes("radius server");
      my $x = 1;
      my $y = scalar(grep {defined $_} @server_rad); 
      my $z = 1;
      foreach my $server(@server_rad) {
        if ($config->exists("radius server $server acct-port")) {
          push(@conf_file0, '  $radacctport', "$x ='", $config->returnValue("radius server $server acct-port"), "';", "\n"); 
        }
        else {
          push(@conf_file0, '  $radacctport', "$x = ' ';", "\n");
        }
        if ($config->exists("radius server $server auth-port")) {
          push(@conf_file0, '  $radauthport', "$x ='", $config->returnValue("radius server $server auth-port"), "';", "\n"); 
        }
        else {
          push(@conf_file0, '  $radauthport', "$x = ' ';", "\n");
        }
        if ($config->exists("radius server $server name")) {
          push(@conf_file0, '  $radname', "$x ='", $config->returnValue("radius server $server name"), "';", "\n"); 
        }
        else {
          push(@conf_file0, '  $radname', "$x = ' ';", "\n");
        }
        if ($config->exists("radius server $server shared-secret")) {
          push(@conf_file0, '  $radsecret', "$x ='", $config->returnValue("radius server $server shared-secret"), "';", "\n"); 
        }
        else {
          push(@conf_file0, '  $radsecret', "$x = ' ';", "\n");
        }
        while ($z < $y) {
          push(@conf_file2, '  array($radacctport', "$z,", '$radauthport', "$z,", '$radname', "$z,", '$radsecret', "$z),", "\n");
          ++$z;
        }
        if ($x == $y) {
          push(@conf_file2, '    array($radacctport', "$z,", '$radauthport', "$z,", '$radname', "$z,", '$radsecret', "$z));", "\n");
        }
        ++$x;
      }
      push(@conf_file1, '  $radservers = array', "\n");
      push(@conf_file1, '  (', "\n");
      foreach (@conf_file0) {
        push(@conf_file, "$_");
      }
      foreach (@conf_file1) {
        push(@conf_file, "$_");
      }   
      foreach (@conf_file2) {
        push(@conf_file, "$_");
      }
    }
    if ($auth_opt eq "local") {
      push(@conf_file, '  $localarray = array();', "\n");
      push(@conf_file, '  $localarray[0] = $tunnel;', "\n");
      push(@conf_file, '  $localarray[1] = $username;', "\n");
      push(@conf_file, '  $localarray[2] = $password;', "\n");
      push(@conf_file, '  $localarray[3] = ', '"',"$htPasswdFile", '"', ";", "\n");
    }
    if ($auth_opt eq "pam") {
      push(@conf_file, '  $pamarray = array();', "\n");
      push(@conf_file, '  $pamarray[0] = $tunnel;', "\n");
      push(@conf_file, '  $pamarray[1] = $username;', "\n");
      push(@conf_file, '  $pamarray[2] = $password;', "\n");
    }
  }
  
  foreach my $auth_opt(@user_auth) {
     if ($auth_opt eq "ldap") {
       push(@conf_file, '  ldap($ldaparray);', "\n");
     }
     if ($auth_opt eq "radius") {
       push(@conf_file, '  radius($radarray, $radservers);', "\n");
     }
     if ($auth_opt eq "local") {
       push(@conf_file, '  local($localarray);', "\n");
     }
     if ($auth_opt eq "pam") {
       push(@conf_file, '  pam($pamarray);', "\n");
     }
  }
  push(@conf_file, "}\n");
  push(@conf_file, "?>");
  
  open ($fh,">$authfile");
  foreach (@conf_file) {
    print $fh "$_";
  }
  close $fh;
  exit 0;
}

#
# main
#

GetOptions (
  "set_user"  => \$set_user,
  "set_web"   => \$set_web,
  "user_cn"   => \$user_cn,
  "genovpn"   => \$genovpn,
  "tun=s"     => \$tun,
  "phpuser=s" => \$phpuser
) or usage ();

configure_users() if $set_user;
user_cn()         if $user_cn;
gen_ovpn()        if $genovpn;
configure_web()   if $set_web;
# end of file
