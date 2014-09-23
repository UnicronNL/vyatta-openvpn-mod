<?php
  function ldap($ldaparray){

  $username        = $ldaparray[1];
  $password        = $ldaparray[2];
  $ldapurl         = $ldaparray[3];
  $ldapbinddn      = $ldaparray[4];
  $ldapbindpass    = $ldaparray[5];
  $ldapcacertdir   = $ldaparray[6];
  $ldapcacertfile  = $ldaparray[7];
  $ldapciphersuite = $ldaparray[8];
  $ldapclientkey   = $ldaparray[9];
  $ldapclientcert  = $ldaparray[10];
  $ldapentls       = $ldaparray[11];
  $ldapfolref      = $ldaparray[12];
  $ldapnettime     = $ldaparray[13];
  $ldapauthbasedn  = $ldaparray[14];
  $ldapauthseflt   = $ldaparray[15];
  $ldapauthusegrp  = $ldaparray[16];
  $ldapgrpbasedn   = $ldaparray[17];
  $ldapgrpmemattr  = $ldaparray[18];
  $ldapgrpseflt    = $ldaparray[19];

  $ldapconn = ldap_connect($ldapurl);
  if ($ldapconn) {
    $ldapbind = ldap_bind($ldapconn, $ldapbinddn, $ldapbindpass);
    if ($ldapbind) {
     $sr=ldap_search($ldapconn, $ldapauthbasedn, $ldapauthseflt);
     $info = ldap_get_entries($ldapconn, $sr);
    if ($info["count"] > 1) {
      echo "WARNING: More than one user was found. <br />";
      exit;
    }
    $ldapbinduser = ldap_bind($ldapconn, $info[0]["dn"], $password);
    if ($info["count"] == 0) {
      echo "LDAP <br>";
      echo "Authentication failure! <br>";
    }
    else
      if ($ldapbinduser) {
        echo "LDAP <br>";
        echo "You are authenticated! <br>";
      }
      else {
        echo "LDAP <br>";
        echo "Authentication failure! <br>";
      }
      ldap_close($ldapconn);
    }
  }
  else {
    echo "<h4>Unable to connect to LDAP server</h4>";
  }
}
?>
