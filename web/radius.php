<?php
function radius($radarray, $radservers) {
  require_once('radius.class.php');

  $tunnel        = $radarray[0];
  $username      = $radarray[1];
  $password      = $radarray[2];
  $radframedprt  = $radarray[3];
  $radnasaddr    = $radarray[4];
  $radnasid      = $radarray[5];
  $radnasprttype = $radarray[6];
  $radsrvtype    = $radarray[7];

  foreach ($radservers as $innerArray) {
    if (is_array($innerArray)){
      $radacctport = $innerArray[0];
      $radauthport = $innerArray[1];
      $radname     = $innerArray[2];
      $radsecret   = $innerArray[3];
      $radius      = new Radius($radname, $radsecret);
      $radius->SetFramedProtocol($radframedprt);
      $radius->SetNasIpAddress($radnasaddr);
      $radius->SetNASIdentifier($radnasid);
      $radius->SetNASPortType($radnasprttype);
      $radius->SetServiceType($radsrvtype);
      $radius->SetAccountingPort($radacctport);
      $radius->SetAuthenticationPort($radauthport);
      if ($radius->AccessRequest($username, $password)) {
        echo "RADIUS <br />";
        echo "You are authenticated! <br />";
        include 'include/linkgen.php';
      }
      else {
        echo "RADIUS <br />";
        echo "Authentication failure! <br />";
      }
    }
  }
}
?>
