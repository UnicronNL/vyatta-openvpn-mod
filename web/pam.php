<?php
function pam($pamarray){

  $tunnel   = $pamarray[0];
  $username = $pamarray[1];
  $password = $pamarray[2];

  if (pam_auth($username, $password, &$error)) {
    echo "PAM <br>";
    echo "You are authenticated! <br>";
    include 'include/linkgen.php';
  }
  else {
    echo "PAM <br>";
    echo "$error! <br>";
  }
}
?>
