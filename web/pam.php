<?php
function pam($pamarray){

  $username = $pamarray[1];
  $password = $pamarray[2];

  if (pam_auth($username, $password, &$error)) {
    echo "PAM <br>";
    echo "You are authenticated! <br>";
  }
  else {
    echo "PAM <br>";
    echo "$error! <br>";
  }
}
?>
