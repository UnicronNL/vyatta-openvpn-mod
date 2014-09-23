<?php
function local($localarray) {

  $username = $localarray[1];
  $password = $localarray[2];
  $htpasswd = $localarray[3];

  if( !($passwd = @fopen($htpasswd, "r" ))) {
    echo "Cannot open password file.";
    exit;
  }
  while( $pwent = fgets( $passwd, 100 )) {
    $part = explode( ":", chop($pwent));
    $pass = explode( "\$", $part[1]);
    $plainpasswd=$password;
    $salt=$pass[2];
    $len = strlen($plainpasswd);
    $text = $plainpasswd.'$apr1$'.$salt;
    $bin = pack("H32", md5($plainpasswd.$salt.$plainpasswd));
    for($i = $len; $i > 0; $i -= 16) { $text .= substr($bin, 0, min(16, $i)); }
    for($i = $len; $i > 0; $i >>= 1) { $text .= ($i & 1) ? chr(0) : $plainpasswd{0}; }
    $bin = pack("H32", md5($text));
    for($i = 0; $i < 1000; $i++) {
      $new = ($i & 1) ? $plainpasswd : $bin;
      if ($i % 3) $new .= $salt;
      if ($i % 7) $new .= $plainpasswd;
      $new .= ($i & 1) ? $bin : $plainpasswd;
      $bin = pack("H32", md5($new));
    }
    $tmp="";
    for ($i = 0; $i < 5; $i++) {
      $k = $i + 6;
      $j = $i + 12;
      if ($j == 16) $j = 5;
      $tmp = $bin[$i].$bin[$k].$bin[$j].$tmp;
    }
    $tmp = chr(0).chr(0).$bin[11].$tmp;
    $tmp = strtr(strrev(substr(base64_encode($tmp), 2)),
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
    $hashedpasswd = "$"."apr1"."$".$salt."$".$tmp;
    if (($username == $part[0]) && ($hashedpasswd == $part[1])) {
      echo "LOCAL <br>";
      echo "You are authenticated! <br>";
    }
    else {
      echo "LOCAL <br>";
      echo "Authentication failure! <br>";
    }
  }
}
?>
