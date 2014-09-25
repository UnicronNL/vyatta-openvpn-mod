<?php
  $file = $_POST['filename'];
  $run = "sudo /opt/vyatta/sbin/vyos-username-ovpn.pl --genovpn --tun $tunnel --phpuser $username";
  $target = "/config/auth/$tunnel/$username.ovpn";
  $link = "/tmp/$username.ovpn";
  
  ob_start();
  passthru($run);
  $perlreturn = ob_get_contents();
  ob_end_clean();
  symlink($target, $link);

  header('Content-Description: File Transfer');
  header('Content-Type: application/application/x-openvpn-profile');
  header('Content-Disposition: attachment; filename='.basename($file));
  header('Expires: 0');
  header('Cache-Control: must-revalidate');
  header('Pragma: public');
  header('Content-Length: ' . filesize($file));
  readfile($file);
  unlink($file);
  ignore_user_abort(true);
  if (connection_aborted()) {
    unlink($file);
  }
?>
