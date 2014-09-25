<?php
  $file = $_POST['filename'];
  $tunnel = $_POST['tunnel'];
  $username = $_POST['username'];
  $target = "/config/auth/$tunnel/$username.ovpn";

  symlink($target, $file);

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
