<?php
 $file = "sudo /opt/vyatta/sbin/vyos-username-ovpn.pl --genovpn --tun $tunnel --phpuser $username";
 ob_start();
 passthru($file);
 $perlreturn = ob_get_contents();
 ob_end_clean();

 $target = "/config/auth/$tunnel/$username.ovpn";
 $link = "/tmp/$username.ovpn";
 symlink($target, $link);

?>
<script language="javascript">
  function submitform() {
    document.forms["download"].submit();
  }
</script>

<form name=download action="download.php" method="post">
  <input type="hidden" name="filename" value="<?=$link ?>"/>
  <a href="#" onClick="submitform()">Submit</a>
</form>
