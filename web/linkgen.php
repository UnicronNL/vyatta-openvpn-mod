<?php
  $run = "sudo /opt/vyatta/sbin/vyos-username-ovpn.pl --genovpn --tun $tunnel --phpuser $username";
  $file = "/tmp/$username.ovpn";

  ob_start();
  passthru($run);
  $perlreturn = ob_get_contents();
  ob_end_clean();
?>
<script language="javascript">
  function submitform() {
    document.forms["download"].submit();
  }
</script>

<form name=download action="download.php" method="post">
  <input type="hidden" name="tunnel" value="<?=$tunnel ?>"/>
  <input type="hidden" name="username" value="<?=$username ?>"/>
  <input type="hidden" name="filename" value="<?=$file ?>"/>
  <a href="#" onClick="submitform()">Submit</a>
</form>
