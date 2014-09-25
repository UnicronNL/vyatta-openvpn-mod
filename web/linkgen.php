<script language="javascript">
  function submitform() {
    document.forms["download"].submit();
  }
</script>

<form name=download action="download.php" method="post">
  <input type="hidden" name="filename" value="<?=$link ?>"/>
  <a href="#" onClick="submitform()">Submit</a>
</form>
