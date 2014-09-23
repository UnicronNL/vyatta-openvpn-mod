<?php
if(isset($_POST['username']) && isset($_POST['password'])){
  $username = $_POST['username'];
  $password = $_POST['password'];
  auth($username, $password);
}
else{
  ?>
  <!DOCTYPE html>
  <html xmlns="http://www.w3.org/1999/xhtml">
  <head>
      <title>Log in</title>
      <link href="include/stylesheet.css" rel="stylesheet" />
  </head>
  <body>
      <section id="loginBox">
          <h2>Login</h2>
          <form action="#"method="post" class="minimal">
              <label for="username">
                  Username:
                  <input type="text" name="username" id="username" placeholder="Username" required="required" />
              </label>
              <label for="password">
                  Password:
                  <input type="password" name="password" id="password" placeholder="Password" required="required" />
              </label>
              <button type="submit" class="btn-minimal">Sign in</button>
          </form>
      </section>
  </body>
  </html>
  <?php
}
?>
