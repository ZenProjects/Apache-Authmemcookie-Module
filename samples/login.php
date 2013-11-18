<?php
/* Copyright 1999-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 ?>
<html>
<head>
<title>page de login</title>
<link rel="stylesheet" type="text/css" href="/styles/evroult.css">
</head>
<body>
<h1>&nbsp;</h1>

<h1>&nbsp;</h1>

<h1 align="center">Authentification de l'intranet</h1>

<p align="center">&nbsp;</p>
<form method="POST" action="login_post.php">
  <div align="center">
    <center>
    <table border="0" cellpadding="0" cellspacing="0" style="border-collapse: collapse" width="373">
      <tr>
        <td width="212">Identifiant :</td>
        <td width="161"><input type="text" name="user" size="20" tabindex="1"></td>
	</td>
      </tr>
      <tr>
        <td width="212">Mot de passe : </td>
        <td width="161"><input type="password" name="password" size="20" tabindex="2"></td>
      </tr>
    </table>
    </center>
  </div>
  <input type="hidden" name="referer" value="<?php if (isset($_SERVER["REDIRECT_URL"])) echo $_SERVER["REDIRECT_URL"]; else echo "/"; ?>">
  <p align="center">&nbsp;<input type="submit" value="Se connecter" tabindex="3">
</form>
</body>
</html>

