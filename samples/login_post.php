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

  /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // cookie parametters
  $my_cookie_name="myauthcookie"; // name of the cookie
  $my_domain=""; // cookie domain
  $my_expiretime=0; // expiration time off the cookie, must be zero or in seconds.
  $my_path="/";    // path of the cookie
  $my_secure=FALSE;   // if cookie are secure (must be transmited only on ssl)
  // to use where behind reverse proxy
  //if (isset($_SERVER["HTTP_X_FORWARDED_FOR"])
  //$my_remoteip=$_SERVER["HTTP_X_FORWARDED_FOR"];
  if (isset($_SERVER["HTTP_VIA"]))
   $my_remoteip=$_SERVER["HTTP_VIA"];

  // to use where directly connected to the client
  if (!isset($my_remoteip))
   $my_remoteip=$_SERVER["REMOTE_ADDR"];


  // ldap connxion parametters
  $my_ldap_url="ldap://localhost:389"; // ldap url
  $my_ldap_base="o=MyOrg"; // ldap base dn
  $my_ldap_dn="cn=myBindDnUser,".$my_ldap_base; // bind dn user, if you must bind befor search (no anonymous access)
  $my_ldap_dn_pass="myPassword"; // bind dn user password
  $my_ldap_prot_version=3;

  $my_send_pass_flag=FALSE;  // transmit or not the password of authenticated user

  /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  $my_referer=$_POST["referer"];
  $my_id_ok=FALSE;
  $my_groups="";

  // get user and password from auth form
  $my_user=$_POST["user"];
  $my_password=$_POST["password"];

  // check user identity
  $my_ldap_conn=ldap_connect($my_ldap_url) or die("ldap connexion failed!");

  // set ldap version to V3
  ldap_set_option($my_ldap_conn, LDAP_OPT_PROTOCOL_VERSION, $my_ldap_prot_version);

  // bind to dn
  if ($my_ldap_dn!="") $my_ldap_bind = ldap_bind($my_ldap_conn, $my_ldap_dn, $my_ldap_dn_pass) or die("ldap bind dn failed!");

  // "dn" search for the uid=$my_user
  $my_ldap_result=ldap_search($my_ldap_conn,$my_ldap_base, "uid=".$my_user ) or die("User \"".$my_user."\" not found!");

  // get the first entry for the search
  $my_ldap_entry = ldap_first_entry($my_ldap_conn,$my_ldap_result);
  if ($my_ldap_entry)
  { 
    $my_ldap_attributes = ldap_get_attributes($my_ldap_conn,$my_ldap_entry);
    if ($my_ldap_attributes)
    {  
      $my_nom=$my_ldap_attributes["sn"][0];
      $my_prenom=$my_ldap_attributes["givenName"][0];
      $my_mail=$my_ldap_attributes["mail"][0];

      // get ldap group for the uid
      $my_group_ldap_result=ldap_search($my_ldap_conn,$my_ldap_base, "uniqueMember=uid=".$my_user.",".$my_ldap_base, array("cn") );
      if ($my_group_ldap_result)
      {
	  $my_group_array=ldap_get_entries($my_ldap_conn,$my_group_ldap_result);
	  for($i = 0; $i < count($my_group_array) - 1; $i++)
	  {
	     if ($my_groups!="") $my_groups.=":".$my_group_array[$i][cn][0];
	     else $my_groups=$my_group_array[$i][cn][0];
	  }
      }

      // free the ldap result
      ldap_free_result($my_group_ldap_result);

      // check password for the uid with bind using dn found
      if($my_password==""||!@ldap_bind($my_ldap_conn, ldap_get_dn($my_ldap_conn,$my_ldap_entry), $my_password)) {
?>
<html>
<head>
<title>Erreur d'authentiufication...</title>
<link rel="stylesheet" type="text/css" href="/styles/evroult.css">
</head>
<body>
<h1>&nbsp;</h1>

<h1>&nbsp;</h1>

<h1>&nbsp;</h1>
<h1>&nbsp;</h1>
<h1>&nbsp;</h1>
<h1 align="center">Utilisateur ou mot de passe incorrect!</h1>
<h1 align="center">Cliquer sur pr&eacute;c&eacute;dant et veuillez recommencer...</h1>
</body>
</html>
       <?
       exit;
      }
      $my_id_ok=TRUE;

      // free the ldap result
      ldap_free_result($my_ldap_result);
    }
    else die("ldap error: failed to get attribut from ldap_search....");
  }

  // close ldap connexion
  ldap_close($my_ldap_conn); 

  
  if ($my_id_ok) {
    // instantiate memcache api object
    $memcache = new Memcache;

    // connect to memcached on localhost port 11000
    $memcache->connect('localhost', 11000) or die ("Could not connect");

    // generate cookie uniq session id   
    $key=md5(uniqid(rand(), true).$_SERVER["REMOTE_ADDR"].time());

    // contruct session value to be stored in memcached for the cookie session id.
    $value="UserName=".$my_user."\r\n";
    $value.="Groups=".$my_groups."\r\n";
    $value.="RemoteIP=".$my_remoteip."\r\n";
    $value.="Expiration=".$my_expiretime."\r\n";
    if ($my_send_pass_flag!=FALSE) $value.="Password=".$my_password."\r\n";
    $value.="Email=".$my_mail."\r\n";
    $value.="Name=".$my_nom."\r\n";
    $value.="GivenName=".$my_prenom."\r\n";

    // store value for the key in memcache deamon
    $memcache->set($key,$value,false,$my_expiretime);

    // set cookie session
    if ($my_expiretime!=0) setcookie($my_cookie_name,$key,time()+$my_expiretime,$my_path,$my_domain,$my_secure);
    else setcookie($my_cookie_name,$key,$my_expiretime,$my_path,$my_domain,$my_secure);

    // redirect to referer page....
    header("Location: ".$my_referer);
    exit;
  }
?>
