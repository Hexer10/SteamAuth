<?php

require_once "../libs/SteamAuth.php";
$auth = new SteamAuth('APIKEY');

//Init our OpenID
$auth->initOpenID('welcome.php', 'a random key');


//Client asks to login.
if (isset($_GET['login'])){
    //Redirect to welcome page if it's already logged.
    if ($auth->isLogged()) {
        header("Location: welcome.php");
    } else {
        //Redirect client to steam page.
        header("Location:" . $auth->getLoginURL());
    }
} else {
    echo 'Click <a href="?login">here</a> to login.';
}