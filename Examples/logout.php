<?php

require_once "../libs/SteamAuth.php";
$auth = new SteamAuth('APIKEY');

//Init our OpenID
$auth->initOpenID('welcome.php', 'a random key');

//If not logged redirect user to login page.
if (!$auth->isLogged()) {
    header('Location: login.php');
} else {
    $auth->logout('login.php');
}