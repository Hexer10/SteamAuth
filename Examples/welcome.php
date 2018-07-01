<?php

require_once "../libs/SteamAuth.php";
$auth = new SteamAuth('APIKEY');

//Init our OpenID
$auth->initOpenID('welcome.php', 'a random key');

//If not logged redirect user to login page.
if (!$auth->isLogged()) {
    header('Location: login.php');
} else {
    echo 'Welcome '. $auth->username . PHP_EOL . 'You can click <a href="logout.php">here</a> to logout.' ;
}
