<?php
require "../libs/SteamAuth.php";

if (empty($_GET['steamid'])){
    die('Missing "steamid" parameter');
}

$auth = new SteamAuth("APIKEY");

$auth->getPlayerSum($_GET['steamid']);
echo 'His name is '. $auth->usernam();
