# SteamAuth
Authenticated users using steam openid or gather users informations! 

You can find a full documentaion [here](https://developer.valvesoftware.com/wiki/Steam_Web_API#GetPlayerSummaries_.28v0002.29) about the used API, a smaller doc about the properties & function it's on the class PHPDoc.

This requires openid.php (Included in this repo.)

# Usage

``` PHP
//Require our library.
require "libs/SteamAuth.php"

//Costruct our class
$auth = new SteamAuth('APIKEY'); //Get apikey from https://steamcommunity.com/dev/apikey
```

Now we can to two things:
 * Authenticate a user
 ``` PHP
 $auth->initOpenID('welcome.php', 'a random key'); //A secure key to encrypt our cookie data.
 header("Location:" . $auth->getLoginURL()); //Redirect to login url.
 ``` 
 * Get user infomations by SteamID64.
 ``` PHP
 $auth->getPlayerSum($_GET['steamid']);
 ```
 
 Finally we can get information about the user:
 ``` PHP
 echo $auth->username; //Get client display name.
 echo $auth->realname; //Get client real name if specified.
 //And so on
 ```
 
 I sugged to check the [Examples](https://github.com/Hexer10/SteamAuth/tree/master/Examples) pages for more complex examples.
 
 # Todo
 * Add composer.
 * Add more steam api functions.
