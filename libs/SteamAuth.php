<?php
require "openid.php";

/**
 * This class provides a simple usage of the steam openid.
 *
 * It's properly tested only on PHP 7.2
 *
 * @version     v2.00 (2018-07-02)
 * @link        https://github.com/Hexer10/SteamAuth         GitHub Repo
 * @author      Mattia (Hexah/Hexer10) (hexer504@mail.com)
 * @copyright   Copyright (c) 2018 Mattia (Hexah/Hexer10) (hexer504@mail.com)
 * @license     http://opensource.org/licenses/mit-license.php  MIT License
 * @see         https://developer.valvesoftware.com/wiki/Steam_Web_API#GetPlayerSummaries_.28v0002.29 API Documentaion
 *
 * @property-read mixed $steamid User's STEAMID64
 * @property-read mixed $username User's Steam Displayname.
 * @property-read mixed $profile User's profile URL.
 * @property-read mixed $avatar User's avatar small (32x32)
 * @property-read mixed $avatarm User's avatar medium (64x64)
 * @property-read mixed $avatarf User's avatar full (184x184)
 * @property-read mixed $personaState The user's current status. 0 - Offline or Private, 1 - Online, 2 - Busy, 3 - Away,
 *                                    4 - Snooze, 5 - looking to trade, 6 - looking to play.
 * @property-read mixed $visState Represents whether the profile is visible or not
 * 								  1 - the profile is not visible to you (Private, Friends Only, etc),
 * 								  3 - the profile is "Public", and the data is visible.
 * @property-read mixed $profileState Indicates if the user has a community profile configured (1).
 * @property-read mixed $lastLogoff The last time the user was online, in unix time.
 * @property-read mixed $commentPerm Indicates if the profile allows public comments.
 *
 * @property-read mixed $realName Users's "Real Name", if it's set, otherwise ''.
 * @property-read mixed $primaryClan User's primary clan ID, if it's set, otherwise 0.
 * @property-read mixed $timeCreated User's account creation time, if it's public, otherwise 0.
 * @property-read mixed $gameId Client User's playing game, or 0 if it's not playing/private.
 * @property-read mixed $gameServerIP User's playing server IP:PORT or 0.0.0.0 .
 * @property-read mixed $gameExtraInfo User's playing game, or '' if it's not playing/private.
 * @property-read mixed $countryCode User's country of residence.
 * @property-read mixed $stateCode User's state of residence.
 * @property-read mixed $cityId User's city of residence.

 * @property-read mixed $personaStateFlags This is not listed on the documentation.

 * @property-read mixed $friends Associative array with the user's friends.
 * @property-read mixed $playerInfo Associative array with all the user's information.
 */
class SteamAuth{

    /** @var LightOpenID $this->OpenID */
    //General
    private $OpenID;
    private $APIkey;
    private $SSteamID;
    private $useSSL;
    private $expire;

    //Client data - Public
    protected $steamid;
    protected $username;
    protected $profile;
    protected $avatar;
    protected $avatarm;
    protected $avatarf;
    protected $personaState;
    protected $visState;
    protected $profileState;
    protected $lastLogoff;
    protected $commentPerm;

    //Client data - Private
    protected $realName;
    protected $primaryClan;
    protected $timeCreated;
    protected $gameId;
    protected $gameServerIP;
    protected $gameExtraInfo;
    protected $countryCode;
    protected $stateCode;
    protected $cityId;

    //Client data - Unlisted
    protected $personaStateFlags;

    //Additional data
    protected $friends;

    //All data
    protected $playerInfo;

    //Encrypt Key
    private $secret_key;
    private $encrypt_method = "AES-256-CBC";
    private $key;

    /**
     * SteamAuth constructor.
     * @param $apikey int Steam APIKey
     */
    function __construct($apikey){
        $this->APIkey = $apikey;
    }

    /**
     * Required to allow user to login in using steam.
     * @param $loginURL int Where to redirect after successful login.
     * @param $secretKey int Secret key used to encrypt the client SteamID.
     * @param $cookieTime int By default it's 10y from the which date it's called.
     * @param $ssl bool True to save a secure cookie, only compatible with HTTPs.
     * @throws ErrorException
     */
    function initOpenID($loginURL, $secretKey, $cookieTime = null, $ssl = true){
        $this->OpenID = new LightOpenID($_SERVER['SERVER_NAME']);
        $this->OpenID->identity = "https://steamcommunity.com/openid";
        $this->secret_key = $secretKey;
        $this->expire = empty($cookieTime)? time() + (10 * 365 * 24 * 60 * 60) : $cookieTime;
        $this->useSSL = $ssl;
        $this->key = hash('sha256', $this->secret_key);
        if (isset($_COOKIE['SteamSession'])){
            $this->SSteamID = $this->decryptSteamID($_COOKIE['SteamSession']);
        }

        if ($this->isLogged()) {
            $this->updateData();
        } elseif ($this->getLoginState() === 1){
            $this->validateLogin($loginURL);
        }
    }

    /**
     * Get info about a steam user.
     *
     * @param $steamid64 mixed SteamID64 of the user.
     */
    function getPlayerSum($steamid64){
        $this->SSteamID = $steamid64;
        $this->updateData();
    }

    /**
     * This operation should be considerate heavy, and be done only when strictly required.
     * @return string Login URL
     * @throws ErrorException
     */
    function getLoginURL(){
        return $this->OpenID->authUrl();
    }
    
    /**
     * Returns:
     * 0 -> The client need to login into steamcommunity.
     * 1 -> The login needs to be validated
     * 2 -> The client is already logged
     * -1 -> The login was aborted.
     * @return int;
     */
    private function getLoginState(){
        if (!empty($this->SSteamID)){
            return 2;
        }

        $mode = $this->OpenID->mode;
        if (!$mode) {
            return 0;
        } elseif ($mode === "cancel") {
            return -1;
        } else {
            return 1;
        }
    }


    /**
     * Validates a client login.
     * @param $url string Where to redirect after the successful login.
     * @return bool Array if the login needs to be validated, false if not.
     * @throws ErrorException
     *
     */
    private function validateLogin($url){
        if ($this->OpenID->validate()) {
            $id = $this->OpenID->identity;
            $ptn = "/^https?:\/\/steamcommunity\.com\/openid\/id\/(7[0-9]{15,25}+)$/";
            preg_match($ptn, $id, $matches);

            setcookie("SteamSession", $this->encryptSteamID($matches[1]), $this->expire, "/", $_SERVER['SERVER_NAME'], $this->useSSL, true);
            $this->SSteamID = $matches[1];

            $this->updateData();
            header("Location: " .$url);
            return true;
        } else {
            return false;
        }
    }

    /**
     * Returns if a client is logged with steam or not.
     * @return bool True if the user is logged, false otherwise
     */
    function isLogged(){
        return !empty($this->SSteamID);
    }

    /**
     *
     * @param string $logoutURL Where to redirect after logout. If empty no redirect will happen.
     * @return bool False if the logout fail (user not logged in), true otherwise.
     */
    function logout($logoutURL = ""){
        if (empty($this->SSteamID)){
            return false;
        } else {
            setcookie("SteamSession", "", time() - 3600, "/", $_SERVER['SERVER_NAME'], $this->useSSL, true);
            $this->SSteamID = "";
            $this->purgeData();
        }
        if (!empty($logoutURL)){
            header("Location: " .$logoutURL);
        }
        return true;
    }
    
    /**
     * Update the user data from steam API
     * @noreturn
     */
    function updateData(){

        //Player sum
        $url = file_get_contents("https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=" .$this->APIkey. "&steamids=" .$this->SSteamID);
        $data = json_decode($url, true);
        $player = $data['response']['players'][0];

        //Public data
        $this->steamid = $player['steamid']; //SteamID64
        $this->username = $player['personaname']; //Display name
        $this->profile = $player['profileurl']; //Community profile URL
        $this->avatar = $player['avatar']; //Avatar 32x32
        $this->avatarm = $player['avatarmedium']; //Avatar 64x64
        $this->avatarf = $player['avatarfull']; //Avatar 184x184
        $this->personaState = $player['personastate']; //User's status
        $this->visState = $player['communityvisibilitystate']; //Profile visibility status
        $this->profileState = $player['profilestate']; //Profile configurated or not
        $this->lastLogoff = $player['lastlogoff']; //Last user online time
        $this->commentPerm = $player['commentpermission']; //Comment permission

        //Private data
        $this->realName =  isset($player['realname'])? $player['realname'] : ""; //User's realname
        $this->primaryClan = isset($player['primaryclanid'])? $player['primaryclanid'] : 0; //User's primary clan id
        $this->timeCreated = isset($player['timecreated'])? $player['timecreated'] : 0; //Account creation time
        $this->gameId = isset($player['gameid'])? $player['gameid'] : 0; //Playing game id
        $this->gameServerIP = isset($player['gameserverip'])? $player['gameserverip'] : "0.0.0.0"; //Playing server ip
        $this->gameExtraInfo = isset($player['gameextrainfo'])? $player['gameextrainfo'] : ""; //Playing game name
        $this->countryCode = isset($player['loccountrycode'])? $player['loccountrycode'] : 0; //Country of residence code
        $this->stateCode = isset($player['locstatecode'])? $player['locstatecode'] : 0; //State of residence code
        $this->cityId = isset($player['loccityid'])? $player['loccityid'] : 0; //City of residence id

        //Unknown
        $this->personaStateFlags = isset($player['personastateflags'])? $player['personastateflags'] : 0;
        
        //Player friends
        $url = file_get_contents("https://api.steampowered.com/ISteamUser/GetFriendList/v0001/?key=" .$this->APIkey. "&steamid=" .$this->SSteamID);
        $this->friends = json_decode($url, true);
        
        $this->playerInfo['PlayerSummaries'] = $player;
        $this->playerInfo['Friends'] = $this->friends;
    }


    private function purgeData(){
        //Public data
        $this->steamid = '';
        $this->username = '';
        $this->profile = '';
        $this->avatar = '';
        $this->avatarm = '';
        $this->avatarf = '';
        $this->personaState = '';
        $this->visState = '';
        $this->profileState = '';
        $this->lastLogoff = '';
        $this->commentPerm = '';
        
        //Private data
        $this->realName = '';
        $this->primaryClan = '';
        $this->timeCreated = '';
        $this->gameId = '';
        $this->gameServerIP = '';
        $this->gameExtraInfo = '';
        $this->countryCode = '';
        $this->stateCode = '';
        $this->cityId = '';

        //Unknown
        $this->personaStateFlags = '';

        //Player friends
        $this->friends = '';

        //All info
        $this->playerInfo = array();
    }

    //Encrypt data
    private function encryptSteamID($string){
        return base64_encode(openssl_encrypt($string, $this->encrypt_method, $this->key));
    }

    //Decrypt data
    private function decryptSteamID($string){
        return openssl_decrypt(base64_decode($string), $this->encrypt_method, $this->key);
    }

    /**
     * @param $name mixed Property name.
     * @return mixed Property value.
     * @throws Exception
     */
    public function __get($name) {
        $rp = new ReflectionProperty($this, $name);
        if ($rp->isPrivate())
            die("Cannot access private property");

        if (isset($this->$name)) {
            return $this->$name;
        } else {
            throw new Exception( "Call to nonexistent '$name' property of MyClass class" );
        }
    }
}
