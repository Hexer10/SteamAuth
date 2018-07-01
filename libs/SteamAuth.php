<?php
require "openid.php";

/**
 * This class provides a simple usage of the steam openid.
 *
 * It's properly tested only on PHP 7.2
 *
 * @version     v1.0 (2018-06-3)
 * @link        https://github.com/Hexer10/SteamAuth         GitHub Repo
 * @author      Mattia (Hexah/Hexer10) (hexer504@mail.com)
 * @copyright   Copyright (c) 2018 Mattia (Hexah/Hexer10) (hexer504@mail.com)
 * @license     http://opensource.org/licenses/mit-license.php  MIT License
 * @see         https://developer.valvesoftware.com/wiki/Steam_Web_API#GetPlayerSummaries_.28v0002.29 API Documentaion
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
    function initOpenID($loginURL, $secretKey, $cookieTime = '', $ssl = true){
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

    /** GET PUBLIC DATA */

    /**
     * 64bit SteamID of the user
     * @return mixed SteamID64.
     */
    function getSteamID(){
        return $this->steamid;
    }

    /**
     * The player's persona name (display name)
     * @return string Steam username.
     */
    function getUsername(){
        return $this->username;
    }

    /**
     * The full URL of the player's avatar.
     * @param int $type Avatar type: 0 = Normal(32x32), 1 = Medium(64x64), 2 = Full(184x184).
     * @return string Avatar URL.
     */
    function getAvatar($type = 0){
        if ($type === 0){
            return $this->avatar;
        } elseif ($type === 1){
            return $this->avatarm;
        } else {
            return $this->avatarf;
        }
    }

    /**
     * The user's current status. 0 - Offline or Private, 1 - Online, 2 - Busy, 3 - Away,
     *                            4 - Snooze, 5 - looking to trade, 6 - looking to play.
     * @return int Personal state.
     */
    function getPersonaState(){
        return $this->personaState;
    }

    /**
     * This represents whether the profile is visible or not, and if it is visible, why you are allowed to see it.
     * 1 - the profile is not visible to you (Private, Friends Only, etc),
     * 3 - the profile is "Public", and the data is visible.
     * @return int Visibility state.
     */
    function getVisibilityState(){
        return $this->visState;
    }

    /**
     * If set, indicates the user has a community profile configured (will be set to '1').
     * @return int Profile state.
     */
    function getProfileState(){
        return $this->profileState;
    }


    /**
     * The last time the user was online, in unix time.
     * @return int Last log off.
     */
    function getLastlogoff(){
        return $this->lastLogoff;
    }

    /**
     * If set, indicates the profile allows public comments.
     * @return int Comment permission.
     */
    function getCommentPermission(){
        return $this->commentPerm;
    }


    /** GET PRIVATE DATA */

    /**
     * The player's "Real Name", if they have set it.
     * @return string Real name.
     */
    function getRealName(){
        return $this->realName;
    }

    /**
     * The player's primary group, as configured in their Steam Community profile.
     * @return int Primary Clan ID.
     */
    function getPrimaryClan(){
        return $this->primaryClan;
    }

    /**
     * If the user is currently in-game, this value will be returned and set to the gameid of that game
     * @return int Playing game id.
     */
    function getGameId(){
        return $this->gameId;
    }

    /**
     * The ip and port of the game server the user is currently playing on,
     * if they are playing on-line in a game using Steam matchmaking. Otherwise will be set to "0.0.0.0:0".
     * @return string Game server IP.
     */
    function getGameServerIP(){
        return $this->gameServerIP;
    }

    /**
     * If the user is currently in-game, this will be the name of the game they are playing.
     * This may be the name of a non-Steam game shortcut.
     * @return string Game name.
     */
    function getGameExtraInfo(){
        return $this->gameExtraInfo;
    }

    /**
     * The time the player's account was created.
     * @return int Get timestamp of account creation.
     */
    function getTimeCreated(){
        return $this->timeCreated;
    }

    /**
     * If set on the user's Steam Community profile, The user's country of residence, 2-character ISO country code.
     * @return int Country code.
     */
    function getCountryCode(){
        return $this->countryCode;
    }

    /**
     * If set on the user's Steam Community profile, The user's state of residence.
     * @return int State code.
     */
    function getStateCode(){
        return $this->stateCode;
    }

    /**
     * An internal code indicating the user's city of residence
     * @return int City id.
     */
    function getCityID(){
        return $this->cityId;
    }


    //Unknown - Not listed on doc

    /**
     * @return int Personal state flags.
     */
    function getPersonaStateFlags(){
        return $this->personaStateFlags;
    }

    /** ADDITIONAL PRIVATE DATA from other APIs */

    /**
     * Get an array filled with user's friend or a clear array if his profile is set to hide friends.
     * @return array Friends array or clear if profile is private.
     */
    function getFriends(){
        return $this->friends;
    }


    /**
     * Get all info gathered from a user.
     *
     * @return array Array filled with the user data.
     */
    function getData(){
        return $this->playerInfo;
    }
}
