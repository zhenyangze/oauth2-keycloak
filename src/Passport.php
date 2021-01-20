<?php

namespace Stevenmaguire\OAuth2\Client;

use League\OAuth2\Client\Token\AccessToken;
use Stevenmaguire\OAuth2\Client\Adapter\AdapterAbstract;
use Stevenmaguire\OAuth2\Client\Adapter\DefaultAdapter;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak;

/**
 *  Passport
 */
class Passport
{
    /**
     * provider
     */
    private $provider;
    /**
     * userInfo
     */
    private $userInfo;
    /**
     * adapter
     */
    private $adapter;

    /**
     * accessToken
     */
    private $accessToken;

    /**
     * token
     */
    private $token;

    /**
     * instance
     */
    static private $instance;

    /**
     * MODEL_TOKEN
     */
    static public $MODEL_TOKEN = 1; // only use token
    /**
     * MODEL_REFRESH_TOKEN
     */
    static public $MODEL_REFRESH_TOKEN = 2; // toekn + refreshToken

    /**
     * model
     */
    private $model;


    /**
     * __construct 
     *
     * @param $config
     * @param $adapter
     *
     * @return 
     */
    private function __construct($config = [], AdapterAbstract $adapter = null, $model = 2){
        $this->provider  = new Keycloak($config);
        $this->adapter = empty($adapter) ? new DefaultAdapter : $adapter;
        $this->model = $model;
        /*$this->provider  = new Keycloak([
            'authServerUrl' => 'http://127.0.0.1:8080/auth',
            'realm'         => 'real-demo',
            'clientId'      => 'backend',
            'clientSecret'  => '9030c395-1ffa-44ad-99ba-e2aba9586822',
            'redirectUri'   => 'http://127.0.0.1:8003/auth',
        ]);*/
    }

    /**
     * __clone 
     *
     * @return 
     */
    private function __clone(){

    }

    /**
     * connect 
     *
     * @param $config
     * @param $adapter
     * @param $model
     *
     * @return 
     */
    static public function init($config = [], AdapterAbstract $adapter = null, $model = 2)
    {
        if (!self::$instance instanceof self) {
            self::$instance = new self($config, $adapter, $model);
        }
        return self::$instance;
    }

    /**
     * isLogin 
     *
     * @return 
     */
    public function isLogin()
    {
        return !empty($this->userInfo);
    }

    /**
     * checkLogin 
     *
     * @param $autoJump
     *
     * @return 
     */
    public function checkLogin($autoJump = true)
    {
        if (!empty($this->userInfo)) {
            return $this->userInfo;
        }

        $user = null;
        try {
            $this->accessToken = $accessToken = $this->getAccessTokenFromServer();
            $this->token = $token = $this->getAccessTokenEntity($accessToken);

            if ($this->model == self::$MODEL_REFRESH_TOKEN && $token->hasExpired()) {
                $this->token = $token = $this->getTokenByRefreshToken($token);
            }
            $user = $this->getUserInfoByToken($token);
        } catch (\Exception $e) {
            $this->adapter->log($e);
        }

        if (empty($user) && $autoJump){
            $this->Auth();
        } else if (empty($user) && !$autoJump) {
            return null;
        }

        $this->userInfo = $user;
        return $this->userInfo;
    }

    /**
     * getAccessTokenEntity 
     *
     * @param $accessToken
     *
     * @return 
     */
    protected function getAccessTokenEntity($accessToken)
    {
        $tokenArr = [];

        if ($this->model == self::$MODEL_REFRESH_TOKEN) {
            $tokenArr = $this->adapter->getToken($accessToken);
        }
       
        if (empty($tokenArr)) {
            $tokenArr = [
                'access_token' => $accessToken,
            ];
        }
        
        if (is_object($tokenArr) && $tokenArr instanceof AccessToken) {
            return $tokenArr;
        }

        return new AccessToken($tokenArr);
    }

    /**
     * getAccessToken 
     *
     * @return 
     */
    public function getAccessToken()
    {
        if (empty($this->accessToken)) {
            $this->accessToken = $this->adapter->getAccessToken();
        }

        return $this->accessToken;
    }

    /**
     * getToken 
     *
     * @return 
     */
    public function getToken()
    {
        if (empty($this->token)) {
            $accessToken = $this->getAccessToken();
            if (!empty($accessToken)) {
                $this->token = $this->adapter->getToken($accessToken);
            }
        }
        return $this->token;
    }


    /**
     * getAccessTokenFromServer 
     *
     * @return 
     */
    protected function getAccessTokenFromServer()
    {
        $accessToken = $this->adapter->getAccessToken();
        if (empty($accessToken)) {
            // get code from url
            $code = $this->adapter->getCode();
            $accessToken = $this->getTokenByCode($code);
        }

        return $accessToken;
    }

    /**
     * Auth 
     *
     * @return 
     */
    public function Auth()
    {
        $this->clearRecord();
        header('Location: ' . $this->getAuthorizationUrl());
        exit;
    }

    protected function clearRecord()
    {
        $this->accessToken = '';
        $this->adapter->saveAccessToken('');
    }

    /**
     * getAuthorizationUrl 
     *
     * @return 
     */
    public function getAuthorizationUrl()
    {
        return $this->provider->getAuthorizationUrl();
    }

    /**
     * logout 
     *
     * @return 
     */
    public function logout()
    {
        $this->clearRecord();
        header('Location: ' . $this->getLogoutUrl());
        exit;
    }

    /**
     * getLogoutUrl 
     *
     * @return 
     */
    public function getLogoutUrl()
    {
        return $this->provider->getLogoutUrl();
    }

    /**
     * getUserInfo 
     *
     * @return 
     */
    public function getUserInfo()
    {
        return $this->checkLogin(false);
    }

    /**
     * setModel 
     *
     * @param $model
     *
     * @return 
     */
    public function setModel($model = 1)
    {
        $this->model = $model;
    }

    /**
     * getTokenByCode 
     *
     * @param $code
     *
     * @return 
     */
    protected function getTokenByCode($code = '')
    {
        if (empty($code)) {
            throw new \Exception("passport empty code");
            $this->Auth();
        }

        $token = $this->provider->getAccessToken('authorization_code', [
            'code' => $code
        ]);
        $accessToken = $token->getToken();

        // 服务器中记录对应的信息
        $this->adapter->saveAccessToken($token->getToken());
        $this->adapter->saveToken($token->getToken(), $token->jsonSerialize(), ($token->getExpires() + 6000 - time()));

        return $accessToken;
    }

    /**
     * getUserInfoByToken 
     *
     * @param $token
     *
     * @return 
     */
    protected function getUserInfoByToken($token)
    {
        return $this->provider->getResourceOwner($token);
    }

    /**
     * getTokenByRefreshToken 
     *
     * @param $token
     *
     * @return 
     */
    protected function getTokenByRefreshToken($token)
    {
        $token = $this->provider->getAccessToken('refresh_token', [
            'refresh_token' => $token->getRefreshToken()
        ]);
        // 服务器中记录对应的信息
        $this->adapter->saveToken($token->getToken(), $token->jsonSerialize(), ($token->getExpires() + 1000 - time()));
        $this->adapter->saveAccessToken($token->getToken());
        return $token;
    }
}
