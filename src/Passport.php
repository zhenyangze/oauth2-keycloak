<?php

namespace Stevenmaguire\OAuth2\Client;

use League\OAuth2\Client\Token\AccessToken;
use Stevenmaguire\OAuth2\Client\Adapter\AdapterAbstract;
use Stevenmaguire\OAuth2\Client\Adapter\DefaultAdapter;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak;
use Stevenmaguire\OAuth2\Client\Provider\KeycloakResourceOwner;
use Stevenmaguire\OAuth2\Client\Provider\Exception\PassportRuntimeException;
use Stevenmaguire\OAuth2\Client\Provider\TokenUtil;

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
     * config
     */
    private $config;

    /**
     * idleTime
     */
    public $idleTime = 3600;

    /**
     * lifespanRatio
     */
    public $lifespanRatio = 0.834;

    /**
     * expired
     */
    protected $expired = true;

    /**
     * __construct 
     *
     * @param $config
     * @param $adapter
     *
     * @return 
     */
    private function __construct($config = [], AdapterAbstract $adapter = null, $model = 2)
    {
        $this->config = $config;;
        $this->provider  = new Keycloak($config);
        $this->adapter = empty($adapter) ? new DefaultAdapter : $adapter;
        $this->model = $model;

        if (isset($this->config['idleTime']) && $this->config['idleTime'] > 0) {
            $this->idleTime = $this->config['idleTime'];
        }
    }

    /**
     * __clone 
     *
     * @return 
     */
    private function __clone()
    {
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
     * @return KeycloakResourceOwner
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

            $userInfo = $this->parseToken($this->accessToken);

            if (!empty($userInfo)) {
                $user = $userInfo;
            } else {
                if ($this->model == self::$MODEL_REFRESH_TOKEN && !empty($token->getExpires()) && $this->expired) {
                    $this->token = $token = $this->getTokenByRefreshToken($token);
                }
                $user = $this->getUserInfoByToken($token);
            }
        } catch (PassportRuntimeException $e) {
            $this->adapter->log($e);
            if (empty($user) && $autoJump) {
                $this->clearRecord();
                $this->Auth();
            } else if (empty($user) && !$autoJump) {
                return null;
            }
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

    /**
     * * clearRecord 
     * *
     * * @return 
     * */
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
        return $this->callProviderMethod('getAuthorizationUrl');
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
        return $this->callProviderMethod('getLogoutUrl');
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
            throw new PassportRuntimeException("passport empty code");
        }

        $token = $this->callProviderMethod('getAccessToken', [
            'authorization_code',
            [
                'code' => $code
            ]
        ]);

        $accessToken = $token->getToken();

        $this->saveToken($token);

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
        return $this->callProviderMethod('getResourceOwner', [$token]);
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
        $token = $this->callProviderMethod('getAccessToken', [
            'refresh_token',
            [
                'refresh_token' => $token->getRefreshToken()
            ]
        ]);
        $this->saveToken($token);
        return $token;
    }

    /**
     * saveToken 
     *
     * @param $token
     *
     * @return 
     */
    protected function saveToken($token = null)
    {
        if (!($token instanceof AccessToken)) {
            return;
        }
        $this->adapter->saveAccessToken($token->getToken(), ($token->getExpires() + $this->idleTime - time()));
        $this->adapter->saveToken($token->getToken(), $token->jsonSerialize(), ($token->getExpires() + $this->idleTime - time()));
    }

    /**
     * parseToken 
     *
     * @param $accessToken
     *
     * @return array
     */
    public function parseToken($accessToken = '')
    {
        $accessTokenArr = explode('.', $accessToken);
        if (count($accessTokenArr) != 3) {
            throw new PassportRuntimeException("error token");
        }

        $authUrl = $this->config['authServerUrl'] ?? '';
        $realm = $this->config['realm'] ?? '';
        try {
            $userInfo = TokenUtil::parseToken($accessToken, $authUrl, $realm);
        } catch (\Exception $e) {
            throw new PassportRuntimeException("parse token error");
        }

        if (empty($userInfo)) {
            throw new PassportRuntimeException("empty userinfo");
        }

        if ($this->isNeedRefresh($userInfo)) {
            return null;
        }

        if (!$this->checkPes($userInfo)) {
            return null;
        }

        $disabkeKey = ['exp', 'iat', 'auth_time', 'jti', 'iss', 'aud', 'typ', 'azp', 'session_state', 'acr', 'resp', 'scope'];
        foreach ($disabkeKey as $key) {
            if (isset($userInfo[$key])) {
                unset($userInfo[$key]);
            }
        }

        return new KeycloakResourceOwner($userInfo);
    }

    /**
     * checkPes 
     *
     * @param $userInfo
     *
     * @return 
     */
    protected function checkPes($userInfo = [])
    {
        if (!isset($this->config['periodNoCheck']) || !isset($this->config['periodCheck'])) {
            return false;
        }

        if (time() > $userInfo['exp'] || time() < $userInfo['iat']) {
            return false;
        }

        if ($userInfo['iat'] <= 0 || $this->config['periodCheck'] <= 0) {
            return false;
        }

        if ($this->config['periodNoCheck'] <= 0 || $this->config['periodCheck'] <= 0) {
            return false;
        }

        $timeDiff = (time() - $userInfo['iat']) % ($this->config['periodNoCheck'] + $this->config['periodCheck']);

        if ($timeDiff > $this->config['periodNoCheck']) {
            return false;
        }

        return true;
    }

    /**
     * isNeedRefresh 
     *
     * @param $userInfo
     *
     * @return 
     */
    protected function isNeedRefresh($userInfo = [])
    {
        $this->expired = true;
        if ($this->model == self::$MODEL_REFRESH_TOKEN && time() < ($userInfo['iat'] + ($userInfo['exp'] - $userInfo['iat']) * $this->lifespanRatio)) {
            $this->expired = false;
        }

        return $this->expired;
    }

    /**
     * callProviderMethod 
     *
     * @param $method
     * @param $args
     *
     * @return 
     */
    protected function callProviderMethod($method, $args = [])
    {
        try {
            return call_user_func_array([$this->provider, $method], $args);
        } catch (\Exception $e) {
            throw new PassportRuntimeException($e->getMessage());
        }
    }
}
