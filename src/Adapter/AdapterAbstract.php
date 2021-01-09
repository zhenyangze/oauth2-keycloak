<?php

namespace Stevenmaguire\OAuth2\Client\Adapter;

/**
 * Short description for AdapterAbstract.php
 *
 * @package AdapterAbstract
 * @author zhenyangze <zhenyangze@gmail.com>
 * @version 0.1
 * @copyright (C) 2021 zhenyangze <zhenyangze@gmail.com>
 * @license MIT
 */

/**
 * 
 */
abstract class AdapterAbstract
{
    /**
     * getAccessToken 
     *
     * @return 
     */
    abstract public function getAccessToken();
    /**
     * saveAccessToken 
     *
     * @return 
     */
    abstract public function saveAccessToken($accessToken = '');

    /**
     * getToken 
     *
     * @param $accessToken
     *
     * @return 
     */
    abstract public function getToken($accessToken = '');
    /**
     * saveToken 
     *
     * @param $accessToken
     * @param $token
     *
     * @return 
     */
    abstract public function saveToken($accessToken = '', $token);

    /**
     * getCode 
     *
     * @return 
     */
    abstract public function getCode();
}
