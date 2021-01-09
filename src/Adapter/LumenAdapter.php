<?php

namespace Stevenmaguire\OAuth2\Client\Adapter;

use Illuminate\Support\Facades\Cookie;
use Cache;

/**
 * Short description for LumenAdapter.php
 *
 * @package LumenAdapter
 * @author zhenyangze <zhenyangze@gmail.com>
 * @version 0.1
 * @copyright (C) 2021 zhenyangze <zhenyangze@gmail.com>
 * @license MIT
 */

class LumenAdapter extends AdapterAbstract
{
    /**
     * {@inheritDoc}
     */
    public function getAccessToken()
    {
        return request()->cookie('token');
    }

    /**
     * {@inheritDoc}
     */
    public function saveAccessToken($accessToken = '')
    {
        Cookie::queue('token', $accessToken);
    }

    /**
     * {@inheritDoc}
     */
    public function getToken($accessToken = '')
    {
        return Cache::get($accessToken);
    }

    /**
     * {@inheritDoc}
     */
    public function saveToken($accessToken = '', $token)
    {
        Cache::put($accessToken, json_encode($token));
    }

    /**
     * {@inheritDoc}
     */
    public function getCode()
    {
        return \request('code');
    }
}
