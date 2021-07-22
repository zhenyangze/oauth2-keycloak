<?php

namespace Stevenmaguire\OAuth2\Client\Adapter;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

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
        return request()->bearerToken();
    }

    /**
     * {@inheritDoc}
     */
    public function saveAccessToken($accessToken = '', $time = 60)
    {
        request()->headers->add([
            'New-Token' => $accessToken,
        ]);
    }

    /**
     * {@inheritDoc}
     */
    public function getToken($accessToken = '')
    {
        $tokenKey = 'token_' . md5($accessToken);
        return @json_decode(Cache::get($tokenKey), JSON_OBJECT_AS_ARRAY);
    }

    /**
     * {@inheritDoc}
     */
    public function saveToken($accessToken = '', $token, $time = 3600)
    {
        $tokenKey = 'token_' . md5($accessToken);
        Cache::put($tokenKey, json_encode($token), $time);
    }

    /**
     * {@inheritDoc}
     */
    public function getCode()
    {
        return request()->get('code');
    }

    /**
     * {@inheritDoc}
     */
    public function log($e)
    {
        if ($e instanceof \Exception) {
            Log::error($e->getMessage());
        } else if (is_string($e)) {
            Log::error($e);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function getPermissionToken($clientId, $accessToken = '')
    {
        $tokenKey = 'token_permission_' . md5($accessToken) . '_' . $clientId;
        return @json_decode(Cache::get($tokenKey), JSON_OBJECT_AS_ARRAY);
    }

    /**
     * {@inheritDoc}
     */
    public function savePermissionToken($clientId, $accessToken = '', $token, $time = 3600)
    {
        $tokenKey = 'token_permission_' . md5($accessToken) . '_' . $clientId;
        Cache::put($tokenKey, json_encode($token), $time);
    }
}
