<?php

namespace Stevenmaguire\OAuth2\Client\Provider;


use Firebase\JWT\JWT;
use GuzzleHttp\Client;

/**
 * Short description for Token.php
 *
 * @package Token
 * @author zhenyangze <zhenyangze@gmail.com>
 * @version 0.1
 * @copyright (C) 2021 zhenyangze <zhenyangze@gmail.com>
 * @license MIT
 */

class TokenUtil
{
    /**
     * checkToken 
     *
     * @param $token
     *
     * @return 
     */
    public static function parseToken($token = '', $authUrl = null, $realm = null)
    {
        if (empty($token) || empty($authUrl) || empty($realm)) {
            return null;
        }

        //todo:need cache
        $certsUrl = sprintf('%s/realms/%s/protocol/openid-connect/certs', $authUrl, $realm);
        $client = new Client();
        $res = $client->request('GET', $certsUrl);
        $result = $res->getBody();
        $certInfo = @json_decode($result, true);
        if (empty($certInfo) || !isset($certInfo['keys'])) {
            return null;
        }

        $certKeyInfo = reset($certInfo['keys']);

        $algList = explode(',', $certKeyInfo['alg']);
        $publicKey = reset($certKeyInfo['x5c']);
        if (empty($publicKey)) {
            return null;
        }

        $publicKey = <<<EOF
-----BEGIN CERTIFICATE-----
$publicKey
-----END CERTIFICATE-----
EOF;
        try {
            $payload = JWT::decode($token, $publicKey, $algList);
            return self::object2array($payload);
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * object2array 
     *
     * @param $object
     *
     * @return 
     */
    protected static function object2array($object = null)
    {
        return json_decode(json_encode($object), true);
    }
}
