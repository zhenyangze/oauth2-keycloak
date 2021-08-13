<?php

namespace Stevenmaguire\OAuth2\Client;


use Firebase\JWT\JWT;

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
            return false;
        }

        $certsUrl = sprintf('%s/auth/realms/%s/protocol/openid-connect/certs', $authServerUrl, $realm);
        $client = new GuzzleHttp\Client();
        $res = $client->request('GET', $certsUrl);
        $result = $res->getBody();
        $certInfo = @json_decode($result, true);
        if (empty($certInfo) || !isset($certInfo['keys'])) {
            return false;
        }

        $certKeyInfo = reset($certInfo['keys']);

        $algList = explode(',', $certKeyInfo['alg']);
        $publicKey = reset($certKeyInfo['x5c']);
        if (empty($publicKey)) {
            return false;
        }

        $publicKey = <<<EOF
-----BEGIN CERTIFICATE-----
$publicKey
-----END CERTIFICATE-----
EOF;
        return JWT::decode($token, $key, $algList);
    }
}
