<?php

namespace OAuth2\Token;

use OAuth2\Client\IOAuth2Client;
use OAuth2\Token\IOAuth2AccessToken;
use OAuth2\Token\OAuth2MACAccessToken;
use OAuth2\Token\OAuth2MACAccessTokenManager;
use OAuth2\ResourceOwner\IOAuth2ResourceOwner;

class OAuth2MACAccessTokenManagerStub extends OAuth2MACAccessTokenManager
{
    protected $accessTokens = array();

    protected function addAccessToken($token, $expiresAt, IOAuth2Client $client, $scope = null, IOAuth2ResourceOwner $resourceOwner = null) {

        $key   = $this->generator->getRandomString($this->configuration->getOption('mac_access_token_key_length', 10));
        $algo  = $this->configuration->getOption('mac_access_token_algorithm', 'sha1');

        $access_token = new OAuth2MACAccessToken($client, $token, $key, $algo, $expiresAt, $scope, $resourceOwner);

        $this->accessTokens[$token] = $access_token;
        return $access_token;
    }

    protected function getAccessToken($token) {

        return isset($this->accessTokens[$token])?$this->accessTokens[$token]:null;
    }
}
