<?php

namespace OAuth2\Token;

use OAuth2\Token\IOAuth2AccessToken;
use OAuth2\Token\OAuth2MACAccessTokenManager;

class OAuth2MACAccessTokenManagerStub extends OAuth2MACAccessTokenManager
{
    protected $accessTokens = array();

    protected function addAccessToken(IOAuth2AccessToken $token) {

        $this->accessTokens[$token->getToken()] = $token;
        return $this;
    }

    protected function getAccessToken($token) {

        return isset($this->accessTokens[$token])?$this->accessTokens[$token]:null;
    }
}
