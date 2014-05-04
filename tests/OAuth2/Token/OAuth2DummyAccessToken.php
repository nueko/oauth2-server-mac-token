<?php

namespace OAuth2\Token;

use OAuth2\Token\OAuth2AccessToken;
use OAuth2\Token\IOAuth2AccessToken;

class OAuth2DummyAccessToken extends OAuth2AccessToken implements IOAuth2AccessToken
{
    
    public function toArray()
    {
        return parent::toArray()+array(
           'token_type' => 'Dummy',
        );
    }
}
