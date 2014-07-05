<?php

namespace OAuth2\Token;

use OAuth2\Token\IOAuth2AccessToken;

/**
 */
interface IOAuth2MACAccessToken extends IOAuth2AccessToken
{
    /**
     * @return string
     */
    public function getKey();

    /**
     * @return string
     */
    public function getAlgorithm();
}
