<?php

namespace OAuth2\Token;

use OAuth2\Token\IOAuth2Generator;

class OAuth2DummyGenerator implements IOAuth2Generator
{
    /**
     * @param integer $length
     */
    public static function getRandomString($length) {
        return false;
    }
}
