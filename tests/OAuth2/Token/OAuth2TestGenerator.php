<?php

namespace OAuth2\Token;

use OAuth2\Token\IOAuth2Generator;

class OAuth2TestGenerator implements IOAuth2Generator
{
    /**
     * @param integer $length
     */
    public static function getRandomString($length) {
        $alphanum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        $result = '';
        for ($cptr=0; $cptr < $length; $cptr++) { 
            $result .= substr($alphanum, rand(0,strlen($alphanum)-1),1);
        }
        return empty($result)?false:$result;
    }
}
