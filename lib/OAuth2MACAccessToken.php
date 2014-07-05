<?php

namespace OAuth2\Token;

use OAuth2\Token\OAuth2AccessToken;
use OAuth2\Token\IOAuth2MACAccessToken;
use OAuth2\Exception\OAuth2NotImplementedException;

abstract class OAuth2MACAccessToken extends OAuth2AccessToken implements IOAuth2MACAccessToken
{
    public function getType()
    {
        return 'mac';
    }

    public function toArray()
    {
        return parent::toArray()+array(
           'mac_key' => $this->getKey(),
           'mac_algorithm' => $this->convertAlgorithm($this->getAlgorithm()),
        );
    }

    /**
     * @param string $algorithm
     */
    protected function convertAlgorithm($algorithm)
    {
        switch ($algorithm) {
            case 'sha1':
                return 'hmac-sha-1';
            case 'sha256':
                return 'hmac-sha-256';
            default:
                throw new OAuth2NotImplementedException('invalid_algorithm', "The algorithm '$algorithm' is not implemented");
        }
    }
}
