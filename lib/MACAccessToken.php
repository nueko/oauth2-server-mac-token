<?php

namespace OAuth2\Token;

use OAuth2\Token\AccessToken;
use OAuth2\Token\MACAccessTokenInterface;
use OAuth2\Exception\NotImplementedException;

abstract class MACAccessToken extends AccessToken implements MACAccessTokenInterface
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
                throw new NotImplementedException('invalid_algorithm', "The algorithm '$algorithm' is not implemented");
        }
    }
}
