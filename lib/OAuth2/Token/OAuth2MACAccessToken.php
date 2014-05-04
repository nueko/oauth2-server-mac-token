<?php

namespace OAuth2\Token;

use OAuth2\Token\OAuth2AccessToken;
use OAuth2\Token\IOAuth2MACAccessToken;
use OAuth2\Client\IOAuth2Client;
use OAuth2\Exception\OAuth2NotImplementedException;

class OAuth2MACAccessToken extends OAuth2AccessToken implements IOAuth2MACAccessToken
{
    protected $key;

    protected $algorithm;

    /**
     * @param IOAuth2Client $client_id
     * @param string        $token
     * @param string        $key
     * @param string        $algorithm
     * @param null|integer  $expiresAt
     * @param null|string   $scope
     * @param string|null   $data
     */
    public function __construct(IOAuth2Client $client_id, $token, $key, $algorithm, $expiresAt = null, $scope = null, $data = null)
    {
        $this->key = $key;
        $this->algorithm = $algorithm;
        parent::__construct($client_id, $token, $expiresAt, $scope, $data);
    }

    public function getKey() {
        return $this->key;
    }

    public function getAlgorithm() {
        return $this->algorithm;
    }
    
    public function toArray()
    {
        return parent::toArray()+array(
           'token_type' => 'mac',
           'mac_key' => $this->getKey(),
           'mac_algorithm' => self::convertAlgorithm($this->getAlgorithm()),
        );
    }

    /**
     * @param string $algorithm
     */
    protected static function convertAlgorithm($algorithm)
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
