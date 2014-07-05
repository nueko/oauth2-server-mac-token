<?php

namespace OAuth2\Test;

use OAuth2\Token\OAuth2MACAccessToken;

class OAuth2MACTokenTest extends \PHPUnit_Framework_TestCase
{
    public function testSha1()
    {
        $token = $this->createAccessToken('jd93dh9dh39D', 1000, '489dks293j39', 'sha1', 'foo bar baz');

        $this->assertEquals($token->toArray(), array(
           'access_token' => 'jd93dh9dh39D',
           'token_type' => 'mac',
           'expires_in' => 1000,
           'scope' => 'foo bar baz',
           'mac_key' => '489dks293j39',
           'mac_algorithm' => 'hmac-sha-1',
        ));
    }

    public function testSha256()
    {
        $token = $this->createAccessToken('jd93dh9dh39D', 1000, '489dks293j39', 'sha256', 'foo bar baz');

        $this->assertEquals($token->toArray(), array(
           'access_token' => 'jd93dh9dh39D',
           'token_type' => 'mac',
           'expires_in' => 1000,
           'scope' => 'foo bar baz',
           'mac_key' => '489dks293j39',
           'mac_algorithm' => 'hmac-sha-256',
        ));
    }

    /**
     * @expectedException OAuth2\Exception\OAuth2NotImplementedException invalid_algorithm
     */
    public function testBadAlgorithm()
    {
        $token = $this->createAccessToken('jd93dh9dh39D', 1000, '489dks293j39', 'foo-bar', 'foo bar baz');

        $token->toArray();
    }

    protected function createAccessToken($token = null, $getExpiresIn = null, $key = null, $algorithm = null, $scope = null)
    {
        $accessToken = $this->getMockBuilder('OAuth2\Token\OAuth2MACAccessToken')
            ->setMethods(array('getToken', 'getExpiresIn', 'getClient', 'getScope', 'getResourceOwner', 'hasExpired', 'getKey', 'getAlgorithm'))
            ->getMock();

        if (null !== $token)
        {
            $accessToken->expects($this->any())
                ->method('getToken')
                ->will($this->returnValue($token));
        }

        if (null !== $getExpiresIn)
        {
            $accessToken->expects($this->any())
                ->method('getExpiresIn')
                ->will($this->returnValue($getExpiresIn));
        }

        if (null !== $key)
        {
            $accessToken->expects($this->any())
                ->method('getKey')
                ->will($this->returnValue($key));
        }

        if (null !== $algorithm)
        {
            $accessToken->expects($this->any())
                ->method('getAlgorithm')
                ->will($this->returnValue($algorithm));
        }

        if (null !== $scope)
        {
            $accessToken->expects($this->any())
                ->method('getScope')
                ->will($this->returnValue($scope));
        }

        return $accessToken;
    }
}
