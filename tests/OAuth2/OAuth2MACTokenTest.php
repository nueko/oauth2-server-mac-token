<?php

namespace OAuth2;

use OAuth2\Token\OAuth2MACAccessToken;
use OAuth2\Client\OAuth2PublicClient;
use OAuth2\Exception\OAuth2NotImplementedException;

class OAuth2MACTokenTest extends \PHPUnit_Framework_TestCase
{
    public function testArray()
    {
        $client = new OAuth2PublicClient("foo");
        $token1 = new OAuth2MACAccessToken($client, 'jd93dh9dh39D', '8yfrufh348h', 'sha1', time() + 1000, 'foo bar baz', 'data');
        $token2 = new OAuth2MACAccessToken($client, 'jd93dh9dh39D', '8yfrufh348h', 'sha256', time() + 1000, 'foo bar baz', 'data');
        $token3 = new OAuth2MACAccessToken($client, 'jd93dh9dh39D', '8yfrufh348h', 'foo', time() + 1000, 'foo bar baz', 'data');

        $this->assertEquals($token1->toArray(), array(
           'access_token' => 'jd93dh9dh39D',
           'token_type' => 'MAC',
           'expires_in' => 1000,
           'key' => '8yfrufh348h',
           'algorithm' => 'hmac-sha-1',
           'scope' => 'foo bar baz',
        ));
        $this->assertEquals($token2->toArray(), array(
           'access_token' => 'jd93dh9dh39D',
           'token_type' => 'MAC',
           'expires_in' => 1000,
           'key' => '8yfrufh348h',
           'algorithm' => 'hmac-sha-256',
           'scope' => 'foo bar baz',
        ));

        try {
            $token3->toArray();
            $this->fail("The expected exception was not thrown");
        } catch (\Exception $e) {
            if(!$e instanceof OAuth2NotImplementedException){
                throw $e;
            }
            $this->assertSame('invalid_algorithm', $e->getMessage());
            $this->assertSame("The algorithm 'foo' is not implemented",$e->getDescription());
        }
    }
}
