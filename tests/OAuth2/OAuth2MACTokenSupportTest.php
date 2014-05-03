<?php

namespace OAuth2;

use OAuth2\Token\IOAuth2MACAccessToken;
use OAuth2\Token\OAuth2MACAccessToken;
use OAuth2\Token\OAuth2MACAccessTokenManager;
use OAuth2\Client\OAuth2PublicClient;
use OAuth2\Configuration\OAuth2Configuration;
use Symfony\Component\HttpFoundation\Request;
use OAuth2\Token\OAuth2TestGenerator;

/**
 * @group TokenSupports
 */
class OAuth2MACTokenSupportTest extends \PHPUnit_Framework_TestCase
{
    public function testArray()
    {
        $client = new OAuth2PublicClient("foo");
        $token = new OAuth2MACAccessToken($client, 'jd93dh9dh39D', '8yfrufh348h', 'sha1', time() + 1000, 'foo bar baz', 'data');

        $this->assertEquals($token->toArray(), array(
           'access_token' => 'jd93dh9dh39D',
           'token_type' => 'MAC',
           'expires_in' => 1000,
           'key' => '8yfrufh348h',
           'algorithm' => 'hmac-sha-1',
           'scope' => 'foo bar baz',
        ));
    }

    /** 
     * @dataProvider getTestAccessTokenData
     */
    public function testAccessToken(IOAuth2MACAccessToken $token, Request $request, $expectedSameToken, $expectedIsValid = null)
    {
        $support = new OAuth2MACAccessTokenManager(new OAuth2Configuration(), new OAuth2TestGenerator);

        $tokenId = $support->findAccessToken($request);
        $isValid = $support->isAccessTokenValid($request, $token);
        if($expectedSameToken === true) {
            $this->assertSame($isValid, $expectedIsValid);
        } else {
            $this->assertFalse($tokenId === $token->getToken());
        }

    }

    public function getTestAccessTokenData()
    {
        $client = new OAuth2PublicClient("foo");
        return array(
            array(
                new OAuth2MACAccessToken($client, 'jd93dh9dh39D', '8yfrufh348h', 'sha1', time() + 1000, 'foo bar baz', 'data'),
                $this->createRequest(
                    '/request',
                    'POST',
                    array('CONTENT_TYPE' => 'application/x-www-form-urlencoded'),
                    'hello=world%21',
                    array(
                        'HOST' => 'example.com',
                        'AUTHORIZATION' => 'MAC id="jd93dh9dh39D",nonce="273156:di3hvdf8",bodyhash="k9kbtCIy0CkI3/FEfpS/oIDjk6k=",mac="W7bdMZbv9UWOTadASIQHagZyirA="',
                    )
                ),
                true,
                true,
            ),
            array(
                new OAuth2MACAccessToken($client, 'jd93dh9dh39D', '8yfrufh348h', 'sha1', time() + 1000, 'foo bar baz', 'data'),
                $this->createRequest(
                    '/request',
                    'POST',
                    array('CONTENT_TYPE' => 'application/x-www-form-urlencoded'),
                    'hello=world%21',
                    array(
                        'HOST' => 'example.com',
                        'AUTHORIZATION' => 'MAC id="jd93dh9dh39D",nonce="273156:di3hvdf8",mac="+2eC5lk+s+9xpEtpwrPQ32Oo8GU="',
                    )
                ),
                true,
                true,
            ),
            array(
                new OAuth2MACAccessToken($client, 'jd93dh9dh39D', '8yfrufh348h', 'sha1', time() + 1000, 'foo bar baz', 'data'),
                $this->createRequest(
                    '/request',
                    'POST',
                    array('CONTENT_TYPE' => 'application/x-www-form-urlencoded'),
                    'hello=world%21',
                    array(
                        'HOST' => 'example.com',
                        'AUTHORIZATION' => 'MAC id="jd93dh9dh39D",nonce="273156:di3hvdf8",bodyhash="k9kbtCIy0CkI3/FEfpS/oIDjk6k=",mac="nU2i+PEfRrULhYhnadHvo99vGjQ=",ext="a,b,c,d"',
                    )
                ),
                true,
                true,
            ),
            array(
                new OAuth2MACAccessToken($client, 'jd93dh9dh39D', '8yfrufh348h', 'sha1', time() + 1000, 'foo bar baz', 'data'),
                $this->createRequest(
                    '/request',
                    'POST',
                    array('CONTENT_TYPE' => 'application/x-www-form-urlencoded'),
                    'hello=world%21',
                    array(
                        'HOST' => 'example.com',
                        'AUTHORIZATION' => 'MAC id="jd93dh9dh39D",nonce="273156:di3hvdf8",mac="kX94DpXtNSKUrx0O4V9xYUKB2ws=",ext="a,b,c,d"',
                    )
                ),
                true,
                true,
            ),
            array(
                new OAuth2MACAccessToken($client, 'jd93dh9dh39D', '8yfrufh348h', 'sha1', time() + 1000, 'foo bar baz', 'data'),
                $this->createRequest(
                    '/request',
                    'POST',
                    array('CONTENT_TYPE' => 'application/x-www-form-urlencoded'),
                    'hello=world%21',
                    array(
                        'HOST' => 'example.com',
                    )
                ),
                false,
            ),
            array(
                new OAuth2MACAccessToken($client, 'jd93dh9dh39D', '8yfrufh348h', 'sha1', time() + 1000, 'foo bar baz', 'data'),
                $this->createRequest(
                    '/request',
                    'POST',
                    array('CONTENT_TYPE' => 'application/x-www-form-urlencoded'),
                    'hello=world%21',
                    array(
                        'HOST' => 'example.com',
                        'AUTHORIZATION' => 'MAC id="jd93dh9dh39D",bodyhash="k9kbtCIy0CkI3/FEfpS/oIDjk6k=",mac="W7bdMZbv9UWOTadASIQHagZyirA="',
                    )
                ),
                true,
                false
            ),
            array(
                new OAuth2MACAccessToken($client, 'jd93dh9dh39', '8yfrufh348h', 'sha1', time() + 1000, 'foo bar baz', 'data'),
                $this->createRequest(
                    '/request',
                    'POST',
                    array('CONTENT_TYPE' => 'application/x-www-form-urlencoded'),
                    'hello=world%21',
                    array(
                        'HOST' => 'example.com',
                        'AUTHORIZATION' => 'MAC id="jd93dh9dh39D",nonce="273156:di3hvdf8",bodyhash="k9kbtCIy0CkI3/FEfpS/oIDjk6k=",mac="W7bdMZbv9UWOTadASIQHagZyirA="',
                    )
                ),
                true,
                false
            ),
            array(
                new OAuth2MACAccessToken($client, 'jd93dh9dh39D', '8yfrufh348h', 'sha1', time() + 1000, 'foo bar baz', 'data'),
                $this->createRequest(
                    '/request',
                    'POST',
                    array('CONTENT_TYPE' => 'application/x-www-form-urlencoded'),
                    'hello=world%21',
                    array(
                        'HOST' => 'example.com',
                        'AUTHORIZATION' => 'MAC id="jd93dh9dh39D",nonce="273156:di3hvdf8",bodyhash="k9kbtCIy0CkI3/FEfpS/oIDjk5k=",mac="W7bdMZbv9UWOTadASIQHagZyirA="',
                    )
                ),
                true,
                false
            ),
            array(
                new OAuth2MACAccessToken($client, 'jd93dh9dh39D', '8yfrufh348h', 'sha1', time() + 1000, 'foo bar baz', 'data'),
                $this->createRequest(
                    '/request',
                    'POST',
                    array('CONTENT_TYPE' => 'application/x-www-form-urlencoded'),
                    'hello=world%21',
                    array(
                        'HOST' => 'example.com',
                        'AUTHORIZATION' => 'Bearer jd93dh9dh39D',
                    )
                ),
                false
            ),
        );
    }

    /**
     * @param string $uri
     * @param string $content
     */
    protected function createRequest($uri, $method = 'GET', array $server = array(), $content = null, array $headers = array() )
    {
        $request = Request::create($uri,$method, array(), array(), array(), $server, $content);

        foreach ($headers as $key => $value) {
            $request->headers->set($key, $value);
        }
        return $request;
    }
}
