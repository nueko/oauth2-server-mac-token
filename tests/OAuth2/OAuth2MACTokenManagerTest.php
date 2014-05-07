<?php

namespace OAuth2;

use OAuth2\Token\IOAuth2MACAccessToken;
use OAuth2\Token\OAuth2MACAccessToken;
use OAuth2\Token\OAuth2MACAccessTokenManager;
use OAuth2\Token\OAuth2DummyAccessToken;
use OAuth2\Client\OAuth2PublicClient;
use OAuth2\Configuration\OAuth2Configuration;
use Symfony\Component\HttpFoundation\Request;
use OAuth2\Token\OAuth2TestGenerator;
use OAuth2\Token\OAuth2DummyGenerator;
use OAuth2\Exception\OAuth2InternalServerErrorException;
use OAuth2\ResourceOwner\OAuth2ResourceOwner;

class OAuth2MACTokenManagerTest extends \PHPUnit_Framework_TestCase
{
    public function testManagerToken()
    {
        $client = new OAuth2PublicClient("foo");
        $manager1 = new OAuth2MACAccessTokenManager(new OAuth2Configuration, new OAuth2TestGenerator);
        $manager2 = new OAuth2MACAccessTokenManager(new OAuth2Configuration(array('mac_access_token_algorithm'=>'sha256')), new OAuth2TestGenerator);
        $manager3 = new OAuth2MACAccessTokenManager(new OAuth2Configuration, new OAuth2DummyGenerator);

        $this->assertSame('MAC', $manager1->getAccessTokenType());

        $token = $manager1->createAccessToken($client)->toArray();
        $this->assertSame('hmac-sha-1', $token['mac_algorithm']);

        $token = $manager2->createAccessToken($client)->toArray();
        $this->assertSame('hmac-sha-256', $token['mac_algorithm']);

        try {
            $token = $manager3->createAccessToken($client);
            $this->fail("The expected exception was not thrown");
        } catch (\Exception $e) {
            if(!$e instanceof OAuth2InternalServerErrorException){
                throw $e;
            }
            $this->assertSame('token_creation_error', $e->getMessage());
            $this->assertSame("An error has occured during the creation of the token.",$e->getDescription());
        }

        $this->assertFalse($manager1->isAccessTokenValid(new Request, new OAuth2DummyAccessToken($client, 'foo')));
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
        $owner = new OAuth2ResourceOwner('username', 'secret');

        return array(
            array(
                new OAuth2MACAccessToken($client, 'jd93dh9dh39D', '8yfrufh348h', 'sha1', time() + 1000, 'foo bar baz', $owner),
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
                new OAuth2MACAccessToken($client, 'jd93dh9dh39D', '8yfrufh348h', 'sha1', time() + 1000, 'foo bar baz', $owner),
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
                new OAuth2MACAccessToken($client, 'jd93dh9dh39D', '8yfrufh348h', 'sha1', time() + 1000, 'foo bar baz', $owner),
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
                new OAuth2MACAccessToken($client, 'jd93dh9dh39D', '8yfrufh348h', 'sha1', time() + 1000, 'foo bar baz', $owner),
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
                new OAuth2MACAccessToken($client, 'jd93dh9dh39D', '8yfrufh348h', 'sha256', time() + 1000, 'foo bar baz', $owner),
                $this->createRequest(
                    '/request',
                    'POST',
                    array('CONTENT_TYPE' => 'application/x-www-form-urlencoded'),
                    'hello=world%21',
                    array(
                        'HOST' => 'example.com',
                        'AUTHORIZATION' => 'MAC id="jd93dh9dh39D",nonce="273156:di3hvdf8",mac="EhUEy9/msxEQJBkyimqrwkcmRDFKNgR9kKRZzHsb72E=",ext="a,b,c,d"',
                    )
                ),
                true,
                true,
            ),
            array(
                new OAuth2MACAccessToken($client, 'jd93dh9dh39D', '8yfrufh348h', 'sha256', time() + 1000, 'foo bar baz', $owner),
                $this->createRequest(
                    '/request',
                    'POST',
                    array('CONTENT_TYPE' => 'application/x-www-form-urlencoded'),
                    'hello=world%21',
                    array(
                        'HOST' => 'example.com',
                        'AUTHORIZATION' => 'MAC id="jd93dh9dh39D",nonce="273156:di3hvdf8",bodyhash="Z49JCJwhZyqL6ZBRQiZkF+oazFM4DcqCT3s/uYpPsik=",mac="LtZyOJ5mJQAy7GyqEZGT84u3GUKnx20i0nOXfNGZNLo=",ext="a,b,c,d"',
                    )
                ),
                true,
                true,
            ),
            array(
                new OAuth2MACAccessToken($client, 'jd93dh9dh39D', '8yfrufh348h', 'sha1', time() + 1000, 'foo bar baz', $owner),
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
                new OAuth2MACAccessToken($client, 'jd93dh9dh39D', '8yfrufh348h', 'sha1', time() + 1000, 'foo bar baz', $owner),
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
                new OAuth2MACAccessToken($client, 'jd93dh9dh39', '8yfrufh348h', 'sha1', time() + 1000, 'foo bar baz', $owner),
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
                new OAuth2MACAccessToken($client, 'jd93dh9dh39D', '8yfrufh348h', 'sha1', time() + 1000, 'foo bar baz', $owner),
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
                new OAuth2MACAccessToken($client, 'jd93dh9dh39D', '8yfrufh348h', 'sha1', time() + 1000, 'foo bar baz', $owner),
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
