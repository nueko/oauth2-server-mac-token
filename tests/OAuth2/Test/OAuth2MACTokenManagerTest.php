<?php

namespace OAuth2\Test;

use Symfony\Component\HttpFoundation\Request;

class OAuth2MACTokenManagerTest extends \PHPUnit_Framework_TestCase
{
    public function testFindWithoutAccessTokenInRequest()
    {
        $manager = $this->createAccessTokenManager();

        $result = $manager->findAccessToken($this->createRequest());
        $this->assertNull($result);
    }

    public function testAccessTokenInAuthorizationHeader()
    {
        $token = $this->createMACAccessToken();
        $manager = $this->createAccessTokenManager(array(
            array('foo', $token)
        ));

        $result = $manager->findAccessToken($this->createRequest('/', 'GET', array(), null, array('AUTHORIZATION'=>'MAC id="foo"')));
        $this->assertInstanceOf('OAuth2\Token\MACAccessToken', $result);
        $this->assertSame($token, $result);
    }

    public function testBadAccessTokenInAuthorizationHeader()
    {
        $manager = $this->createAccessTokenManager();

        $result = $manager->findAccessToken($this->createRequest('/', 'GET', array(), null, array('AUTHORIZATION'=>'Bearer foo')));
        $this->assertNull($result);
    }

    public function testAccessTokenExpired()
    {
        $token = $this->createMACAccessToken('foo', true);
        $manager = $this->createAccessTokenManager();

        $result = $manager->isAccessTokenValid($this->createRequest('/resource/1?b=1&a=2', 'GET', array('HOST' => 'example.com'), null, array('AUTHORIZATION'=>'MAC id="h480djs93hd8",ts="1336363200",nonce="dj83hs9s",mac="bhCQXTVyfj5cmA9uKkPFx1zeOXM="')), $token);
        $this->assertFalse($result);
    }

    public function testBadAccessTokenType()
    {
        $token = $this->createAccessToken();
        $manager = $this->createAccessTokenManager();

        $result = $manager->isAccessTokenValid(new Request, $token);
        $this->assertFalse($result);
    }

    public function testBadAccessToken()
    {
        $token = $this->createMACAccessToken();
        $manager = $this->createAccessTokenManager();

        $result = $manager->isAccessTokenValid(new Request, $token);
        $this->assertFalse($result);
    }

    public function testAccessTokenInvalid()
    {
        $token = $this->createMACAccessToken('jd93dh9dh39D', false, '8yfrufh348h', 'sha1');
        $manager = $this->createAccessTokenManager();

        $result = $manager->isAccessTokenValid($this->createRequest(
                    '/request',
                    'POST',
                    array('CONTENT_TYPE' => 'application/x-www-form-urlencoded'),
                    'hello=world%21',
                    array(
                        'HOST' => 'example.com',
                        'AUTHORIZATION' => 'MAC id="jd93dh9dh39D",mac="+2eC5lk+s+9xpEtpwrPQ32Oo8GU="',
                    )), $token);
        $this->assertFalse($result);
    }

    public function testInvalidBodyhash()
    {
        $token = $this->createMACAccessToken('jd93dh9dh39D', false, '8yfrufh348h', 'sha1');
        $manager = $this->createAccessTokenManager();

        $result = $manager->isAccessTokenValid($this->createRequest(
                    '/request',
                    'POST',
                    array('CONTENT_TYPE' => 'application/x-www-form-urlencoded'),
                    new \StdClass,
                    array(
                        'HOST' => 'example.com',
                        'AUTHORIZATION' => 'MAC id="jd93dh9dh39D",nonce="273156:di3hvdf8",bodyhash="k9kbtCIy0CkI3/FEfpS/oIDjk6k=",mac="W7bdMZbv9UWOTadASIQHagZyirA="',
                    )), $token);
        $this->assertFalse($result);
    }

    public function testBodyhashNotVerified()
    {
        $token = $this->createMACAccessToken('jd93dh9dh39D', false, '8yfrufh348h', 'sha1');
        $manager = $this->createAccessTokenManager();

        $result = $manager->isAccessTokenValid($this->createRequest(
                    '/request',
                    'POST',
                    array('CONTENT_TYPE' => 'application/x-www-form-urlencoded'),
                    'hello=world%2111',
                    array(
                        'HOST' => 'example.com',
                        'AUTHORIZATION' => 'MAC id="jd93dh9dh39D",nonce="273156:di3hvdf8",bodyhash="k9kbtCIy0CkI3/FEfpS/oIDjk6k=",mac="W7bdMZbv9UWOTadASIQHagZyirA="',
                    )), $token);
        $this->assertFalse($result);
    }

    public function testAccessTokenIsValid()
    {
        $token = $this->createMACAccessToken('jd93dh9dh39D', false, '8yfrufh348h', 'sha1');
        $manager = $this->createAccessTokenManager();

        $result = $manager->isAccessTokenValid($this->createRequest(
                    '/request',
                    'POST',
                    array('CONTENT_TYPE' => 'application/x-www-form-urlencoded'),
                    'hello=world%21',
                    array(
                        'HOST' => 'example.com',
                        'AUTHORIZATION' => 'MAC id="jd93dh9dh39D",nonce="273156:di3hvdf8",mac="+2eC5lk+s+9xpEtpwrPQ32Oo8GU="',
                    )), $token);
        $this->assertTrue($result);
    }

    public function testAccessTokenWithBodyhashIsValid()
    {
        $token = $this->createMACAccessToken('jd93dh9dh39D', false, '8yfrufh348h', 'sha1');
        $manager = $this->createAccessTokenManager();

        $result = $manager->isAccessTokenValid($this->createRequest(
                    '/request',
                    'POST',
                    array('CONTENT_TYPE' => 'application/x-www-form-urlencoded'),
                    'hello=world%21',
                    array(
                        'HOST' => 'example.com',
                        'AUTHORIZATION' => 'MAC id="jd93dh9dh39D",nonce="273156:di3hvdf8",bodyhash="k9kbtCIy0CkI3/FEfpS/oIDjk6k=",mac="W7bdMZbv9UWOTadASIQHagZyirA="',
                    )), $token);
        $this->assertTrue($result);
    }

    protected function createAccessTokenManager(array $access_token = null)
    {
        $manager = $this->getMockBuilder('OAuth2\Token\MACAccessTokenManager')
            ->setMethods(array('getExceptionManager', 'getConfiguration', 'addAccessToken', 'getAccessToken', 'getGenerator'))
            ->getMock();

        $manager->expects($this->any())
            ->method('getExceptionManager')
            ->will($this->returnValue($this->createExceptionManager()));

        if (null !== $access_token)
        {
            $manager->expects($this->any())
                ->method('getAccessToken')
                ->will($this->returnValueMap($access_token));
        }

        return $manager;
    }

    protected function createAccessToken()
    {
        $accessToken = $this->getMockBuilder('OAuth2\Token\AccessToken')
            ->setMethods(array('getToken', 'getType', 'getExpiresIn', 'getClient', 'getScope', 'getResourceOwner', 'hasExpired'))
            ->getMock();

        return $accessToken;
    }

    protected function createMACAccessToken($token = null, $hasExpired = null, $key = null, $algorithm = null)
    {
        $accessToken = $this->getMockBuilder('OAuth2\Token\MACAccessToken')
            ->setMethods(array('getToken', 'getExpiresIn', 'getClient', 'getScope', 'getResourceOwner', 'hasExpired', 'getKey', 'getAlgorithm'))
            ->getMock();

        if (null !== $token)
        {
            $accessToken->expects($this->any())
                ->method('getToken')
                ->will($this->returnValue($token));
        }

        if (null !== $hasExpired)
        {
            $accessToken->expects($this->any())
                ->method('hasExpired')
                ->will($this->returnValue($hasExpired));
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

        return $accessToken;
    }

    protected function createRequest($uri = '/', $method = 'POST', array $server = array(), $content = null, array $headers = array() )
    {
        $request = Request::create($uri, $method, array(), array(), array(), $server, $content);

        foreach ($headers as $key => $value) {
            $request->headers->set($key, $value);
        }

        return $request;
    }

    protected function createExceptionManager()
    {
        $manager = $this->getMockBuilder('OAuth2\Exception\ExceptionManager')
            ->setMethods(array('getUri'))
            ->getMock();

        $manager->expects($this->any())
            ->method('getUri')
            ->will($this->returnValue('http://foo.bar/?error='));

        return $manager;
    }
}
