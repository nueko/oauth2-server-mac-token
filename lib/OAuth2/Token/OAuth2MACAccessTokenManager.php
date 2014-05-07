<?php

namespace OAuth2\Token;

use OAuth2\Client\IOAuth2Client;
use OAuth2\Token\IOAuth2AccessTokenManager;
use Symfony\Component\HttpFoundation\Request;
use OAuth2\Util\OAuth2Header;
use OAuth2\Exception\OAuth2InternalServerErrorException;
use OAuth2\ResourceOwner\IOAuth2ResourceOwner;

class OAuth2MACAccessTokenManager extends OAuth2AccessTokenManager implements IOAuth2AccessTokenManager
{
    protected function getToken(Request $request) {
        
        $values = $this->getMACTokenFromHeaders($request);
        return isset($values['id'])?array($values['id']):null;
    }

    public function createAccessToken(IOAuth2Client $client, $scope = null, IOAuth2ResourceOwner $resourceOwner = null) {

        $token = $this->generator->getRandomString(20);
        $key   = $this->generator->getRandomString(10);
        $algo  = $this->configuration->getOption('mac_access_token_algorithm', 'sha1');
        if($token === false || $key === false) {
            throw new OAuth2InternalServerErrorException('token_creation_error', 'An error has occured during the creation of the token.');
        }
        $this->accessTokens[$token] = new OAuth2MACAccessToken($client, $token, $key, $algo, time() + $this->getLifetime($client), $scope, $resourceOwner);
        return $this->accessTokens[$token];
        
    }

    public function getAccessTokenType() {
        return 'MAC';
    }

    protected function getValues(Request $request) {

        $values = $this->getMACTokenFromHeaders($request);
        if($values === null) {
            return null;
        }

        if( !isset($values['id']) || !isset($values['nonce']) || !isset($values['mac'])) {
            return false;
        }
        return $values;
    }

    public function isAccessTokenValid(Request $request, IOAuth2AccessToken $token) {

        if( !$token instanceof IOAuth2MACAccessToken) {
            return false;
        }

        $values = $this->getValues($request);
        if(!$values) {
            return $values;
        }

        if($values['id'] !== $token->getToken() || $token->hasExpired()) {
            return false;
        }

        if (isset($values['bodyhash'])) {
            $content = $request->getContent();
            if (!is_string($content)) {
                return false;
            }
            $bodyhash = base64_encode(hash($token->getAlgorithm(), $content, true));
            if($values['bodyhash'] !== $bodyhash) {
                return false;
            }
        }

        $mac = $this->generateMac($request, $token, $values);
        return $mac === $values['mac'];
    }

    protected function getMACTokenFromHeaders(Request $request)
    {
        $header = OAuth2Header::getHeader($request, 'AUTHORIZATION');

        if (!$header) {
            return null;
        }

        if (!preg_match('/' . preg_quote('MAC', '/') . '\s(\S+)/', $header, $matches)) {
            return null;
        }

        $values = array();
        $params = explode(',', $matches[1]);
        foreach ($params as $param) {
            $key = substr($param, 0, strpos($param, '='));
            $value = trim(substr($param, strpos($param, '=') + 1), '"');
            $values[$key] = $value;
        }

        return $values;
    }

    protected function generateMac(Request $request, IOAuth2MACAccessToken $token, array $values) {

        $nonce = $values['nonce'];
        $method = $request->getMethod();
        $request_uri = $request->getRequestUri();
        $host = $request->getHost();
        $port = $request->getPort();
        $bodyhash = isset($values['bodyhash'])?$values['bodyhash']:null;
        $ext = isset($values['ext'])?$values['ext']:null;

        $basestr = $nonce . "\n" .
                $method . "\n" .
                $request_uri . "\n" .
                $host . "\n" .
                $port . "\n" .
                $bodyhash . "\n" .
                $ext . "\n";

        return base64_encode(hash_hmac($token->getAlgorithm(), $basestr, $token->getKey(), true));
    }
}
