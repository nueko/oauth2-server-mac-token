<?php

namespace OAuth2\Token;

use OAuth2\Token\AccessTokenManager;
use OAuth2\Token\AccessTokenInterface;
use OAuth2\Token\MACAccessTokenInterface;
use OAuth2\Token\AccessTokenManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use OAuth2\Util\Header;

abstract class MACAccessTokenManager extends AccessTokenManager implements AccessTokenManagerInterface
{
    /**
     * {@inheritdoc}
     */
    public function getAccessTokenType()
    {
        return 'MAC';
    }

    /**
     * Get the list of methods to find the access token
     * This method can be override to add new way to find an access token.
     * These methods are those officialy supported by the RFC6749
     *
     * @return string[]
     */
    protected function getTokenFromMethods()
    {
        return array(
            'getMACTokenFromHeaders',
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function getToken(Request $request)
    {
        $tokens = array();
        $methods = $this->getTokenFromMethods();

        foreach ($methods as $method) {
            $token = $this->$method($request);
            if ($token !== null && isset($token['id'])) {
                $tokens[] = $token['id'];
            }
        }

        return $tokens;
    }

    protected function getValues(Request $request)
    {

        $values = $this->getMACTokenFromHeaders($request);
        if($values === null)
        {
            return null;
        }

        if( !isset($values['id']) || !isset($values['nonce']) || !isset($values['mac']))
        {
            return false;
        }
        return $values;
    }

    public function isAccessTokenValid(Request $request, AccessTokenInterface $token)
    {

        if( !$token instanceof MACAccessTokenInterface)
        {
            return false;
        }

        $values = $this->getValues($request);
        if(!is_array($values))
        {
            return false;
        }

        if(!isset($values['id']) || $values['id'] !== $token->getToken() || $token->hasExpired())
        {
            return false;
        }

        if (isset($values['bodyhash']))
        {
            $content = $request->getContent();
            if (!is_string($content))
            {
                return false;
            }
            $bodyhash = base64_encode(hash($token->getAlgorithm(), $content, true));
            if($values['bodyhash'] !== $bodyhash)
            {
                return false;
            }
        }

        $mac = $this->generateMac($request, $token, $values);
        return $mac === $values['mac'];
    }

    protected function getMACTokenFromHeaders(Request $request)
    {
        $header = Header::getParameter($request, 'AUTHORIZATION');

        if (!$header)
        {
            return null;
        }

        if (!preg_match('/' . preg_quote('MAC', '/') . '\s(\S+)/', $header, $matches))
        {
            return null;
        }

        $values = array();
        $params = explode(',', $matches[1]);
        foreach ($params as $param)
        {
            $key = substr($param, 0, strpos($param, '='));
            $value = trim(substr($param, strpos($param, '=') + 1), '"');
            $values[$key] = $value;
        }

        return $values;
    }

    protected function generateMac(Request $request, MACAccessTokenInterface $token, array $values)
    {

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
