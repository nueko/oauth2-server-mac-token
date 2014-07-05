MAC Access Token for OAuth2 Server
==================================

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/Spomky-Labs/oauth2-server-mac-token/badges/quality-score.png?s=6bc92db71f3f3cd12867736da85241668e42c1a0)](https://scrutinizer-ci.com/g/Spomky-Labs/oauth2-server-mac-token/)
[![Code Coverage](https://scrutinizer-ci.com/g/Spomky-Labs/oauth2-server-mac-token/badges/coverage.png?s=cd7d57269813bec3c66eb61ec620f2a822ba4122)](https://scrutinizer-ci.com/g/Spomky-Labs/oauth2-server-mac-token/)

[![Build Status](https://travis-ci.org/Spomky-Labs/oauth2-server-mac-token.svg?branch=master)](https://travis-ci.org/Spomky-Labs/oauth2-server-mac-token)
[![HHVM Status](http://hhvm.h4cc.de/badge/spomky-labs/oauth2-server-mac-token.png)](http://hhvm.h4cc.de/package/spomky-labs/oauth2-server-mac-token)

[![Latest Stable Version](https://poser.pugx.org/spomky-labs/oauth2-server-mac-token/v/stable.png)](https://packagist.org/packages/spomky-labs/oauth2-server-mac-token)
[![Latest Unstable Version](https://poser.pugx.org/spomky-labs/oauth2-server-mac-token/v/unstable.png)](https://packagist.org/packages/spomky-labs/oauth2-server-mac-token)
[![Total Downloads](https://poser.pugx.org/spomky-labs/oauth2-server-mac-token/downloads.png)](https://packagist.org/packages/spomky-labs/oauth2-server-mac-token)
[![License](https://poser.pugx.org/spomky-labs/oauth2-server-mac-token/license.png)](https://packagist.org/packages/spomky-labs/oauth2-server-mac-token)

This library adds a new type of access token for OAuth2 Server: MAC Access Token.

This package only implements the [draft 2](http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-02) of the IETF Specification.

# Prerequisites #

This library needs at least `PHP 5.3` and HTTP Foundation from the Symfony2 framework.

It has been successfully tested using `PHP 5.3` to `PHP 5.6` and `HHVM` using HTTP Foundation `v2.3.*` to `2.5.*`.

# Installation #

Installation is a quick 3 steps process:

* Download and install the library
* Extend with your classes
* Add the token type to your OAuth2 Server

##Step 1: Install the library##

The preferred way to install this bundle is to rely on Composer. Just check on Packagist the version you want to install (in the following example, we used stable branch) and add it to your `composer.json`:

    {
        "require": {
            // ...
            "spomky-labs/oauth2-server-mac-token": "1.0.*"
        }
    }

##Step 2: Create your classes##
This library provides an abstract Token Manager and an abstract Mac Access Token to ease your work:

- `OAuth2\Token\OAuth2MACAccessToken`.
- `OAuth2\Token\OAuth2MACAccessTokenManager`.

You just have to implement the missing functions to use this kind of access token with your server.

###The Access Token

Example:

    <?php

    namespace ACME\MyOAuth2Server\Token;

    use OAuth2\Token\OAuth2MACAccessToken;
    use OAuth2\Client\IOAuth2Client;
    use OAuth2\ResourceOwner\IOAuth2ResourceOwner;

    class MyAccessToken extends OAuth2MACAccessToken
    {
        protected $token;
        protected $key;
        protected $algorithm;
        protected $expires_at;
        protected $client;
		protected $resource_owner;
		protected $scope;

		public function __construct(IOAuth2Client $client, $token, $expiresAt, $scope, IOAuth2ResourceOwner $resourceOwner, $key, $algorithm)
		{
			$this->token = $token;
			$this->key = $key;
			$this->algorithm = $algorithm;
			$this->expires_at = $expires_at;
			$this->client = $client;
			$this->resource_owner = $resource_owner;
			$this->scope = $scope;
		}

		public function getToken()
		{
			return $this->token;
		}

		public function getKey()
		{
			return $this->key;
		}

		public function getAlgorithm()
		{
			return $this->algorithm;
		}

		public function getClient()
		{
			return $this->client;
		}

		public function getScope()
		{
			return $this->scope;
		}

		public function getResourceOwner()
		{
			return $this->resource_owner;
		}

		public function getExpiresIn()
		{
			return $this->expires_at-now();
		}

		public function hasExpired()
		{
			return $this->getExpiresIn()<0;
		}
    }

###The Access Token Manager

Example:

    <?php

    namespace ACME\MyOAuth2Server\Token;

    use ACME\MyOAuth2Server\Token\MyAccessToken;
    use OAuth2\Token\OAuth2MACAccessTokenManager;
    use OAuth2\Client\IOAuth2Client;
    use OAuth2\ResourceOwner\IOAuth2ResourceOwner;
	use Symfony\Component\Security\Core\Util\SecureRandom;

    class MyAccessTokenManager extends OAuth2MACAccessTokenManager
    {
        protected $accessTokens = array();

        protected function addAccessToken($token, $expiresAt, IOAuth2Client $client, $scope = null, IOAuth2ResourceOwner $resourceOwner = null)
		{
			$generator = new SecureRandom();
			$key = $generator->nextBytes(10);

            $access_token = new MyAccessToken($client, $token, $expiresAt, $scope, $resourceOwner, $key, "sha256");
            $this->accessTokens[$token] = $access_token;
            return $access_token;
        }

        protected function getAccessToken($token) {

            return isset($this->accessTokens[$token])?$this->accessTokens[$token]:null;
        }
    }

##Step 3: Add the token type to your OAuth2 Server##

To use this token type, just use your access token manager with your server.
