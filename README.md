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

This package only includes the [draft 2](http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-02) of the IETF Specification.

# Prerequisites #

This library needs OAuth2 Server.

# Installation #

Installation is a quick 3 steps process:

* Download and install the library
* Extend with your classes
* Add the token type to your OAuth2 Server

##Step 1: Install the library##

The preferred way to install this bundle is to rely on Composer. Just check on Packagist the version you want to install (in the following example, we used "dev-master") and add it to your `composer.json`:

    {
        "require": {
            // ...
            "spomky-labs/oauth2-server-mac-token": "1.0.*@dev"
        }
    }

##Step 2: Create your classes##

This library provides an abstract class to ease your work: `OAuth2\Token\OAuth2MCAccessTokenManager`.

You just have to implement functions to create, store, retreive your codes and mark them as used.
In the following example, we use `OAuth2MACAccessToken` object and an array.

    <?php

    namespace ACME\MyOAuth2Server\Token;

    use OAuth2\Client\IOAuth2Client;
    use OAuth2\Token\OAuth2MACAccessToken;
    use OAuth2\Token\OAuth2MACAccessTokenManager;
    use OAuth2\ResourceOwner\IOAuth2ResourceOwner;

    class MyAccessTokenManager extends OAuth2MACAccessTokenManager
    {
        protected $accessTokens = array();

        protected function addAccessToken($token, $expiresAt, IOAuth2Client $client, $scope = null, IOAuth2ResourceOwner $resourceOwner = null) {

            $key   = $this->generator->getRandomString($this->configuration->getOption('mac_access_token_key_length', 10));
            $algo  = $this->configuration->getOption('mac_access_token_algorithm', 'sha1');

            $access_token = new OAuth2MACAccessToken($client, $token, $key, $algo, $expiresAt, $scope, $resourceOwner);

            $this->accessTokens[$token] = $access_token;
            return $access_token;
        }

        protected function getAccessToken($token) {

            return isset($this->accessTokens[$token])?$this->accessTokens[$token]:null;
        }
    }


##Step 3: Add the token type to your OAuth2 Server##

To use this token type, just create a new manager object and use it with your server:

    <?php

    namespace ACME\MyOAuth2Server

    use OAuth2\OAuth2;
    use ACME\MyOAuth2Server\MyAccessTokenManager;

    …

    //Create your manager. Our class needs a configuration object (for token lifetime, length…) and a token generator.
    $accessTokenManager = new MyAccessTokenManager($configuration, $generator);

    //Start your server
    $server = new OAuth2($configuration, $clientManagers, $supportedGrantTypes, $scopeManager, $accessTokenManager, $refreshTokenManager);

# Configuration #

This attess token type adds new configuration options:

* `mac_access_token_algorithm` (string, default='sha1'): the algorithm of the access token. Only `sha1` and `sha256` supported.
* `mac_access_token_key_length` (integer>0, default=10): the key length associated to the access token.

Example:

    <?php

    use OAuth2\Configuration\OAuth2Configuration;

    $configuration = new OAuth2Configuration(array(
        'mac_access_token_algorithm' => 'sha256',
        'mac_access_token_key_length' => 15
    ));
