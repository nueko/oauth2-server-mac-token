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

This library provides classes that you can use as it is or you can extend with your own methods.

* Manager Class: `OAuth2\Token\OAuth2MACAccessTokenManager`
* Access Token Class: `OAuth2\Token\OAuth2MACAccessToken`


##Step 3: Add the token type to your OAuth2 Server##

To use this token type, just create a new manager object and use it with your server:

    <?php

    namespace ACME\MyOAuth2Server

    use OAuth2\OAuth2;
    use OAuth2\Token\OAuth2MACAccessToken;

    …

    //Create your manager. Our class needs a configuration object (for token lifetime, length…) and a token generator.
    $accessTokenManager = new OAuth2MACAccessToken($configuration, $generator);

    //Start your server
    $server = new OAuth2($configuration, $clientManagers, $supportedGrantTypes, $scopeManager, $accessTokenManager, $refreshTokenManager);
