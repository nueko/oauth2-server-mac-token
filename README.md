MAC Token for OAuth2 Server
===========================

This library adds a new type of access token for OAuth2 Server: MAC Token.

This token type is more secure than Bearer access tokens.

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
