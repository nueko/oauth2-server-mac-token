<?php

namespace OAuth2\ResourceOwner;

use OAuth2\ResourceOwner\IOAuth2ResourceOwner;
use OAuth2\Client\IOAuth2Client;

class OAuth2ResourceOwner implements IOAuth2ResourceOwner
{
    protected $username;
    protected $password;
    protected $refreshTokenAllowed;

    /**
     * @param string $username
     * @param string $password
     */
    public function __construct($username, $password, $refreshTokenAllowed = false) {
        $this->username = $username;
        $this->setPassword($password);
        $this->refreshTokenAllowed = $refreshTokenAllowed;
    }

    public function setPassword($password) {
        $this->password = $password;
        return $this;
    }

    public function getUsername() {
        return $this->username;
    }

    public function checkCredentials($password) {
        return $password === $this->password;
    }

    public function isRefreshTokenIssueAllowed(IOAuth2Client $client) {
        return $refreshTokenAllowed;
    }
}
