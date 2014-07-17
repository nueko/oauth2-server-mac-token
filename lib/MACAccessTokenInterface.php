<?php

namespace OAuth2\Token;

use OAuth2\Token\AccessTokenInterface;

/**
 */
interface MACAccessTokenInterface extends AccessTokenInterface
{
    /**
     * @return string
     */
    public function getKey();

    /**
     * @return string
     */
    public function getAlgorithm();
}
