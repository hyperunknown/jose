<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose;

use Jose\Object\JWEInterface;
use Jose\Object\JWKInterface;

/**
 * Encrypter Interface.
 */
interface EncrypterInterface
{
    /**
     * @param \Jose\Object\JWEInterface $jwe
     */
    public function encrypt(JWEInterface &$jwe);

    /**
     * @param \Jose\Object\JWEInterface      $jwe
     * @param \Jose\Object\JWKInterface      $recipient_key
     * @param array                          $recipient_headers
     */
    public function addRecipient(JWEInterface &$jwe, JWKInterface $recipient_key, array $recipient_headers = []);
}
