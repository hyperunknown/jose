<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Factory;

use Assert\Assertion;
use Jose\Encrypter;
use Jose\Object\JWE;
use Jose\Object\JWEInterface;
use Jose\Object\JWKInterface;

final class JWEFactory
{
    /**
     * @param mixed       $payload
     * @param array       $shared_protected_headers
     * @param array       $shared_headers
     * @param null|string $aad
     *
     * @return JWEInterface
     */
    public static function createJWE($payload, array $shared_protected_headers = [], array $shared_headers = [], ?string $aad = null): JWEInterface
    {
        $jwe = new JWE();
        $jwe = $jwe->withSharedProtectedHeaders($shared_protected_headers);
        $jwe = $jwe->withSharedHeaders($shared_headers);
        $jwe = $jwe->withPayload($payload);

        if (null !== $aad) {
            $jwe = $jwe->withAAD($aad);
        }

        return $jwe;
    }

    /**
     * @param mixed        $payload
     * @param JWKInterface $recipient_key
     * @param array        $shared_protected_headers
     *
     * @return string
     */
    public static function createJWEToCompactJSON($payload, JWKInterface $recipient_key, array $shared_protected_headers): string
    {
        $jwe = self::createJWEAndEncrypt($payload, $recipient_key, $shared_protected_headers, [], [], null);

        return $jwe->toCompactJSON(0);
    }

    /**
     * @param mixed        $payload
     * @param JWKInterface $recipient_key
     * @param array        $shared_protected_headers
     * @param array        $shared_headers
     * @param array        $recipient_headers
     * @param string|null  $aad
     *
     * @return string
     */
    public static function createJWEToFlattenedJSON($payload, JWKInterface $recipient_key, array $shared_protected_headers = [], $shared_headers = [], $recipient_headers = [], ?string $aad = null): string
    {
        $jwe = self::createJWEAndEncrypt($payload, $recipient_key, $shared_protected_headers, $shared_headers, $recipient_headers, $aad);

        return $jwe->toFlattenedJSON(0);
    }

    /**
     * @param mixed        $payload
     * @param JWKInterface $recipient_key
     * @param array        $shared_protected_headers
     * @param array        $shared_headers
     * @param array        $recipient_headers
     * @param string|null  $aad
     *
     * @return JWEInterface
     */
    private static function createJWEAndEncrypt($payload, JWKInterface $recipient_key, array $shared_protected_headers = [], $shared_headers = [], $recipient_headers = [], ?string $aad): JWEInterface
    {
        $complete_headers = array_merge($shared_protected_headers, $shared_headers, $recipient_headers);
        Assertion::keyExists($complete_headers, 'alg', 'No "alg" parameter set in the header');
        Assertion::keyExists($complete_headers, 'enc', 'No "enc" parameter set in the header');
        $encrypter = Encrypter::createEncrypter([$complete_headers['alg']], [$complete_headers['enc']], ['DEF', 'ZLIB', 'GZ']);

        $jwe = self::createJWE($payload, $shared_protected_headers, $shared_headers, $aad);

        $jwe = $jwe->addRecipientInformation($recipient_key, $recipient_headers);

        $encrypter->encrypt($jwe);

        return $jwe;
    }
}
