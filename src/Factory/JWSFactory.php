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
use Jose\Object\JWKInterface;
use Jose\Object\JWS;
use Jose\Object\JWSInterface;
use Jose\Signer;

final class JWSFactory
{
    /**
     * @param $payload
     * @param bool $is_payload_detached
     * @return JWSInterface
     */
    public static function createJWS($payload, bool $is_payload_detached = false): JWSInterface
    {
        $jws = new JWS();
        $jws = $jws->withPayload($payload);
        if (true === $is_payload_detached) {
            $jws = $jws->withDetachedPayload();
        } else {
            $jws = $jws->withAttachedPayload();
        }

        return $jws;
    }

    /**
     * @param $payload
     * @param JWKInterface $signature_key
     * @param array $protected_headers
     * @return string
     */
    public static function createJWSToCompactJSON($payload, JWKInterface $signature_key, array $protected_headers): string
    {
        $jws = self::createJWSAndSign($payload, $signature_key, $protected_headers, []);

        return $jws->toCompactJSON(0);
    }

    /**
     * @param $payload
     * @param JWKInterface $signature_key
     * @param array $protected_headers
     * @return string
     */
    public static function createJWSWithDetachedPayloadToCompactJSON($payload, JWKInterface $signature_key, array $protected_headers): string
    {
        $jws = self::createJWSWithDetachedPayloadAndSign($payload, $signature_key, $protected_headers, []);

        return $jws->toCompactJSON(0);
    }

    /**
     * @param $payload
     * @param JWKInterface $signature_key
     * @param array $protected_headers
     * @param array $headers
     * @return string
     */
    public static function createJWSToFlattenedJSON($payload, JWKInterface $signature_key, array $protected_headers = [], array $headers = []): string
    {
        $jws = self::createJWSAndSign($payload, $signature_key, $protected_headers, $headers);

        return $jws->toFlattenedJSON(0);
    }

    /**
     * @param $payload
     * @param JWKInterface $signature_key
     * @param array $protected_headers
     * @param array $headers
     * @return string
     */
    public static function createJWSWithDetachedPayloadToFlattenedJSON($payload, JWKInterface $signature_key, array $protected_headers = [], $headers = []): string
    {
        $jws = self::createJWSWithDetachedPayloadAndSign($payload, $signature_key, $protected_headers, $headers);

        return $jws->toFlattenedJSON(0);
    }

    /**
     * @param mixed                     $payload
     * @param JWKInterface $signature_key
     * @param array                     $protected_headers
     * @param array                     $headers
     *
     * @return JWSInterface
     */
    private static function createJWSAndSign($payload, JWKInterface $signature_key, array $protected_headers = [], array $headers = []): JWSInterface
    {
        $jws = self::createJWS($payload);

        $jws = $jws->addSignatureInformation($signature_key, $protected_headers, $headers);

        $complete_headers = array_merge($protected_headers, $headers);
        Assertion::keyExists($complete_headers, 'alg', 'No "alg" parameter set in the header');
        $signer = Signer::createSigner([$complete_headers['alg']]);
        $signer->sign($jws);

        return $jws;
    }

    /**
     * @param mixed        $payload
     * @param JWKInterface $signature_key
     * @param array        $protected_headers
     * @param array        $headers
     *
     * @return JWSInterface
     */
    private static function createJWSWithDetachedPayloadAndSign($payload, JWKInterface $signature_key, array $protected_headers = [], array $headers = []): JWSInterface
    {
        $jws = self::createJWS($payload, true);

        $jws = $jws->addSignatureInformation($signature_key, $protected_headers, $headers);

        $complete_headers = array_merge($protected_headers, $headers);
        Assertion::keyExists($complete_headers, 'alg', 'No "alg" parameter set in the header');
        $signer = Signer::createSigner([$complete_headers['alg']]);
        $signer->sign($jws);

        return $jws;
    }
}
