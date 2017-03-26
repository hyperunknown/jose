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
use Base64Url\Base64Url;
use Http\Client\HttpClient;
use Http\Message\RequestFactory;
use Jose\KeyConverter\ECKey;
use Jose\KeyConverter\KeyConverter;
use Jose\KeyConverter\RSAKey;
use Jose\Object\JKUJWKSet;
use Jose\Object\JWK;
use Jose\Object\JWKInterface;
use Jose\Object\JWKSet;
use Jose\Object\JWKSetInterface;
use Jose\Object\JWKSets;
use Jose\Object\PublicJWKSet;
use Jose\Object\RotatableJWKSet;
use Jose\Object\StorableJWK;
use Jose\Object\StorableJWKSet;
use Jose\Object\X5UJWKSet;

final class JWKFactory
{
    /**
     * @param JWKSetInterface $jwkset
     *
     * @return JWKSetInterface
     */
    public static function createPublicKeySet(JWKSetInterface $jwkset): JWKSetInterface
    {
        return new PublicJWKSet($jwkset);
    }

    /**
     * @param array $jwksets
     *
     * @return JWKSetInterface
     */
    public static function createKeySets(array $jwksets = []): JWKSetInterface
    {
        return new JWKSets($jwksets);
    }

    /**
     * @param string $filename
     * @param array  $parameters
     *
     * @return JWKInterface
     */
    public static function createStorableKey(string $filename, array $parameters): JWKInterface
    {
        return new StorableJWK($filename, $parameters);
    }

    /**
     * @param string $filename
     * @param array  $parameters
     * @param int    $nb_keys
     *
     * @return JWKSetInterface
     */
    public static function createRotatableKeySet(string $filename, array $parameters, int $nb_keys): JWKSetInterface
    {
        return new RotatableJWKSet($filename, $parameters, $nb_keys);
    }

    /**
     * @param string $filename
     * @param array  $parameters
     * @param int    $nb_keys
     *
     * @return JWKSetInterface
     */
    public static function createStorableKeySet(string $filename, array $parameters, int $nb_keys): JWKSetInterface
    {
        return new StorableJWKSet($filename, $parameters, $nb_keys);
    }

    /**
     * @param array $config
     *
     * @return JWKInterface
     */
    public static function createKey(array $config): JWKInterface
    {
        Assertion::keyExists($config, 'kty', 'The key "kty" must be set');
        $supported_types = ['RSA' => 'RSA', 'OKP' => 'OKP', 'EC' => 'EC', 'oct' => 'Oct', 'none' => 'None'];
        $kty = $config['kty'];
        Assertion::keyExists($supported_types, $kty, sprintf('The key type "%s" is not supported. Please use one of %s', $kty, json_encode(array_keys($supported_types))));
        $method = sprintf('create%sKey', $supported_types[$kty]);

        return self::$method($config);
    }

    /**
     * @param array $values
     *
     * @return JWKInterface
     */
    public static function createRSAKey(array $values): JWKInterface
    {
        Assertion::keyExists($values, 'size', 'The key size is not set.');
        $size = $values['size'];
        unset($values['size']);

        Assertion::true(0 === $size % 8, 'Invalid key size.');
        Assertion::greaterOrEqualThan($size, 384, 'Key length is too short. It needs to be at least 384 bits.');

        $key = openssl_pkey_new([
            'private_key_bits' => $size,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        openssl_pkey_export($key, $out);
        $rsa = new RSAKey($out);
        $values = array_merge(
            $values,
            $rsa->toArray()
        );

        return new JWK($values);
    }

    /**
     * @param array $values
     *
     * @return JWKInterface
     */
    public static function createECKey(array $values): JWKInterface
    {
        Assertion::keyExists($values, 'crv', 'The curve is not set.');
        $curve = $values['crv'];
        $args = [
            'curve_name'       => self::getOpensslName($curve),
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ];
        $key = openssl_pkey_new($args);
        $res = openssl_pkey_export($key, $out);
        Assertion::true($res, 'Unable to create the key');

        $rsa = new ECKey($out);
        $values = array_merge(
            $values,
            $rsa->toArray()
        );

        return new JWK($values);
    }

    /**
     * @param array $values
     *
     * @return JWKInterface
     */
    public static function createOctKey(array $values): JWKInterface
    {
        Assertion::keyExists($values, 'size', 'The key size is not set.');
        $size = $values['size'];
        unset($values['size']);
        Assertion::true(0 === $size % 8, 'Invalid key size.');
        $values = array_merge(
            $values,
            [
                'kty' => 'oct',
                'k'   => Base64Url::encode(random_bytes($size / 8)),
            ]
        );

        return new JWK($values);
    }

    /**
     * @param array $values
     *
     * @return JWKInterface
     */
    public static function createOKPKey(array $values): JWKInterface
    {
        Assertion::keyExists($values, 'crv', 'The curve is not set.');
        $curve = $values['crv'];
        switch ($curve) {
            case 'X25519':
                Assertion::true(function_exists('curve25519_public'), sprintf('Unsupported "%s" curve', $curve));
                $d = random_bytes(32);
                $x = curve25519_public($d);
                break;
            case 'Ed25519':
                Assertion::true(function_exists('ed25519_publickey'), sprintf('Unsupported "%s" curve', $curve));
                $d = random_bytes(32);
                $x = ed25519_publickey($d);
                break;
            default:
                throw new \InvalidArgumentException(sprintf('Unsupported "%s" curve', $curve));
        }

        $values = array_merge(
            $values,
            [
                'kty' => 'OKP',
                'crv' => $curve,
                'x'   => Base64Url::encode($x),
                'd'   => Base64Url::encode($d),
            ]
        );

        return new JWK($values);
    }

    /**
     * @param array $values
     *
     * @return JWKInterface
     */
    public static function createNoneKey(array $values): JWKInterface
    {
        $values = array_merge(
            $values,
            [
                'kty' => 'none',
                'alg' => 'none',
                'use' => 'sig',
            ]
        );

        return new JWK($values);
    }

    /**
     * @param string $curve
     *
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    private static function getOpensslName(string $curve): string
    {
        switch ($curve) {
            case 'P-256':
                return 'prime256v1';
            case 'P-384':
                return 'secp384r1';
            case 'P-521':
                return 'secp521r1';
            default:
                throw new \InvalidArgumentException(sprintf('The curve "%s" is not supported.', $curve));
        }
    }

    /**
     * @param array $values
     *
     * @return JWKInterface|JWKSetInterface
     */
    public static function createFromValues(array $values)
    {
        if (array_key_exists('keys', $values) && is_array($values['keys'])) {
            return new JWKSet($values);
        }

        return new JWK($values);
    }

    /**
     * @param string $file
     * @param array  $additional_values
     *
     * @return JWKInterface
     */
    public static function createFromCertificateFile(string $file, array $additional_values = []): JWKInterface
    {
        $values = KeyConverter::loadKeyFromCertificateFile($file);
        $values = array_merge($values, $additional_values);

        return new JWK($values);
    }

    /**
     * @param string $certificate
     * @param array $additional_values
     * @return JWKInterface
     */
    public static function createFromCertificate(string $certificate, array $additional_values = []): JWKInterface
    {
        $values = KeyConverter::loadKeyFromCertificate($certificate);
        $values = array_merge($values, $additional_values);

        return new JWK($values);
    }

    /**
     * @param       $res
     * @param array $additional_values
     *
     * @return JWKInterface
     */
    public static function createFromX509Resource($res, array $additional_values = []): JWKInterface
    {
        Assertion::true(is_resource($res));
        $values = KeyConverter::loadKeyFromX509Resource($res);
        $values = array_merge($values, $additional_values);

        return new JWK($values);
    }

    /**
     * @param string      $file
     * @param null|string $password
     * @param array       $additional_values
     *
     * @return JWKInterface
     */
    public static function createFromKeyFile(string $file, ?string $password = null, array $additional_values = []): JWKInterface
    {
        $values = KeyConverter::loadFromKeyFile($file, $password);
        $values = array_merge($values, $additional_values);

        return new JWK($values);
    }

    /**
     * @param string      $key
     * @param null|string $password
     * @param array       $additional_values
     *
     * @return JWKInterface
     */
    public static function createFromKey(string $key, ?string $password = null, array $additional_values = []): JWKInterface
    {
        $values = KeyConverter::loadFromKey($key, $password);
        $values = array_merge($values, $additional_values);

        return new JWK($values);
    }

    /**
     * @param RequestFactory $requestFactory
     * @param HttpClient     $client
     * @param string         $jku
     * @param bool           $allow_http_connection
     *
     * @return JWKSetInterface
     */
    public static function createFromJKU(RequestFactory $requestFactory, HttpClient $client, string $jku, bool $allow_http_connection = false): JWKSetInterface
    {
        return new JKUJWKSet($requestFactory, $client, $jku, $allow_http_connection);
    }

    /**
     * @param RequestFactory $requestFactory
     * @param HttpClient     $client
     * @param string         $x5u
     * @param bool           $allow_http_connection
     *
     * @return JWKSetInterface
     */
    public static function createFromX5U(RequestFactory $requestFactory, HttpClient $client, string $x5u, bool $allow_http_connection = false): JWKSetInterface
    {
        return new X5UJWKSet($requestFactory, $client, $x5u, $allow_http_connection);
    }

    /**
     * @param array $x5c
     * @param array $additional_values
     *
     * @return JWKInterface
     */
    public static function createFromX5C(array $x5c, array $additional_values = []): JWKInterface
    {
        $values = KeyConverter::loadFromX5C($x5c);
        $values = array_merge($values, $additional_values);

        return new JWK($values);
    }

    /**
     * @param JWKSetInterface $jwk_set
     * @param int             $key_index
     *
     * @return JWKInterface
     */
    public static function createFromKeySet(JWKSetInterface $jwk_set, int $key_index): JWKInterface
    {
        return $jwk_set->getKey($key_index);
    }
}
