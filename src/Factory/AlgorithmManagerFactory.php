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
use Jose\Algorithm\JWAInterface;
use Jose\Algorithm\JWAManager;
use Jose\Algorithm\Signature;
use Jose\Algorithm\KeyEncryption;
use Jose\Algorithm\ContentEncryption;

final class AlgorithmManagerFactory
{
    /**
     * @param string[]|JWAInterface[] $algorithms
     *
     * @return JWAManager
     */
    public static function createAlgorithmManager(array $algorithms): JWAManager
    {
        $jwaManager = new JWAManager();

        foreach ($algorithms as $algorithm) {
            if ($algorithm instanceof JWAInterface) {
                $jwaManager->addAlgorithm($algorithm);
            } else {
                Assertion::string($algorithm, 'Bad argument: must be a list with either algorithm names (string) or instances of JWAInterface.');
                $class = self::getAlgorithmClass($algorithm);
                $jwaManager->addAlgorithm(new $class());
            }
        }

        return $jwaManager;
    }

    /**
     * @param string $algorithm
     *
     * @return bool
     */
    private static function isAlgorithmSupported(string $algorithm): bool
    {
        return array_key_exists($algorithm, self::getSupportedAlgorithms());
    }

    /**
     * @param string $algorithm
     *
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    private static function getAlgorithmClass(string $algorithm): string
    {
        Assertion::true(self::isAlgorithmSupported($algorithm), sprintf('Algorithm "%s" is not supported.', $algorithm));

        return self::getSupportedAlgorithms()[$algorithm];
    }

    /**
     * @return array
     */
    private static function getSupportedAlgorithms(): array
    {
        return [
            'HS256'              => Signature\HS256::class,
            'HS384'              => Signature\HS384::class,
            'HS512'              => Signature\HS512::class,
            'ES256'              => Signature\ES256::class,
            'ES384'              => Signature\ES384::class,
            'ES512'              => Signature\ES512::class,
            'none'               => Signature\None::class,
            'RS256'              => Signature\RS256::class,
            'RS384'              => Signature\RS384::class,
            'RS512'              => Signature\RS512::class,
            'PS256'              => Signature\PS256::class,
            'PS384'              => Signature\PS384::class,
            'PS512'              => Signature\PS512::class,
            'EdDSA'              => Signature\EdDSA::class,
            'A128GCM'            => ContentEncryption\A128GCM::class,
            'A192GCM'            => ContentEncryption\A192GCM::class,
            'A256GCM'            => ContentEncryption\A256GCM::class,
            'A128CBC-HS256'      => ContentEncryption\A128CBCHS256::class,
            'A192CBC-HS384'      => ContentEncryption\A192CBCHS384::class,
            'A256CBC-HS512'      => ContentEncryption\A256CBCHS512::class,
            'A128KW'             => KeyEncryption\A128KW::class,
            'A192KW'             => KeyEncryption\A192KW::class,
            'A256KW'             => KeyEncryption\A256KW::class,
            'A128GCMKW'          => KeyEncryption\A128GCMKW::class,
            'A192GCMKW'          => KeyEncryption\A192GCMKW::class,
            'A256GCMKW'          => KeyEncryption\A256GCMKW::class,
            'dir'                => KeyEncryption\Dir::class,
            'ECDH-ES'            => KeyEncryption\ECDHES::class,
            'ECDH-ES+A128KW'     => KeyEncryption\ECDHESA128KW::class,
            'ECDH-ES+A192KW'     => KeyEncryption\ECDHESA192KW::class,
            'ECDH-ES+A256KW'     => KeyEncryption\ECDHESA256KW::class,
            'PBES2-HS256+A128KW' => KeyEncryption\PBES2HS256A128KW::class,
            'PBES2-HS384+A192KW' => KeyEncryption\PBES2HS384A192KW::class,
            'PBES2-HS512+A256KW' => KeyEncryption\PBES2HS512A256KW::class,
            'RSA1_5'             => KeyEncryption\RSA15::class,
            'RSA-OAEP'           => KeyEncryption\RSAOAEP::class,
            'RSA-OAEP-256'       => KeyEncryption\RSAOAEP256::class,
        ];
    }
}
