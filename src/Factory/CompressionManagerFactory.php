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
use Jose\Compression\CompressionInterface;
use Jose\Compression\CompressionManager;

final class CompressionManagerFactory
{
    /**
     * @param string[]|CompressionInterface[] $methods
     *
     * @return CompressionManager
     */
    public static function createCompressionManager(array $methods): CompressionManager
    {
        $compressionManager = new CompressionManager();

        foreach ($methods as $method) {
            if ($method instanceof CompressionInterface) {
                $compressionManager->addCompressionAlgorithm($method);
            } else {
                Assertion::string($method, 'Bad argument: must be a list with either method names (string) or instances of CompressionInterface.');
                $class = self::getMethodClass($method);
                $compressionManager->addCompressionAlgorithm(new $class());
            }
        }

        return $compressionManager;
    }

    /**
     * @param string $method
     *
     * @return bool
     */
    private static function isAlgorithmSupported(string $method): bool
    {
        return array_key_exists($method, self::getSupportedMethods());
    }

    /**
     * @param string $method
     *
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    private static function getMethodClass(string $method): string
    {
        Assertion::true(self::isAlgorithmSupported($method), sprintf('Compression method "%s" is not supported.', $method));

        return self::getSupportedMethods()[$method];
    }

    private static function getSupportedMethods(): array
    {
        return [
            'DEF'  => '\Jose\Compression\Deflate',
            'GZ'   => '\Jose\Compression\GZip',
            'ZLIB' => '\Jose\Compression\ZLib',
        ];
    }
}
