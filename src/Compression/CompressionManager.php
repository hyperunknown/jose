<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Compression;

/**
 * Compression algorithm manager.
 */
final class CompressionManager
{
    /**
     * @var CompressionInterface[]
     */
    private $compression_algorithms = [];

    /**
     * @param CompressionInterface $compression_algorithm
     */
    public function addCompressionAlgorithm(CompressionInterface $compression_algorithm)
    {
        $this->compression_algorithms[$compression_algorithm->getMethodName()] = $compression_algorithm;
    }

    /**
     * @param string $name
     *
     * @return CompressionInterface|null
     */
    public function getCompressionAlgorithm(string $name): ?CompressionInterface
    {
        return array_key_exists($name, $this->compression_algorithms) ? $this->compression_algorithms[$name] : null;
    }
}
