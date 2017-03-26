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
    private $compressionAlgorithms = [];

    /**
     * @param CompressionInterface $compressionAlgorithm
     */
    public function addCompressionAlgorithm(CompressionInterface $compressionAlgorithm)
    {
        $this->compressionAlgorithms[$compressionAlgorithm->getMethodName()] = $compressionAlgorithm;
    }

    /**
     * @param string $name
     *
     * @return CompressionInterface|null
     */
    public function getCompressionAlgorithm(string $name): ?CompressionInterface
    {
        return array_key_exists($name, $this->compressionAlgorithms) ? $this->compressionAlgorithms[$name] : null;
    }
}
