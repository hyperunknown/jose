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

use Assert\Assertion;

/**
 * This class implements the compression algorithm ZLIB (ZLib).
 * This compression algorithm is not part of the specification.
 */
final class ZLib implements CompressionInterface
{
    /**
     * @var int
     */
    protected $compressionLevel = -1;

    /**
     * Deflate constructor.
     *
     * @param int $compressionLevel
     */
    public function __construct(int $compressionLevel = -1)
    {
        Assertion::range($compressionLevel, -1, 9, 'The compression level can be given as 0 for no compression up to 9 for maximum compression. If -1 given, the default compression level will be the default compression level of the zlib library.');

        $this->compressionLevel = $compressionLevel;
    }

    /**
     * @return int
     */
    private function getCompressionLevel(): int
    {
        return $this->compressionLevel;
    }

    /**
     * {@inheritdoc}
     */
    public function getMethodName(): string
    {
        return 'ZLIB';
    }

    /**
     * {@inheritdoc}
     */
    public function compress(string $data): string
    {
        $data = gzcompress($data, $this->getCompressionLevel());
        Assertion::false(false === $data, 'Unable to compress data');

        return $data;
    }

    /**
     * {@inheritdoc}
     */
    public function uncompress(string $data): string
    {
        $data = gzuncompress($data);
        Assertion::false(false === $data, 'Unable to uncompress data');

        return $data;
    }
}
