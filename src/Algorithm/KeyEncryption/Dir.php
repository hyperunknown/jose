<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\KeyEncryption;

use Base64Url\Base64Url;
use Jose\Object\JWKInterface;

final class Dir implements DirectEncryptionInterface
{
    /**
     * {@inheritdoc}
     */
    public function getCEK(JWKInterface $key): string
    {
        if ('oct' !== $key->get('kty')) {
            throw new \InvalidArgumentException('Wrong key type.');
        }
        if (false === $key->has('k')) {
            throw new \InvalidArgumentException('The key parameter "k" is missing.');
        }

        return Base64Url::decode($key->get('k'));
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithmName(): string
    {
        return 'dir';
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyManagementMode(): string
    {
        return self::MODE_DIRECT;
    }
}
