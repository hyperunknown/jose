<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\Signature;

use Base64Url\Base64Url;
use Jose\Algorithm\SignatureAlgorithmInterface;
use Jose\Object\JWKInterface;

/**
 * This class handles signatures using HMAC.
 * It supports algorithms HS256, HS384 and HS512;.
 */
abstract class HMAC implements SignatureAlgorithmInterface
{
    /**
     * {@inheritdoc}
     */
    public function sign(JWKInterface $key, string $input): string
    {
        $this->checkKey($key);

        return hash_hmac($this->getHashAlgorithm(), $input, Base64Url::decode($key->get('k')), true);
    }

    /**
     * {@inheritdoc}
     */
    public function verify(JWKInterface $key, string $input, string $signature): bool
    {
        return hash_equals($this->sign($key, $input), $signature);
    }

    /**
     * @param JWKInterface $key
     */
    protected function checkKey(JWKInterface $key)
    {
        if ('oct' !== $key->get('kty')) {
            throw new \InvalidArgumentException('Wrong key type.');
        }
        if (false === $key->has('k')) {
            throw new \InvalidArgumentException('The key parameter "k" is missing.');
        }
    }

    /**
     * @return string
     */
    abstract protected function getHashAlgorithm(): string;
}
