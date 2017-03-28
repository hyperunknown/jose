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

/**
 * Class AESKW.
 */
abstract class AESKW implements KeyWrappingInterface
{
    /**
     * {@inheritdoc}
     */
    public function wrapKey(JWKInterface $key, string $cek, array $complete_headers, array &$additional_headers): string
    {
        $this->checkKey($key);
        $wrapper = $this->getWrapper();

        return $wrapper->wrap(Base64Url::decode($key->get('k')), $cek);
    }

    /**
     * {@inheritdoc}
     */
    public function unwrapKey(JWKInterface $key, string $encrypted_cek, array $header): string
    {
        $this->checkKey($key);
        $wrapper = $this->getWrapper();

        return $wrapper->unwrap(Base64Url::decode($key->get('k')), $encrypted_cek);
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyManagementMode(): string
    {
        return self::MODE_WRAP;
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
        if($this->getKeySize() !== mb_strlen(Base64Url::decode($key->get('k')), '8bit')) {
            throw new \InvalidArgumentException('The key size is not valid');
        }
    }

    /**
     * @return int
     */
    abstract protected function getKeySize(): int;

    /**
     * @return \AESKW\A128KW|\AESKW\A192KW|\AESKW\A256KW
     */
    abstract protected function getWrapper();
}
