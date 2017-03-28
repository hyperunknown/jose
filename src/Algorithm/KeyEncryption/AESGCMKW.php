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
 * Class AESGCMKW.
 */
abstract class AESGCMKW implements KeyWrappingInterface
{
    /**
     * {@inheritdoc}
     */
    public function wrapKey(JWKInterface $key, string $cek, array $complete_headers, array &$additional_headers): string
    {
        $this->checkKey($key);
        $kek = Base64Url::decode($key->get('k'));
        $iv = random_bytes(96 / 8);
        $additional_headers['iv'] = Base64Url::encode($iv);

        $mode = $this->getMode($kek);
        $tag = null;
        $tag_length = 128;
        $encrypted_cek = openssl_encrypt($cek, $mode, $kek, OPENSSL_RAW_DATA, $iv, $tag, null, $tag_length / 8);
        if(false === $encrypted_cek) {
            throw new \InvalidArgumentException('Unable to encrypt the data.');
        }

        $additional_headers['tag'] = Base64Url::encode($tag);

        return $encrypted_cek;
    }

    /**
     * {@inheritdoc}
     */
    public function unwrapKey(JWKInterface $key, string $encrypted_cek, array $header): string
    {
        $this->checkKey($key);
        $this->checkAdditionalParameters($header);

        $kek = Base64Url::decode($key->get('k'));
        $tag = Base64Url::decode($header['tag']);
        $iv = Base64Url::decode($header['iv']);
        $mode = $this->getMode($kek);

        $decrypted_cek = openssl_decrypt($encrypted_cek, $mode, $kek, OPENSSL_RAW_DATA, $iv, $tag, null);
        if(false === $decrypted_cek) {
            throw new \InvalidArgumentException('Unable to decrypt the data.');
        }

        return $decrypted_cek;
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
    }

    /**
     * @param array $header
     */
    protected function checkAdditionalParameters(array $header)
    {
        foreach (['iv', 'tag'] as $key) {
            if(!array_key_exists($key, $header)) {
                throw new \InvalidArgumentException(sprintf('Parameter "%s" is missing.', $key));
            }
        }
    }

    /**
     * @return int
     */
    abstract protected function getKeySize(): int;

    /**
     * @param string $kek
     *
     * @return string
     */
    private function getMode(string $kek): string
    {
        $key_length = mb_strlen($kek, '8bit') * 8;

        return 'aes-'.($key_length).'-gcm';
    }
}
