<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\ContentEncryption;

use Jose\Algorithm\ContentEncryptionAlgorithmInterface;

abstract class AESCBCHS implements ContentEncryptionAlgorithmInterface
{
    /**
     * {@inheritdoc}
     */
    public function encryptContent(string $data, string $cek, string $iv, ?string $aad, string $encoded_protected_header, ?string &$tag): string
    {
        $k = mb_substr($cek, mb_strlen($cek, '8bit') / 2, null, '8bit');

        $cyphertext = openssl_encrypt($data, $this->getMode($k), $k, OPENSSL_RAW_DATA, $iv);

        $tag = $this->calculateAuthenticationTag($cyphertext, $cek, $iv, $aad, $encoded_protected_header);

        return $cyphertext;
    }

    /**
     * {@inheritdoc}
     */
    public function decryptContent(string $data, string $cek, string $iv, ?string $aad, string $encoded_protected_header, string $tag): string
    {
        if (false === $this->isTagValid($data, $cek, $iv, $aad, $encoded_protected_header, $tag)) {
            throw new \InvalidArgumentException('Unable to verify the tag.');
        }

        $k = mb_substr($cek, mb_strlen($cek, '8bit') / 2, null, '8bit');

        return openssl_decrypt($data, self::getMode($k), $k, OPENSSL_RAW_DATA, $iv);
    }

    /**
     * @param string      $encrypted_data
     * @param string      $cek
     * @param string      $iv
     * @param null|string $aad
     * @param string      $encoded_header
     *
     * @return string
     */
    protected function calculateAuthenticationTag(string $encrypted_data, string $cek, string $iv, ?string $aad, string $encoded_header): string
    {
        $calculated_aad = $encoded_header;
        if (null !== $aad) {
            $calculated_aad .= '.'.$aad;
        }
        $mac_key = mb_substr($cek, 0, mb_strlen($cek, '8bit') / 2, '8bit');
        $auth_data_length = mb_strlen($encoded_header, '8bit');

        $secured_input = implode('', [
            $calculated_aad,
            $iv,
            $encrypted_data,
            pack('N2', ($auth_data_length / 2147483647) * 8, ($auth_data_length % 2147483647) * 8), // str_pad(dechex($auth_data_length), 4, "0", STR_PAD_LEFT)
        ]);
        $hash = hash_hmac($this->getHashAlgorithm(), $secured_input, $mac_key, true);

        return  mb_substr($hash, 0, mb_strlen($hash, '8bit') / 2, '8bit');
    }

    /**
     * @param string      $authentication_tag
     * @param string      $encoded_header
     * @param string      $encrypted_data
     * @param string      $cek
     * @param string      $iv
     * @param string|null $aad
     *
     * @return bool
     */
    protected function isTagValid(string $encrypted_data, string $cek, string $iv, ?string $aad, string $encoded_header, string $authentication_tag): bool
    {
        return $authentication_tag === $this->calculateAuthenticationTag($encrypted_data, $cek, $iv, $aad, $encoded_header);
    }

    /**
     * @return string
     */
    abstract protected function getHashAlgorithm(): string;

    /**
     * @return int
     */
    public function getIVSize(): int
    {
        return 128;
    }

    /**
     * @param string $k
     *
     * @return string
     */
    private function getMode(string $k): string
    {
        return 'aes-'.(8 * mb_strlen($k, '8bit')).'-cbc';
    }
}
