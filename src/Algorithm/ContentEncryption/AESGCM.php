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

abstract class AESGCM implements ContentEncryptionAlgorithmInterface
{
    /**
     * {@inheritdoc}
     */
    public function encryptContent(string $data, string $cek, string $iv, ?string $aad, string $encoded_protected_header, ?string &$tag): string
    {
        $calculated_aad = $encoded_protected_header;
        if (null !== $aad) {
            $calculated_aad .= '.'.$aad;
        }

        $mode = $this->getMode($cek);
        $tag = null;
        $tag_length = 128;

        return openssl_encrypt($data, $mode, $cek, OPENSSL_RAW_DATA, $iv, $tag, $calculated_aad, $tag_length / 8);
    }

    /**
     *  {@inheritdoc}
     */
    public function decryptContent(string $data, string $cek, string $iv, ?string $aad, string $encoded_protected_header, string $tag): string
    {
        $calculated_aad = $encoded_protected_header;
        if (null !== $aad) {
            $calculated_aad .= '.'.$aad;
        }

        $mode = $this->getMode($cek);

        return openssl_decrypt($data, $mode, $cek, OPENSSL_RAW_DATA, $iv, $tag, $calculated_aad);
    }

    /**
     * @return int
     */
    public function getIVSize(): int
    {
        return 96;
    }

    /**
     * @return int
     */
    public function getCEKSize():int
    {
        return $this->getKeySize();
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
