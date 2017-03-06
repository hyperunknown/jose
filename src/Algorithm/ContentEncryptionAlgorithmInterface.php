<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm;

interface ContentEncryptionAlgorithmInterface extends JWAInterface
{
    /**
     * Encrypt data.
     *
     * @param string      $data                     The data to encrypt
     * @param string      $cek                      The content encryption key
     * @param string      $iv                       The Initialization Vector
     * @param string|null $aad                      Additional Additional Authenticated Data
     * @param string      $encoded_protected_header The Protected Header encoded in Base64Url
     * @param string|null $tag                      Tag
     *
     * @return string The encrypted data
     */
    public function encryptContent(string $data, string $cek, string $iv, ?string $aad, string $encoded_protected_header, ?string &$tag): string;

    /**
     * Decrypt data.
     *
     * @param string      $data                     The data to decrypt
     * @param string      $cek                      The content encryption key
     * @param string      $iv                       The Initialization Vector
     * @param string|null $aad                      Additional Additional Authenticated Data
     * @param string      $encoded_protected_header The Protected Header encoded in Base64Url
     * @param string      $tag                      Tag
     *
     * @return string
     */
    public function decryptContent(string $data, string $cek, string $iv, ?string $aad, string $encoded_protected_header, string $tag): string;

    /**
     * @return int|null
     */
    public function getIVSize(): int;

    /**
     * @return int
     */
    public function getCEKSize(): int;
}
