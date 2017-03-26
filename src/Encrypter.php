<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose;

use Base64Url\Base64Url;
use Jose\Algorithm\ContentEncryptionAlgorithmInterface;
use Jose\Algorithm\JWAManager;
use Jose\Algorithm\KeyEncryption\KeyAgreementWrappingInterface;
use Jose\Algorithm\KeyEncryption\KeyEncryptionInterface;
use Jose\Algorithm\KeyEncryption\KeyWrappingInterface;
use Jose\Algorithm\KeyEncryptionAlgorithmInterface;
use Jose\Compression\CompressionInterface;
use Jose\Compression\CompressionManager;
use Jose\Object\JWEInterface;
use Jose\Object\JWKInterface;
use Jose\Object\Recipient;
use Jose\Object\RecipientInterface;

final class Encrypter
{
    /**
     * @var JWAManager
     */
    private $jwaManager;

    /**
     * @var CompressionManager
     */
    private $compressionManager;

    use Behaviour\HasKeyChecker;
    use Behaviour\CommonCipheringMethods;
    use Behaviour\EncrypterTrait;

    /**
     * @param array $key_encryption_algorithms
     * @param array $content_encryption_algorithms
     * @param array $compression_methods
     * @return Encrypter
     */
    public static function createEncrypter(array $key_encryption_algorithms, array $content_encryption_algorithms, array $compression_methods = ['DEF', 'ZLIB', 'GZ']): Encrypter
    {
        $encrypter = new self($key_encryption_algorithms, $content_encryption_algorithms, $compression_methods);

        return $encrypter;
    }

    /**
     * Decrypter constructor.
     *
     * @param string[]|KeyEncryptionAlgorithmInterface[]     $key_encryption_algorithms
     * @param string[]|ContentEncryptionAlgorithmInterface[] $content_encryption_algorithms
     * @param string[]|CompressionInterface[]              $compression_methods
     */
    public function __construct(array $key_encryption_algorithms, array $content_encryption_algorithms, array $compression_methods)
    {
        $this->setKeyEncryptionAlgorithms($key_encryption_algorithms);
        $this->setContentEncryptionAlgorithms($content_encryption_algorithms);
        $this->setCompressionMethods($compression_methods);
        $this->jwaManager = Factory\AlgorithmManagerFactory::createAlgorithmManager(array_merge($key_encryption_algorithms, $content_encryption_algorithms));
        $this->compressionManager = Factory\CompressionManagerFactory::createCompressionManager($compression_methods);
    }

    /**
     * @param JWEInterface $jwe
     */
    public function encrypt(JWEInterface &$jwe)
    {
        if (true === $jwe->isEncrypted()) {
            throw new \LogicException('The JWE is already encrypted.');
        }
        if (0 === $jwe->countRecipients()) {
            throw new \InvalidArgumentException('The JWE does not contain recipient.');
        }
        $additional_headers = [];
        $nb_recipients = $jwe->countRecipients();
        $content_encryption_algorithm = $this->getContentEncryptionAlgorithm($jwe);
        $compression_method = $this->getCompressionMethod($jwe);
        $key_management_mode = $this->getKeyManagementMode($jwe);
        $cek = $this->determineCEK($jwe, $content_encryption_algorithm, $key_management_mode, $additional_headers);

        for ($i = 0; $i < $nb_recipients; $i++) {
            $this->processRecipient($jwe, $jwe->getRecipient($i), $cek, $content_encryption_algorithm, $additional_headers);
        }

        if (!empty($additional_headers) && 1 === $jwe->countRecipients()) {
            $jwe = $jwe->withSharedProtectedHeaders(array_merge($jwe->getSharedProtectedHeaders(), $additional_headers));
        }

        $iv_size = $content_encryption_algorithm->getIVSize();
        $iv = $this->createIV($iv_size);

        $this->encryptJWE($jwe, $content_encryption_algorithm, $cek, $iv, $compression_method);
    }

    /**
     * @param JWEInterface                           $jwe
     * @param RecipientInterface                     $recipient
     * @param string                                              $cek
     * @param ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param array                                               $additional_headers
     */
    private function processRecipient(JWEInterface $jwe, RecipientInterface &$recipient, $cek, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, array &$additional_headers)
    {
        if (null === $recipient->getRecipientKey()) {
            return;
        }
        $complete_headers = array_merge($jwe->getSharedProtectedHeaders(), $jwe->getSharedHeaders(), $recipient->getHeaders());
        $key_encryption_algorithm = $this->findKeyEncryptionAlgorithm($complete_headers);
        $this->checkKeys($key_encryption_algorithm, $content_encryption_algorithm, $recipient->getRecipientKey());
        $encrypted_content_encryption_key = $this->getEncryptedKey($complete_headers, $cek, $key_encryption_algorithm, $content_encryption_algorithm, $additional_headers, $recipient->getRecipientKey());
        $recipient_headers = $recipient->getHeaders();
        if (!empty($additional_headers) && 1 !== $jwe->countRecipients()) {
            $recipient_headers = array_merge($recipient_headers, $additional_headers);
            $additional_headers = [];
        }

        $recipient = Recipient::createRecipientFromLoadedJWE($recipient_headers, $encrypted_content_encryption_key);
    }

    /**
     * @param JWEInterface                           $jwe
     * @param ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param string                                              $cek
     * @param string                                              $iv
     * @param CompressionInterface|null         $compression_method
     */
    private function encryptJWE(JWEInterface &$jwe, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, $cek, $iv, Compression\CompressionInterface $compression_method = null)
    {
        if (!empty($jwe->getSharedProtectedHeaders())) {
            $jwe = $jwe->withEncodedSharedProtectedHeaders(Base64Url::encode(json_encode($jwe->getSharedProtectedHeaders())));
        }

        $tag = null;
        $payload = $this->preparePayload($jwe->getPayload(), $compression_method);
        $aad = null === $jwe->getAAD() ? null : Base64Url::encode($jwe->getAAD());
        $ciphertext = $content_encryption_algorithm->encryptContent($payload, $cek, $iv, $aad, $jwe->getEncodedSharedProtectedHeaders(), $tag);
        $jwe = $jwe->withCiphertext($ciphertext);
        $jwe = $jwe->withIV($iv);

        if (null !== $tag) {
            $jwe = $jwe->withTag($tag);
        }
    }

    /**
     * @param string                                      $payload
     * @param CompressionInterface|null $compression_method
     *
     * @return string
     */
    private function preparePayload($payload, Compression\CompressionInterface $compression_method = null): string
    {
        $prepared = is_string($payload) ? $payload : json_encode($payload);
        if (!is_string($prepared)) {
            throw new \InvalidArgumentException('The payload is empty or cannot encoded into JSON.');
        }

        if (null === $compression_method) {
            return $prepared;
        }
        $compressed_payload = $compression_method->compress($prepared);
        if (!is_string($compressed_payload)) {
            throw new \InvalidArgumentException('Compression failed.');
        }

        return $compressed_payload;
    }

    /**
     * @param array                                               $complete_headers
     * @param string                                              $cek
     * @param KeyEncryptionAlgorithmInterface     $key_encryption_algorithm
     * @param ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param JWKInterface                           $recipient_key
     * @param array                                               $additional_headers
     *
     * @return string|null
     */
    private function getEncryptedKey(array $complete_headers, $cek, KeyEncryptionAlgorithmInterface $key_encryption_algorithm, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, array &$additional_headers, JWKInterface $recipient_key): ?string
    {
        if ($key_encryption_algorithm instanceof KeyEncryptionInterface) {
            return $this->getEncryptedKeyFromKeyEncryptionAlgorithm($complete_headers, $cek, $key_encryption_algorithm, $recipient_key, $additional_headers);
        } elseif ($key_encryption_algorithm instanceof KeyWrappingInterface) {
            return $this->getEncryptedKeyFromKeyWrappingAlgorithm($complete_headers, $cek, $key_encryption_algorithm, $recipient_key, $additional_headers);
        } elseif ($key_encryption_algorithm instanceof KeyAgreementWrappingInterface) {
            return $this->getEncryptedKeyFromKeyAgreementAndKeyWrappingAlgorithm($complete_headers, $cek, $key_encryption_algorithm, $content_encryption_algorithm, $additional_headers, $recipient_key);
        }

        return null;
    }

    /**
     * @param array                                                       $complete_headers
     * @param string                                                      $cek
     * @param KeyAgreementWrappingInterface $key_encryption_algorithm
     * @param ContentEncryptionAlgorithmInterface         $content_encryption_algorithm
     * @param array                                                       $additional_headers
     * @param JWKInterface                                   $recipient_key
     *
     * @return string
     */
    private function getEncryptedKeyFromKeyAgreementAndKeyWrappingAlgorithm(array $complete_headers, $cek, KeyAgreementWrappingInterface $key_encryption_algorithm, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, array &$additional_headers, JWKInterface $recipient_key): string
    {
        $jwt_cek = $key_encryption_algorithm->wrapAgreementKey($recipient_key, $cek, $content_encryption_algorithm->getCEKSize(), $complete_headers, $additional_headers);

        return $jwt_cek;
    }

    /**
     * @param array                                                $complete_headers
     * @param string                                               $cek
     * @param KeyEncryptionInterface $key_encryption_algorithm
     * @param JWKInterface                            $recipient_key
     * @param array                                                $additional_headers
     *
     * @return string
     */
    private function getEncryptedKeyFromKeyEncryptionAlgorithm(array $complete_headers, string $cek, KeyEncryptionInterface $key_encryption_algorithm, JWKInterface $recipient_key, array &$additional_headers)
    {
        return $key_encryption_algorithm->encryptKey($recipient_key, $cek, $complete_headers, $additional_headers);
    }

    /**
     * @param array                                              $complete_headers
     * @param string                                             $cek
     * @param KeyWrappingInterface $key_encryption_algorithm
     * @param JWKInterface                          $recipient_key
     * @param array                                              $additional_headers
     *
     * @return string
     */
    private function getEncryptedKeyFromKeyWrappingAlgorithm(array $complete_headers, string $cek, KeyWrappingInterface $key_encryption_algorithm, JWKInterface $recipient_key, &$additional_headers)
    {
        return $key_encryption_algorithm->wrapKey($recipient_key, $cek, $complete_headers, $additional_headers);
    }

    /**
     * @return JWAManager
     */
    protected function getJWAManager(): JWAManager
    {
        return $this->jwaManager;
    }

    /**
     * @return CompressionManager
     */
    protected function getCompressionManager(): CompressionManager
    {
        return $this->compressionManager;
    }
}
