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

use Assert\Assertion;
use Base64Url\Base64Url;
use Jose\Algorithm\ContentEncryptionAlgorithmInterface;
use Jose\Algorithm\JWAInterface;
use Jose\Algorithm\KeyEncryption\DirectEncryptionInterface;
use Jose\Algorithm\KeyEncryption\KeyAgreementInterface;
use Jose\Algorithm\KeyEncryption\KeyAgreementWrappingInterface;
use Jose\Algorithm\KeyEncryption\KeyEncryptionInterface;
use Jose\Algorithm\KeyEncryption\KeyWrappingInterface;
use Jose\Algorithm\KeyEncryptionAlgorithmInterface;
use Jose\Compression\CompressionInterface;
use Jose\Object\JWEInterface;
use Jose\Object\JWKInterface;
use Jose\Object\JWKSet;
use Jose\Object\JWKSetInterface;
use Jose\Object\RecipientInterface;

final class Decrypter
{
    use Behaviour\HasKeyChecker;
    use Behaviour\HasJWAManager;
    use Behaviour\HasCompressionManager;
    use Behaviour\CommonCipheringMethods;

    /**
     * @param array $key_encryption_algorithms
     * @param array $content_encryption_algorithms
     * @param array $compression_methods
     * @return Decrypter
     */
    public static function createDecrypter(array $key_encryption_algorithms, array $content_encryption_algorithms, array $compression_methods = ['DEF', 'ZLIB', 'GZ']): Decrypter
    {
        $decrypter = new self($key_encryption_algorithms, $content_encryption_algorithms, $compression_methods);

        return $decrypter;
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
        $this->setJWAManager(Factory\AlgorithmManagerFactory::createAlgorithmManager(array_merge($key_encryption_algorithms, $content_encryption_algorithms)));
        $this->setCompressionManager(Factory\CompressionManagerFactory::createCompressionManager($compression_methods));
    }

    /**
     * @param JWEInterface $jwe
     * @param JWKInterface $jwk
     * @param null $recipient_index
     */
    public function decryptUsingKey(JWEInterface &$jwe, JWKInterface $jwk, &$recipient_index = null)
    {
        $jwk_set = new JWKSet();
        $jwk_set->addKey($jwk);

        $this->decryptUsingKeySet($jwe, $jwk_set, $recipient_index);
    }

    /**
     * @param JWEInterface $jwe
     * @param JWKSetInterface $jwk_set
     * @param int|null $recipient_index
     */
    public function decryptUsingKeySet(JWEInterface &$jwe, JWKSetInterface $jwk_set, ?int &$recipient_index = null)
    {
        $this->checkJWKSet($jwk_set);
        $this->checkPayload($jwe);
        $this->checkRecipients($jwe);

        $nb_recipients = $jwe->countRecipients();

        for ($i = 0; $i < $nb_recipients; $i++) {
            if (is_int($result = $this->decryptRecipientKey($jwe, $jwk_set, $i))) {
                $recipient_index = $result;

                return;
            }
        }

        throw new \InvalidArgumentException('Unable to decrypt the JWE.');
    }

    /**
     * @param JWEInterface    $jwe
     * @param JWKSetInterface $jwk_set
     * @param int                          $i
     *
     * @return int
     */
    private function decryptRecipientKey(JWEInterface &$jwe, JWKSetInterface $jwk_set, int $i): ?int
    {
        $recipient = $jwe->getRecipient($i);
        $complete_headers = array_merge($jwe->getSharedProtectedHeaders(), $jwe->getSharedHeaders(), $recipient->getHeaders());
        $this->checkCompleteHeader($complete_headers);

        $key_encryption_algorithm = $this->getKeyEncryptionAlgorithm($complete_headers);
        $content_encryption_algorithm = $this->getContentEncryptionAlgorithm($complete_headers);

        foreach ($jwk_set as $jwk) {
            try {
                $this->checkKeyUsage($jwk, 'decryption');
                if ('dir' !== $key_encryption_algorithm->getAlgorithmName()) {
                    $this->checkKeyAlgorithm($jwk, $key_encryption_algorithm->getAlgorithmName());
                } else {
                    $this->checkKeyAlgorithm($jwk, $content_encryption_algorithm->getAlgorithmName());
                }
                $cek = $this->decryptCEK($key_encryption_algorithm, $content_encryption_algorithm, $jwk, $recipient, $complete_headers);
                if (null !== $cek) {
                    if (true === $this->decryptPayload($jwe, $cek, $content_encryption_algorithm, $complete_headers)) {
                        return $i;
                    }
                }
            } catch (\Exception $e) {
                //We do nothing, we continue with other keys
                continue;
            }
        }

        return null;
    }

    /**
     * @param JWEInterface $jwe
     */
    private function checkRecipients(JWEInterface $jwe)
    {
        Assertion::greaterThan($jwe->countRecipients(), 0, 'The JWE does not contain any recipient.');
    }

    /**
     * @param JWEInterface $jwe
     */
    private function checkPayload(JWEInterface $jwe)
    {
        Assertion::true(null === $jwe->getPayload(), 'The JWE is already decrypted.');
    }

    /**
     * @param JWKSetInterface $jwk_set
     */
    private function checkJWKSet(JWKSetInterface $jwk_set)
    {
        Assertion::greaterThan(count($jwk_set), 0, 'No key in the key set.');
    }

    /**
     * @param JWAInterface                        $key_encryption_algorithm
     * @param ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param JWKInterface                           $key
     * @param RecipientInterface                     $recipient
     * @param array                                               $complete_headers
     *
     * @return string
     */
    private function decryptCEK(JWAInterface $key_encryption_algorithm, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, JWKInterface $key, RecipientInterface $recipient, array $complete_headers): string
    {
        if ($key_encryption_algorithm instanceof DirectEncryptionInterface) {
            return $key_encryption_algorithm->getCEK($key);
        } elseif ($key_encryption_algorithm instanceof KeyAgreementInterface) {
            return $key_encryption_algorithm->getAgreementKey($content_encryption_algorithm->getCEKSize(), $content_encryption_algorithm->getAlgorithmName(), $key, $complete_headers);
        } elseif ($key_encryption_algorithm instanceof KeyAgreementWrappingInterface) {
            return $key_encryption_algorithm->unwrapAgreementKey($key, $recipient->getEncryptedKey(), $content_encryption_algorithm->getCEKSize(), $complete_headers);
        } elseif ($key_encryption_algorithm instanceof KeyEncryptionInterface) {
            return $key_encryption_algorithm->decryptKey($key, $recipient->getEncryptedKey(), $complete_headers);
        } elseif ($key_encryption_algorithm instanceof KeyWrappingInterface) {
            return $key_encryption_algorithm->unwrapKey($key, $recipient->getEncryptedKey(), $complete_headers);
        } else {
            throw new \InvalidArgumentException('Unsupported CEK generation');
        }
    }

    /**
     * @param JWEInterface                           $jwe
     * @param string                                              $cek
     * @param ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param array                                               $complete_headers
     *
     * @return bool
     */
    private function decryptPayload(JWEInterface &$jwe, string $cek, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, array $complete_headers): bool
    {
        $payload = $content_encryption_algorithm->decryptContent($jwe->getCiphertext(), $cek, $jwe->getIV(), null === $jwe->getAAD() ? null : Base64Url::encode($jwe->getAAD()), $jwe->getEncodedSharedProtectedHeaders(), $jwe->getTag());
        if (null === $payload) {
            return false;
        }

        $this->decompressIfNeeded($payload, $complete_headers);
        $decoded = json_decode($payload, true);
        $jwe = $jwe->withPayload(null === $decoded ? $payload : $decoded);

        return true;
    }

    /**
     * @param string $payload
     * @param array  $complete_headers
     */
    private function decompressIfNeeded(string &$payload, array $complete_headers)
    {
        if (array_key_exists('zip', $complete_headers)) {
            $compression_method = $this->getCompressionMethod($complete_headers['zip']);
            $payload = $compression_method->uncompress($payload);
            Assertion::string($payload, 'Decompression failed');
        }
    }

    /**
     * @param array $complete_headers
     *
     * @throws \InvalidArgumentException
     */
    private function checkCompleteHeader(array $complete_headers)
    {
        foreach (['enc', 'alg'] as $key) {
            Assertion::keyExists($complete_headers, $key, sprintf("Parameters '%s' is missing.", $key));
        }
    }

    /**
     * @param array $complete_headers
     *
     * @return KeyEncryptionAlgorithmInterface
     */
    private function getKeyEncryptionAlgorithm(array $complete_headers): KeyEncryptionAlgorithmInterface
    {
        $key_encryption_algorithm = $this->getJWAManager()->getAlgorithm($complete_headers['alg']);
        Assertion::isInstanceOf($key_encryption_algorithm, KeyEncryptionAlgorithmInterface::class, sprintf('The key encryption algorithm "%s" is not supported or does not implement KeyEncryptionAlgorithmInterface.', $complete_headers['alg']));

        return $key_encryption_algorithm;
    }

    /**
     * @param array $complete_headers
     *
     * @return ContentEncryptionAlgorithmInterface
     */
    private function getContentEncryptionAlgorithm(array $complete_headers): ContentEncryptionAlgorithmInterface
    {
        $content_encryption_algorithm = $this->getJWAManager()->getAlgorithm($complete_headers['enc']);
        Assertion::isInstanceOf($content_encryption_algorithm, ContentEncryptionAlgorithmInterface::class, sprintf('The key encryption algorithm "%s" is not supported or does not implement ContentEncryptionInterface.', $complete_headers['enc']));

        return $content_encryption_algorithm;
    }

    /**
     * @param string $method
     *
     * @throws \InvalidArgumentException
     *
     * @return CompressionInterface
     */
    private function getCompressionMethod(string $method): CompressionInterface
    {
        $compression_method = $this->getCompressionManager()->getCompressionAlgorithm($method);
        Assertion::notNull($compression_method, sprintf('Compression method "%s" not supported', $method));

        return $compression_method;
    }
}
