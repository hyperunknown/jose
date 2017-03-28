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

use Jose\Checker\CheckerManager;
use Jose\Object\JWEInterface;
use Jose\Object\JWKSetInterface;
use Jose\Object\JWSInterface;
use Jose\Object\JWTInterface;

final class JWTLoader
{
    /**
     * @var Loader
     */
    private $loader;

    /**
     * @var CheckerManager
     */
    private $checker_manager;

    /**
     * @var Decrypter|null
     */
    private $decrypter = null;

    /**
     * @var Verifier
     */
    private $verifier;

    /**
     * JWTLoader constructor.
     *
     * @param CheckerManager $checker_manager
     * @param Verifier       $verifier
     */
    public function __construct(CheckerManager $checker_manager, Verifier $verifier)
    {
        $this->checker_manager = $checker_manager;
        $this->verifier = $verifier;
        $this->loader = new Loader();
    }

    /**
     * @param Decrypter $decrypter
     */
    public function enableDecryptionSupport(Decrypter $decrypter)
    {
        $this->decrypter = $decrypter;
    }

    /**
     * @return string[]
     */
    public function getSupportedSignatureAlgorithms(): array
    {
        return $this->verifier->getSupportedSignatureAlgorithms();
    }

    /**
     * @return bool
     */
    public function isDecryptionSupportEnabled(): bool
    {
        return null !== $this->decrypter;
    }

    /**
     * @return string[]
     */
    public function getSupportedKeyEncryptionAlgorithms(): array
    {
        return false === $this->isDecryptionSupportEnabled() ? [] : $this->decrypter->getSupportedKeyEncryptionAlgorithms();
    }

    /**
     * @return string[]
     */
    public function getSupportedContentEncryptionAlgorithms(): array
    {
        return false === $this->isDecryptionSupportEnabled() ? [] : $this->decrypter->getSupportedContentEncryptionAlgorithms();
    }

    /**
     * @return string[]
     */
    public function getSupportedCompressionMethods(): array
    {
        return false === $this->isDecryptionSupportEnabled() ? [] : $this->decrypter->getSupportedCompressionMethods();
    }

    /**
     * @param string               $assertion
     * @param JWKSetInterface|null $encryption_key_set
     * @param bool                 $is_encryption_required
     *
     * @return JWTInterface
     */
    public function load(string $assertion, ?JWKSetInterface $encryption_key_set = null, bool $is_encryption_required = false): JWTInterface
    {
        $jwt = $this->loader->load($assertion);
        if ($jwt instanceof JWEInterface) {
            if(false === $this->isDecryptionSupportEnabled()) {
                throw new \InvalidArgumentException('Encryption support is not enabled.');
            }
            if(null === $encryption_key_set) {
                throw new \InvalidArgumentException($encryption_key_set, 'Encryption key set is not available.');
            }
            $jwt = $this->decryptAssertion($jwt, $encryption_key_set);
        } elseif (true === $is_encryption_required) {
            throw new \InvalidArgumentException('The assertion must be encrypted.');
        }

        return $jwt;
    }

    /**
     * @param JWSInterface    $jws
     * @param JWKSetInterface $signature_key_set
     * @param string|null     $detached_payload
     *
     * @return int
     */
    public function verify(JWSInterface $jws, JWKSetInterface $signature_key_set, ?string $detached_payload = null): int
    {
        $index = null;
        $this->verifier->verifyWithKeySet($jws, $signature_key_set, $detached_payload, $index);
        if (null === $index) {
            throw new \InvalidArgumentException('JWS signature(s) verification failed.');
        }
        $this->checker_manager->checkJWS($jws, $index);

        return $index;
    }

    /**
     * @param JWEInterface    $jwe
     * @param JWKSetInterface $encryption_key_set
     *
     * @return JWSInterface
     */
    private function decryptAssertion(JWEInterface $jwe, JWKSetInterface $encryption_key_set): JWSInterface
    {
        $this->decrypter->decryptUsingKeySet($jwe, $encryption_key_set);

        $jws = $this->loader->load($jwe->getPayload());
        if (!$jws instanceof JWSInterface) {
            throw new \InvalidArgumentException('The encrypted assertion does not contain a JWS.');
        }

        return $jws;
    }
}
