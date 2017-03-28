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

use Jose\Algorithm\SignatureAlgorithmInterface;
use Jose\KeyConverter\RSAKey;
use Jose\Object\JWKInterface;
use Jose\Util\RSA as JoseRSA;

/**
 * Class RSA.
 */
abstract class RSA implements SignatureAlgorithmInterface
{
    /**
     * Probabilistic Signature Scheme.
     */
    protected const SIGNATURE_PSS = 1;

    /**
     * Use the PKCS#1.
     */
    protected const SIGNATURE_PKCS1 = 2;

    /**
     * @return mixed
     */
    abstract protected function getAlgorithm(): string;

    /**
     * @return int
     */
    abstract protected function getSignatureMethod(): int;

    /**
     * {@inheritdoc}
     */
    public function verify(JWKInterface $key, string $input, string $signature): bool
    {
        $this->checkKey($key);

        $pub = RSAKey::toPublic(new RSAKey($key));

        if ($this->getSignatureMethod() === self::SIGNATURE_PSS) {
            return JoseRSA::verify($pub, $input, $signature, $this->getAlgorithm());
        } else {
            return 1 === openssl_verify($input, $signature, $pub->toPEM(), $this->getAlgorithm());
        }
    }

    /**
     * {@inheritdoc}
     */
    public function sign(JWKInterface $key, string $input): string
    {
        $this->checkKey($key);
        if (false === $key->has('d')) {
            throw new \InvalidArgumentException('The key is not a private key');
        }

        $priv = new RSAKey($key);

        if ($this->getSignatureMethod() === self::SIGNATURE_PSS) {
            $signature = JoseRSA::sign($priv, $input, $this->getAlgorithm());
            $result = is_string($signature);
        } else {
            $result = openssl_sign($input, $signature, $priv->toPEM(), $this->getAlgorithm());
        }
        if(false === $result) {
            throw new \InvalidArgumentException('An error occurred during the creation of the signature');
        }

        return $signature;
    }

    /**
     * @param JWKInterface $key
     */
    private function checkKey(JWKInterface $key)
    {
        if ('RSA' !== $key->get('kty')) {
            throw new \InvalidArgumentException('Wrong key type.');
        }
    }
}
