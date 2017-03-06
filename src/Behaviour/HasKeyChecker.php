<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Behaviour;

use Assert\Assertion;
use Jose\Object\JWKInterface;

trait HasKeyChecker
{
    /**
     * @param JWKInterface $key
     * @param string       $usage
     *
     * @throws \InvalidArgumentException
     */
    protected function checkKeyUsage(JWKInterface $key, string $usage)
    {
        if ($key->has('use')) {
            $this->checkUsage($key, $usage);
        }
        if ($key->has('key_ops')) {
            $this->checkOperation($key, $usage);
        }
    }

    /**
     * @param JWKInterface $key
     * @param string       $usage
     */
    private function checkOperation(JWKInterface $key, string $usage)
    {
        $ops = $key->get('key_ops');
        if (!is_array($ops)) {
            $ops = [$ops];
        }
        switch ($usage) {
            case 'verification':
                Assertion::inArray('verify', $ops, 'Key cannot be used to verify a signature');

                return;
            case 'signature':
                Assertion::inArray('sign', $ops, 'Key cannot be used to sign');

                return;
            case 'encryption':
                Assertion::true(in_array('encrypt', $ops) || in_array('wrapKey', $ops), 'Key cannot be used to encrypt');

                return;
            case 'decryption':
                Assertion::true(in_array('decrypt', $ops) || in_array('unwrapKey', $ops), 'Key cannot be used to decrypt');

                return;
            default:
                throw new \InvalidArgumentException('Unsupported key usage.');
        }
    }

    /**
     * @param JWKInterface $key
     * @param string       $usage
     */
    private function checkUsage(JWKInterface $key, string $usage)
    {
        $use = $key->get('use');
        switch ($usage) {
            case 'verification':
            case 'signature':
                Assertion::eq('sig', $use, 'Key cannot be used to sign or verify a signature');

                return;
            case 'encryption':
            case 'decryption':
                Assertion::eq('enc', $use, 'Key cannot be used to encrypt or decrypt');

                return;
            default:
                throw new \InvalidArgumentException('Unsupported key usage.');
        }
    }

    /**
     * @param JWKInterface $key
     * @param string       $algorithm
     */
    protected function checkKeyAlgorithm(JWKInterface $key, string $algorithm)
    {
        if (!$key->has('alg')) {
            return;
        }

        Assertion::eq($key->get('alg'), $algorithm, sprintf('Key is only allowed for algorithm "%s".', $key->get('alg')));
    }
}
