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

final class ES512 extends ECDSA
{
    /**
     * @return string
     */
    protected function getHashAlgorithm(): string
    {
        return 'sha512';
    }

    /**
     * @return int
     */
    protected function getSignaturePartLength(): int
    {
        return 132;
    }

    /**
     * @return string
     */
    public function getAlgorithmName(): string
    {
        return 'ES512';
    }
}
