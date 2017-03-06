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

use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Primitives\GeneratorPoint;

final class ES256 extends ECDSA
{
    /**
     * @return GeneratorPoint
     */
    protected function getGenerator(): GeneratorPoint
    {
        return EccFactory::getNistCurves()->generator256();
    }

    /**
     * @return string
     */
    protected function getHashAlgorithm(): string
    {
        return 'sha256';
    }

    /**
     * @return int
     */
    protected function getSignaturePartLength(): int
    {
        return 64;
    }

    /**
     * @return string
     */
    public function getAlgorithmName(): string
    {
        return 'ES256';
    }
}
