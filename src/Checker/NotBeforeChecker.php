<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Checker;

use Jose\Object\JWTInterface;

final class NotBeforeChecker implements ClaimCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkClaim(JWTInterface $jwt): array
    {
        if (!$jwt->hasClaim('nbf')) {
            return [];
        }

        $nbf = (int) $jwt->getClaim('nbf');
        if($nbf > time()) {
            throw new \InvalidArgumentException('The JWT can not be used yet.');
        }

        return ['nbf'];
    }
}
