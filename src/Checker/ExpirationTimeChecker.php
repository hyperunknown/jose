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

final class ExpirationTimeChecker implements ClaimCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkClaim(JWTInterface $jwt): array
    {
        if (!$jwt->hasClaim('exp')) {
            return [];
        }

        $exp = (int) $jwt->getClaim('exp');
        if($exp < time()) {
            throw new \InvalidArgumentException('The JWT has expired.');
        }

        return ['exp'];
    }
}
