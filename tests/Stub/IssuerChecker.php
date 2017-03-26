<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Test\Stub;

use Jose\Checker\IssuerChecker as Base;

final class IssuerChecker extends Base
{
    /**
     * {@inheritdoc}
     */
    protected function isIssuerAllowed(string $issuer): bool
    {
        return in_array($issuer, ['ISS1', 'ISS2']);
    }
}
