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

final class AudienceChecker implements ClaimCheckerInterface
{
    /**
     * @var string
     */
    private $audience;

    /**
     * AudienceChecker constructor.
     *
     * @param string $audience
     */
    public function __construct(string $audience)
    {
        $this->audience = $audience;
    }

    /**
     * {@inheritdoc}
     */
    public function checkClaim(JWTInterface $jwt): array
    {
        if (!$jwt->hasClaim('aud')) {
            return [];
        }

        $audience = $jwt->getClaim('aud');
        if (is_string($audience)) {
            if($this->getAudience() !== $audience) {
                throw new \InvalidArgumentException('Bad audience.');
            }
        } elseif (is_array($audience)) {
            if(!in_array($this->getAudience(), $audience)) {
                throw new \InvalidArgumentException('Bad audience.');
            }
        } else {
            throw new \InvalidArgumentException('Bad audience.');
        }

        return ['aud'];
    }

    /**
     * @return string
     */
    public function getAudience()
    {
        return $this->audience;
    }
}
