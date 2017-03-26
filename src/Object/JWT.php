<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Object;

/**
 * Class JWT.
 */
trait JWT
{
    /**
     * @var mixed|null
     */
    private $payload = null;

    /**
     * {@inheritdoc}
     */
    public function getPayload()
    {
        return $this->payload;
    }

    /**
     * {@inheritdoc}
     */
    public function withPayload($payload): JWTInterface
    {
        $jwt = clone $this;
        $jwt->payload = $payload;

        return $jwt;
    }

    /**
     * {@inheritdoc}
     */
    public function getClaim(string $key)
    {
        if ($this->hasClaim($key)) {
            return $this->payload[$key];
        }
        throw new \InvalidArgumentException(sprintf('The payload does not contain claim "%s".', $key));
    }

    /**
     * {@inheritdoc}
     */
    public function getClaims(): array
    {
        if (is_array($this->payload)) {
            return $this->payload;
        }
        throw new \InvalidArgumentException('The payload does not contain claims.');
    }

    /**
     * {@inheritdoc}
     */
    public function hasClaim(string $key): bool
    {
        return $this->hasClaims() && array_key_exists($key, $this->payload);
    }

    /**
     * {@inheritdoc}
     */
    public function hasClaims(): bool
    {
        return is_array($this->payload);
    }
}
