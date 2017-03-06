<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm;

/**
 * Class JWAManager.
 */
final class JWAManager implements JWAManagerInterface
{
    /**
     * @var array
     */
    protected $algorithms = [];

    /**
     * {@inheritdoc}
     */
    public function isAlgorithmSupported(string $algorithm): bool
    {
        return null !== $this->getAlgorithm($algorithm);
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithms(): array
    {
        return $this->algorithms;
    }

    /**
     * {@inheritdoc}
     */
    public function listAlgorithms(): array
    {
        return array_keys($this->getAlgorithms());
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithm(string $algorithm): ?JWAInterface
    {
        return array_key_exists($algorithm, $this->algorithms) ? $this->algorithms[$algorithm] : null;
    }

    /**
     * {@inheritdoc}
     */
    public function addAlgorithm(JWAInterface $algorithm)
    {
        if (!$this->isAlgorithmSupported($algorithm->getAlgorithmName())) {
            $this->algorithms[$algorithm->getAlgorithmName()] = $algorithm;
        }
    }
}
