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

interface JWAManagerInterface
{
    /**
     * @param string $algorithm The algorithm
     *
     * @return bool Returns true if the algorithm is supported
     */
    public function isAlgorithmSupported(string $algorithm): bool;

    /**
     * @param string $algorithm The algorithm
     *
     * @return JWAInterface|null Returns JWAInterface object if the algorithm is supported, else null
     */
    public function getAlgorithm(string $algorithm): ?JWAInterface;

    /**
     * @return JWAInterface[] Returns the list of supported algorithms
     */
    public function getAlgorithms(): array;

    /**
     * @return string[] Returns the list of names of supported algorithms
     */
    public function listAlgorithms(): array;

    /**
     * @param JWAInterface $algorithm
     */
    public function addAlgorithm(JWAInterface $algorithm);
}
