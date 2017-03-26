<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Factory;

use Assert\Assertion;
use Jose\Checker;
use Jose\Checker\CheckerManager;
use Jose\Checker\ClaimCheckerInterface;
use Jose\Checker\HeaderCheckerInterface;

final class CheckerManagerFactory
{
    /**
     * @param string[]|ClaimCheckerInterface[]  $claims
     * @param string[]|HeaderCheckerInterface[] $headers
     *
     * @return CheckerManager
     */
    public static function createClaimCheckerManager(array $claims = ['exp', 'iat', 'nbf'], array $headers = ['crit']): CheckerManager
    {
        $checkerManager = new CheckerManager();

        self::populateClaimCheckers($checkerManager, $claims);
        self::populateHeaderCheckers($checkerManager, $headers);

        return $checkerManager;
    }

    /**
     * @param CheckerManager $checkerManager
     * @param array          $claims
     */
    private static function populateClaimCheckers(CheckerManager &$checkerManager, array $claims)
    {
        foreach ($claims as $claim) {
            if ($claim instanceof ClaimCheckerInterface) {
                $checkerManager->addClaimChecker($claim);
            } else {
                Assertion::string($claim, 'Bad argument: must be a list with either claim names (string) or instances of ClaimCheckerInterface.');
                $class = self::getClaimClass($claim);
                $checkerManager->addClaimChecker(new $class());
            }
        }
    }

    /**
     * @param CheckerManager $checkerManager
     * @param array          $headers
     */
    private static function populateHeaderCheckers(CheckerManager &$checkerManager, array $headers)
    {
        foreach ($headers as $claim) {
            if ($claim instanceof HeaderCheckerInterface) {
                $checkerManager->addHeaderChecker($claim);
            } else {
                Assertion::string($claim, 'Bad argument: must be a list with either header names (string) or instances of HeaderCheckerInterface.');
                $class = self::getHeaderClass($claim);
                $checkerManager->addHeaderChecker(new $class());
            }
        }
    }

    /**
     * @param string $claim
     *
     * @return bool
     */
    private static function isClaimSupported(string $claim): bool
    {
        return array_key_exists($claim, self::getSupportedClaims());
    }

    /**
     * @param string $header
     *
     * @return bool
     */
    private static function isHeaderSupported(string $header): bool
    {
        return array_key_exists($header, self::getSupportedHeaders());
    }

    /**
     * @param string $claim
     *
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    private static function getClaimClass(string $claim): string
    {
        Assertion::true(self::isClaimSupported($claim), sprintf('Claim "%s" is not supported. Please add an instance of ClaimCheckerInterface directly.', $claim));

        return self::getSupportedClaims()[$claim];
    }

    /**
     * @param string $header
     *
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    private static function getHeaderClass(string $header): string
    {
        Assertion::true(self::isHeaderSupported($header), sprintf('Header "%s" is not supported. Please add an instance of HeaderCheckerInterface directly.', $header));

        return self::getSupportedHeaders()[$header];
    }

    /**
     * @return array
     */
    private static function getSupportedClaims(): array
    {
        return [
            'aud' => Checker\AudienceChecker::class,
            'exp' => Checker\ExpirationTimeChecker::class,
            'iat' => Checker\IssuedAtChecker::class,
            'nbf' => Checker\NotBeforeChecker::class,
        ];
    }

    /**
     * @return array
     */
    private static function getSupportedHeaders(): array
    {
        return [
            'crit' => Checker\CriticalHeaderChecker::class,
        ];
    }
}
