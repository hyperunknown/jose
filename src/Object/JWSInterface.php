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

interface JWSInterface extends JWTInterface
{
    /**
     * @return bool
     */
    public function isPayloadDetached(): bool;

    /**
     * @return JWSInterface
     */
    public function withDetachedPayload(): JWSInterface;

    /**
     * @return JWSInterface
     */
    public function withAttachedPayload(): JWSInterface;

    /**
     * @param SignatureInterface $signature
     *
     * @internal
     *
     * @return string|null
     */
    public function getEncodedPayload(SignatureInterface $signature): ?string;

    /**
     * Returns the number of signature associated with the JWS.
     *
     * @return int
     */
    public function countSignatures(): int;

    /**
     * @param JWKInterface $signature_key
     * @param array                     $protected_headers
     * @param array                     $headers
     *
     * @return JWSInterface
     */
    public function addSignatureInformation(JWKInterface $signature_key, array $protected_headers, array $headers = []): JWSInterface;

    /**
     * @param string      $signature
     * @param string|null $encoded_protected_headers
     * @param array       $headers
     *
     * @return JWSInterface
     */
    public function addSignatureFromLoadedData(string $signature, ?string $encoded_protected_headers, array $headers): JWSInterface;

    /**
     * Returns the signature associated with the JWS.
     *
     * @return SignatureInterface[]
     */
    public function getSignatures(): array;

    /**
     * @param int $id
     *
     * @return SignatureInterface
     */
    public function &getSignature(int $id): SignatureInterface;

    /**
     * @param int $id
     *
     * @return string
     */
    public function toCompactJSON(int $id):string;

    /**
     * @param int $id
     *
     * @return string
     */
    public function toFlattenedJSON(int $id):string;

    /**
     * @return string
     */
    public function toJSON(): string;
}
