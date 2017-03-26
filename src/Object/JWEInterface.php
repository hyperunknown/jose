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

interface JWEInterface extends JWTInterface
{
    /**
     * Returns the number of recipients associated with the JWS.
     *
     * @return int
     */
    public function countRecipients(): int;

    /**
     * @return bool
     */
    public function isEncrypted(): bool;

    /**
     * @param JWKInterface $recipient_key
     * @param array        $recipient_headers
     *
     * @return JWEInterface
     */
    public function addRecipientInformation(JWKInterface $recipient_key, array $recipient_headers = []): JWEInterface;

    /**
     * @param string|null $encrypted_key
     * @param array       $recipient_headers
     *
     * @return JWEInterface
     */
    public function addRecipientWithEncryptedKey(?string $encrypted_key, array $recipient_headers): JWEInterface;

    /**
     * Returns the recipients associated with the JWS.
     *
     * @return RecipientInterface[]
     */
    public function getRecipients(): array;

    /**
     * @param int $id
     *
     * @return RecipientInterface
     */
    public function &getRecipient(int $id): RecipientInterface;

    /**
     * @param int $recipient
     *
     * @return string
     */
    public function toCompactJSON(int $recipient): string;

    /**
     * @param int $recipient
     *
     * @return string
     */
    public function toFlattenedJSON(int $recipient): string;

    /**
     * @return string
     */
    public function toJSON(): string;

    /**
     * @internal
     *
     * @return string|null The cyphertext
     */
    public function getCiphertext(): ?string;

    /**
     * @param string $ciphertext
     *
     * @internal
     *
     * @return JWEInterface
     */
    public function withCiphertext(string $ciphertext): JWEInterface;

    /**
     * @internal
     *
     * @return string|null
     */
    public function getAAD(): ?string;

    /**
     * @internal
     *
     * @param string $aad
     *
     * @return JWEInterface
     */
    public function withAAD(string $aad): JWEInterface;

    /**
     * @internal
     *
     * @return string|null
     */
    public function getIV(): ?string;

    /**
     * @internal
     *
     * @param string $iv
     *
     * @return JWEInterface
     */
    public function withIV(string $iv): JWEInterface;

    /**
     * @internal
     *
     * @return string|null
     */
    public function getTag(): ?string;

    /**
     * @internal
     *
     * @param string $tag
     *
     * @return JWEInterface
     */
    public function withTag(string $tag): JWEInterface;

    /**
     * @internal
     *
     * @return string
     */
    public function getEncodedSharedProtectedHeaders(): string;

    /**
     * @internal
     *
     * @param string $encoded_shared_protected_headers
     *
     * @return JWEInterface
     */
    public function withEncodedSharedProtectedHeaders(string $encoded_shared_protected_headers): JWEInterface;

    /**
     * @return array
     */
    public function getSharedProtectedHeaders(): array;

    /**
     * @param array $shared_protected_headers
     *
     * @return JWEInterface
     */
    public function withSharedProtectedHeaders(array $shared_protected_headers): JWEInterface;

    /**
     * @param string     $key
     * @param mixed|null $value
     *
     * @return JWEInterface
     */
    public function withSharedProtectedHeader(string $key, $value): JWEInterface;

    /**
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getSharedProtectedHeader(string $key);

    /**
     * @param string $key The key
     *
     * @return bool
     */
    public function hasSharedProtectedHeader(string $key): bool;

    /**
     * @return array
     */
    public function getSharedHeaders(): array;

    /**
     * @param array $shared_headers
     *
     * @return JWEInterface
     */
    public function withSharedHeaders(array $shared_headers): JWEInterface;

    /**
     * @param string     $key
     * @param mixed|null $value
     *
     * @return JWEInterface
     */
    public function withSharedHeader(string $key, $value): JWEInterface;

    /**
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getSharedHeader(string $key);

    /**
     * @param string $key The key
     *
     * @return bool
     */
    public function hasSharedHeader(string $key): bool;
}
