<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose;

use Jose\Object\JWEInterface;
use Jose\Object\JWKInterface;
use Jose\Object\JWKSet;
use Jose\Object\JWKSetInterface;
use Jose\Object\JWSInterface;

/**
 * Class able to load JWS or JWE.
 * JWS object can also be verified.
 */
final class Loader
{
    /**
     * @param $input
     * @param JWKInterface $jwk
     * @param array $allowed_key_encryption_algorithms
     * @param array $allowed_content_encryption_algorithms
     * @param int|null $recipient_index
     * @return JWEInterface
     */
    public function loadAndDecryptUsingKey($input, JWKInterface $jwk, array $allowed_key_encryption_algorithms, array $allowed_content_encryption_algorithms, ?int &$recipient_index = null): JWEInterface
    {
        $jwk_set = new JWKSet();
        $jwk_set->addKey($jwk);

        return $this->loadAndDecrypt($input, $jwk_set, $allowed_key_encryption_algorithms, $allowed_content_encryption_algorithms, $recipient_index);
    }

    /**
     * @param $input
     * @param JWKSetInterface $jwk_set
     * @param array $allowed_key_encryption_algorithms
     * @param array $allowed_content_encryption_algorithms
     * @param int|null $recipient_index
     * @return JWEInterface
     */
    public function loadAndDecryptUsingKeySet($input, JWKSetInterface $jwk_set, array $allowed_key_encryption_algorithms, array $allowed_content_encryption_algorithms, ?int &$recipient_index = null): JWEInterface
    {
        return $this->loadAndDecrypt($input, $jwk_set, $allowed_key_encryption_algorithms, $allowed_content_encryption_algorithms, $recipient_index);
    }

    /**
     * @param $input
     * @param JWKInterface $jwk
     * @param array $allowed_algorithms
     * @param int|null $signature_index
     * @return JWSInterface
     */
    public function loadAndVerifySignatureUsingKey($input, JWKInterface $jwk, array $allowed_algorithms, ?int &$signature_index = null): JWSInterface
    {
        $jwk_set = new JWKSet();
        $jwk_set->addKey($jwk);

        return $this->loadAndVerifySignature($input, $jwk_set, $allowed_algorithms, null, $signature_index);
    }

    /**
     * @param $input
     * @param JWKSetInterface $jwk_set
     * @param array $allowed_algorithms
     * @param int|null $signature_index
     * @return JWSInterface
     */
    public function loadAndVerifySignatureUsingKeySet($input, JWKSetInterface $jwk_set, array $allowed_algorithms, ?int &$signature_index = null): JWSInterface
    {
        return $this->loadAndVerifySignature($input, $jwk_set, $allowed_algorithms, null, $signature_index);
    }

    /**
     * @param $input
     * @param JWKInterface $jwk
     * @param array $allowed_algorithms
     * @param string $detached_payload
     * @param int|null $signature_index
     * @return JWSInterface
     */
    public function loadAndVerifySignatureUsingKeyAndDetachedPayload($input, JWKInterface $jwk, array $allowed_algorithms, string $detached_payload, ?int &$signature_index = null): JWSInterface
    {
        $jwk_set = new JWKSet();
        $jwk_set->addKey($jwk);

        return $this->loadAndVerifySignature($input, $jwk_set, $allowed_algorithms, $detached_payload, $signature_index);
    }

    /**
     * @param $input
     * @param JWKSetInterface $jwk_set
     * @param array $allowed_algorithms
     * @param string $detached_payload
     * @param int|null $signature_index
     * @return JWSInterface
     */
    public function loadAndVerifySignatureUsingKeySetAndDetachedPayload($input, JWKSetInterface $jwk_set, array $allowed_algorithms, string $detached_payload, ?int &$signature_index = null): JWSInterface
    {
        return $this->loadAndVerifySignature($input, $jwk_set, $allowed_algorithms, $detached_payload, $signature_index);
    }

    /**
     * @param string                       $input
     * @param JWKSetInterface $jwk_set
     * @param array                        $allowed_key_encryption_algorithms
     * @param array                        $allowed_content_encryption_algorithms
     * @param null|int                     $recipient_index
     *
     * @return JWEInterface
     */
    private function loadAndDecrypt(string $input, JWKSetInterface $jwk_set, array $allowed_key_encryption_algorithms, array $allowed_content_encryption_algorithms, ?int &$recipient_index = null): JWEInterface
    {
        $jwt = $this->load($input);
        if (!$jwt instanceof JWEInterface) {
            throw new \InvalidArgumentException('The input is not a valid JWE.');
        }
        $decrypted = Decrypter::createDecrypter($allowed_key_encryption_algorithms, $allowed_content_encryption_algorithms, ['DEF', 'ZLIB', 'GZ']);

        $decrypted->decryptUsingKeySet($jwt, $jwk_set, $recipient_index);

        return $jwt;
    }

    /**
     * @param string                       $input
     * @param JWKSetInterface $jwk_set
     * @param array                        $allowed_algorithms
     * @param string|null                  $detached_payload
     * @param null|int                     $signature_index
     *
     * @return JWSInterface
     */
    private function loadAndVerifySignature(string $input, JWKSetInterface $jwk_set, array $allowed_algorithms, string $detached_payload = null, ?int &$signature_index = null): JWSInterface
    {
        $jwt = $this->load($input);
        if (!$jwt instanceof JWSInterface) {
            throw new \InvalidArgumentException('The input is not a valid JWS.');
        }
        $verifier = Verifier::createVerifier($allowed_algorithms);

        $verifier->verifyWithKeySet($jwt, $jwk_set, $detached_payload, $signature_index);

        return $jwt;
    }

    /**
     * @param string $input
     * @return JWEInterface|JWSInterface
     */
    public function load(string $input)
    {
        $json = $this->convert($input);
        if (array_key_exists('signatures', $json)) {
            return Util\JWSLoader::loadSerializedJsonJWS($json);
        }
        if (array_key_exists('recipients', $json)) {
            return Util\JWELoader::loadSerializedJsonJWE($json);
        }
    }

    /**
     * @param string $input
     *
     * @return array
     */
    private function convert(string $input): array
    {
        if (is_array($data = json_decode($input, true))) {
            if (array_key_exists('signatures', $data) || array_key_exists('recipients', $data)) {
                return $data;
            } elseif (array_key_exists('signature', $data)) {
                return $this->fromFlattenedSerializationSignatureToSerialization($data);
            } elseif (array_key_exists('ciphertext', $data)) {
                return $this->fromFlattenedSerializationRecipientToSerialization($data);
            }
        } elseif (is_string($input)) {
            return $this->fromCompactSerializationToSerialization($input);
        }
        throw new \InvalidArgumentException('Unsupported input');
    }

    /**
     * @param array $input
     * @return array
     */
    private function fromFlattenedSerializationRecipientToSerialization(array $input): array
    {
        $recipient = [];
        foreach (['header', 'encrypted_key'] as $key) {
            if (array_key_exists($key, $input)) {
                $recipient[$key] = $input[$key];
            }
        }
        $recipients = [
            'ciphertext' => $input['ciphertext'],
            'recipients' => [$recipient],
        ];
        foreach (['protected', 'unprotected', 'iv', 'aad', 'tag'] as $key) {
            if (array_key_exists($key, $input)) {
                $recipients[$key] = $input[$key];
            }
        }

        return $recipients;
    }

    /**
     * @param array $input
     * @return array
     */
    private function fromFlattenedSerializationSignatureToSerialization(array $input): array
    {
        $signature = [
            'signature' => $input['signature'],
        ];
        foreach (['protected', 'header'] as $key) {
            if (array_key_exists($key, $input)) {
                $signature[$key] = $input[$key];
            }
        }

        $temp = [];
        if (!empty($input['payload'])) {
            $temp['payload'] = $input['payload'];
        }
        $temp['signatures'] = [$signature];

        return $temp;
    }

    /**
     * @param string $input
     *
     * @return array
     */
    private function fromCompactSerializationToSerialization($input)
    {
        $parts = explode('.', $input);
        switch (count($parts)) {
            case 3:
                return $this->fromCompactSerializationSignatureToSerialization($parts);
            case 5:
                return $this->fromCompactSerializationRecipientToSerialization($parts);
            default:
                throw new \InvalidArgumentException('Unsupported input');
        }
    }

    /**
     * @param array $parts
     *
     * @return array
     */
    private function fromCompactSerializationRecipientToSerialization(array $parts): array
    {
        $recipient = [];
        if (!empty($parts[1])) {
            $recipient['encrypted_key'] = $parts[1];
        }

        $recipients = [
            'recipients' => [$recipient],
        ];
        foreach ([0 => 'protected', 2 => 'iv', 3 => 'ciphertext', 4 => 'tag'] as $part => $key) {
            if (!empty($parts[$part])) {
                $recipients[$key] = $parts[$part];
            }
        }

        return $recipients;
    }

    /**
     * @param array $parts
     *
     * @return array
     */
    private function fromCompactSerializationSignatureToSerialization(array $parts): array
    {
        $temp = [];

        if (!empty($parts[1])) {
            $temp['payload'] = $parts[1];
        }
        $temp['signatures'] = [[
            'protected' => $parts[0],
            'signature' => $parts[2],
        ]];

        return $temp;
    }
}
