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

use Assert\Assertion;
use Base64Url\Base64Url;
use Jose\Algorithm\JWAManager;
use Jose\Algorithm\SignatureAlgorithmInterface;
use Jose\Object\JWKInterface;
use Jose\Object\JWKSet;
use Jose\Object\JWKSetInterface;
use Jose\Object\JWSInterface;
use Jose\Object\SignatureInterface;

final class Verifier
{
    /**
     * @var JWAManager
     */
    private $jwaManager;

    use Behaviour\HasKeyChecker;
    use Behaviour\CommonSigningMethods;

    /**
     * Verifier constructor.
     *
     * @param string[]|SignatureAlgorithmInterface[] $signature_algorithms
     */
    public function __construct(array $signature_algorithms)
    {
        $this->setSignatureAlgorithms($signature_algorithms);
        $this->jwaManager = Factory\AlgorithmManagerFactory::createAlgorithmManager($signature_algorithms);
    }

    /**
     * @param array $signature_algorithms
     * @return Verifier
     */
    public static function createVerifier(array $signature_algorithms): Verifier
    {
        $verifier = new self($signature_algorithms);

        return $verifier;
    }

    /**
     * @param JWSInterface $jws
     * @param JWKInterface $jwk
     * @param null|string $detached_payload
     * @param int|null $recipient_index
     */
    public function verifyWithKey(JWSInterface $jws, JWKInterface $jwk, ?string $detached_payload = null, ?int &$recipient_index = null)
    {
        $jwk_set = new JWKSet();
        $jwk_set->addKey($jwk);

        $this->verifySignatures($jws, $jwk_set, $detached_payload, $recipient_index);
    }

    /**
     * {@inheritdoc}
     */
    public function verifyWithKeySet(JWSInterface $jws, JWKSetInterface $jwk_set, $detached_payload = null, &$recipient_index = null)
    {
        $this->verifySignatures($jws, $jwk_set, $detached_payload, $recipient_index);
    }

    /**
     * @param JWSInterface       $jws
     * @param JWKSetInterface    $jwk_set
     * @param SignatureInterface $signature
     * @param string|null        $detached_payload
     *
     * @return bool
     */
    private function verifySignature(JWSInterface $jws, JWKSetInterface $jwk_set, SignatureInterface $signature, ?string $detached_payload = null): bool
    {
        $input = $this->getInputToVerify($jws, $signature, $detached_payload);
        foreach ($jwk_set->getKeys() as $jwk) {
            $algorithm = $this->getAlgorithm($signature);
            try {
                $this->checkKeyUsage($jwk, 'verification');
                $this->checkKeyAlgorithm($jwk, $algorithm->getAlgorithmName());
                if (true === $algorithm->verify($jwk, $input, $signature->getSignature())) {
                    return true;
                }
            } catch (\Exception $e) {
                //We do nothing, we continue with other keys
                continue;
            }
        }

        return false;
    }

    /**
     * @param JWSInterface       $jws
     * @param SignatureInterface $signature
     * @param string|null        $detached_payload
     *
     * @return string
     */
    private function getInputToVerify(JWSInterface $jws, SignatureInterface $signature, ?string $detached_payload): string
    {
        $encoded_protected_headers = $signature->getEncodedProtectedHeaders();
        if (!$signature->hasProtectedHeader('b64') || true === $signature->getProtectedHeader('b64')) {
            if (null !== $jws->getEncodedPayload($signature)) {
                return sprintf('%s.%s', $encoded_protected_headers, $jws->getEncodedPayload($signature));
            }

            $payload = empty($jws->getPayload()) ? $detached_payload : $jws->getPayload();
            $payload = is_string($payload) ? $payload : json_encode($payload);

            return sprintf('%s.%s', $encoded_protected_headers, Base64Url::encode($payload));
        }

        $payload = empty($jws->getPayload()) ? $detached_payload : $jws->getPayload();
        $payload = is_string($payload) ? $payload : json_encode($payload);

        return sprintf('%s.%s', $encoded_protected_headers, $payload);
    }

    /**
     * @param JWSInterface    $jws
     * @param JWKSetInterface $jwk_set
     * @param string|null     $detached_payload
     * @param int|null        $recipient_index
     */
    private function verifySignatures(JWSInterface $jws, JWKSetInterface $jwk_set, ?string $detached_payload = null, ?int &$recipient_index = null)
    {
        $this->checkPayload($jws, $detached_payload);
        $this->checkJWKSet($jwk_set);
        $this->checkSignatures($jws);

        $nb_signatures = $jws->countSignatures();

        for ($i = 0; $i < $nb_signatures; $i++) {
            $signature = $jws->getSignature($i);
            $result = $this->verifySignature($jws, $jwk_set, $signature, $detached_payload);

            if (true === $result) {
                $recipient_index = $i;

                return;
            }
        }

        throw new \InvalidArgumentException('Unable to verify the JWS.');
    }

    /**
     * @param JWSInterface $jws
     */
    private function checkSignatures(JWSInterface $jws)
    {
        Assertion::greaterThan($jws->countSignatures(), 0, 'The JWS does not contain any signature.');
    }

    /**
     * @param JWKSetInterface $jwk_set
     */
    private function checkJWKSet(JWKSetInterface $jwk_set)
    {
        Assertion::greaterThan($jwk_set->countKeys(), 0, 'There is no key in the key set.');
    }

    /**
     * @param JWSInterface $jws
     * @param null|string  $detached_payload
     */
    private function checkPayload(Object\JWSInterface $jws, ?string $detached_payload = null)
    {
        Assertion::false(
            null !== $detached_payload && !empty($jws->getPayload()),
            'A detached payload is set, but the JWS already has a payload.'
        );
        Assertion::true(
            !empty($jws->getPayload()) || null !== $detached_payload,
            'No payload.'
        );
    }

    /**
     * @param SignatureInterface $signature
     *
     * @return SignatureAlgorithmInterface
     */
    private function getAlgorithm(SignatureInterface $signature): SignatureAlgorithmInterface
    {
        $complete_headers = array_merge(
            $signature->getProtectedHeaders(),
            $signature->getHeaders()
        );
        Assertion::keyExists($complete_headers, 'alg', 'No "alg" parameter set in the header.');

        $algorithm = $this->jwaManager->getAlgorithm($complete_headers['alg']);
        Assertion::isInstanceOf($algorithm, SignatureAlgorithmInterface::class, sprintf('The algorithm "%s" is not supported or does not implement SignatureInterface.', $complete_headers['alg']));

        return $algorithm;
    }
}
