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

use Base64Url\Base64Url;
use Jose\Algorithm\JWAManager;
use Jose\Algorithm\SignatureAlgorithmInterface;
use Jose\Factory\AlgorithmManagerFactory;
use Jose\Object\JWKInterface;
use Jose\Object\JWSInterface;
use Jose\Object\Signature;
use Jose\Object\SignatureInterface;

final class Signer
{
    /**
     * @var JWAManager
     */
    private $jwaManager;

    use Behaviour\HasKeyChecker;
    use Behaviour\CommonSigningMethods;

    /**
     * Signer constructor.
     *
     * @param string[]|SignatureAlgorithmInterface[] $signature_algorithms
     */
    public function __construct(array $signature_algorithms)
    {
        $this->setSignatureAlgorithms($signature_algorithms);
        $this->jwaManager = AlgorithmManagerFactory::createAlgorithmManager($signature_algorithms);
    }

    /**
     * @param array $signature_algorithms
     *
     * @return Signer
     */
    public static function createSigner(array $signature_algorithms): Signer
    {
        $signer = new self($signature_algorithms);

        return $signer;
    }

    /**
     * @param JWSInterface $jws
     */
    public function sign(JWSInterface &$jws)
    {
        $nb_signatures = $jws->countSignatures();

        for ($i = 0; $i < $nb_signatures; $i++) {
            $this->computeSignature($jws, $jws->getSignature($i));
        }
    }

    /**
     * @param JWSInterface       $jws
     * @param SignatureInterface $signature
     */
    private function computeSignature(JWSInterface $jws, SignatureInterface &$signature)
    {
        if (null === $signature->getSignatureKey()) {
            return;
        }
        $this->checkKeyUsage($signature->getSignatureKey(), 'signature');

        $signature_algorithm = $this->getSignatureAlgorithm($signature->getAllHeaders(), $signature->getSignatureKey());

        $input = $this->getInputToSign($jws, $signature);

        $value = $signature_algorithm->sign(
            $signature->getSignatureKey(),
            $input
        );

        $signature = Signature::createSignatureFromLoadedData(
            $value,
            $signature->getEncodedProtectedHeaders(),
            $signature->getHeaders()
        );
    }

    /**
     * @param JWSInterface       $jws
     * @param SignatureInterface $signature
     *
     * @return string
     */
    private function getInputToSign(JWSInterface $jws, SignatureInterface $signature): string
    {
        $this->checkB64HeaderAndCrit($signature);
        $encoded_protected_headers = $signature->getEncodedProtectedHeaders();
        $payload = $jws->getPayload();
        if (!$signature->hasProtectedHeader('b64') || true === $signature->getProtectedHeader('b64')) {
            $encoded_payload = Base64Url::encode(is_string($payload) ? $payload : json_encode($payload));

            return sprintf('%s.%s', $encoded_protected_headers, $encoded_payload);
        }

        return sprintf('%s.%s', $encoded_protected_headers, $payload);
    }

    /**
     * @param SignatureInterface $signature
     *
     * @throws \InvalidArgumentException
     */
    private function checkB64HeaderAndCrit(SignatureInterface $signature)
    {
        if (!$signature->hasProtectedHeader('b64')) {
            return;
        }

        if (false == $signature->hasProtectedHeader('crit')) {
            throw new \InvalidArgumentException('The protected header parameter "crit" is mandatory when protected header parameter "b64" is set.');
        }
        $critHeader = $signature->getProtectedHeader('crit');
        if (!is_array($critHeader)) {
            throw new \InvalidArgumentException('The protected header parameter "crit" must be an array.');
        }
        if (!in_array('b64', $critHeader)) {
            throw new \InvalidArgumentException('The protected header parameter "crit" must contain "b64" when protected header parameter "b64" is set.');
        }
    }

    /**
     * @param array        $complete_headers The complete headers
     * @param JWKInterface $key
     *
     * @return SignatureAlgorithmInterface
     */
    private function getSignatureAlgorithm(array $complete_headers, JWKInterface $key): SignatureAlgorithmInterface
    {
        if (!array_key_exists('alg', $complete_headers)) {
            throw new \InvalidArgumentException('No "alg" parameter set in the headers.');
        }
        if ($key->has('alg') && $key->get('alg') !== $complete_headers['alg']) {
            throw new \InvalidArgumentException(sprintf('The algorithm "%s" is not allowed with this key.', $complete_headers['alg']));
        }

        $algorithm = $this->jwaManager->getAlgorithm($complete_headers['alg']);
        if (!$algorithm instanceof SignatureAlgorithmInterface) {
            throw new \InvalidArgumentException(sprintf('The algorithm "%s" is not supported or is not a signature algorithm.', $complete_headers['alg']));
        }

        return $algorithm;
    }
}
