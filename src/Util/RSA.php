<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Util;

use Assert\Assertion;
use Jose\KeyConverter\RSAKey;

final class RSA
{
    /**
     * Integer-to-Octet-String primitive.
     *
     * @param BigInteger $x
     * @param int                   $xLen
     *
     * @return string
     */
    private static function convertIntegerToOctetString(BigInteger $x, int $xLen): string
    {
        $x = $x->toBytes();
        if (strlen($x) > $xLen) {
            throw new \InvalidArgumentException('Invalid data');
        }

        return str_pad($x, $xLen, chr(0), STR_PAD_LEFT);
    }

    /**
     * Octet-String-to-Integer primitive.
     *
     * @param string $x
     *
     * @return BigInteger
     */
    private static function convertOctetStringToInteger(string $x): BigInteger
    {
        return BigInteger::createFromBinaryString($x);
    }

    /**
     * Exponentiate with or without Chinese Remainder Theorem.
     * Operation with primes 'p' and 'q' is appox. 2x faster.
     *
     * @param RSAKey $key
     * @param BigInteger     $c
     *
     * @return BigInteger
     */
    private static function exponentiate(RSAKey $key, BigInteger $c): BigInteger
    {
        if ($key->isPublic() || empty($key->getPrimes())) {
            return $c->modPow($key->getExponent(), $key->getModulus());
        }

        $p = $key->getPrimes()[0];
        $q = $key->getPrimes()[1];
        $dP = $key->getExponents()[0];
        $dQ = $key->getExponents()[1];
        $qInv = $key->getCoefficient();

        $m1 = $c->modPow($dP, $p);
        $m2 = $c->modPow($dQ, $q);
        $h = $qInv->multiply($m1->subtract($m2)->add($p))->mod($p);
        $m = $m2->add($h->multiply($q));

        return $m;
    }

    /**
     * RSA EP.
     *
     * @param RSAKey     $key
     * @param BigInteger $m
     *
     * @return BigInteger
     */
    private static function getRSAEP(RSAKey $key, BigInteger $m): BigInteger
    {
        if ($m->compare(BigInteger::createFromDecimal(0)) < 0 || $m->compare($key->getModulus()) > 0) {
            throw new \InvalidArgumentException('Unable to get the RSA EP');
        }

        return self::exponentiate($key, $m);
    }

    /**
     * RSA DP.
     *
     * @param RSAKey     $key
     * @param BigInteger $c
     *
     * @return BigInteger
     */
    private static function getRSADP(RSAKey $key, BigInteger $c): BigInteger
    {
        if ($c->compare(BigInteger::createFromDecimal(0)) < 0 || $c->compare($key->getModulus()) > 0) {
            throw new \InvalidArgumentException('Unable to get the RSA DP');
        }

        return self::exponentiate($key, $c);
    }

    /**
     * RSA SP1.
     *
     * @param RSAKey     $key
     * @param BigInteger $m
     *
     * @return BigInteger
     */
    private static function getRSASP1(RSAKey $key, BigInteger $m): BigInteger
    {
        if ($m->compare(BigInteger::createFromDecimal(0)) < 0 || $m->compare($key->getModulus()) > 0) {
            throw new \InvalidArgumentException('Unable to get the RSA SP');
        }

        return self::exponentiate($key, $m);
    }

    /**
     * RSAVP1.
     *
     * @param RSAKey $key
     * @param BigInteger     $s
     *
     * @return BigInteger
     */
    private static function getRSAVP1(RSAKey $key, BigInteger $s)
    {
        if ($s->compare(BigInteger::createFromDecimal(0)) < 0 || $s->compare($key->getModulus()) > 0) {
            throw new \InvalidArgumentException('Unable to get the RSA VP1');
        }

        return self::exponentiate($key, $s);
    }

    /**
     * MGF1.
     *
     * @param string $mgfSeed
     * @param int    $maskLen
     * @param Hash   $mgfHash
     *
     * @return string
     */
    private static function getMGF1(string $mgfSeed, int $maskLen, Hash $mgfHash): string
    {
        $t = '';
        $count = ceil($maskLen / $mgfHash->getLength());
        for ($i = 0; $i < $count; $i++) {
            $c = pack('N', $i);
            $t .= $mgfHash->hash($mgfSeed.$c);
        }

        return mb_substr($t, 0, $maskLen, '8bit');
    }

    /**
     * RSAES-OAEP-ENCRYPT.
     *
     * @param RSAKey $key
     * @param string $m
     * @param Hash   $hash
     *
     * @return string
     */
    private static function encryptRSAESOAEP(RSAKey $key, string $m, Hash $hash): string
    {
        $mLen = mb_strlen($m, '8bit');
        $lHash = $hash->hash('');
        $ps = str_repeat(chr(0), $key->getModulusLength() - $mLen - 2 * $hash->getLength() - 2);
        $db = $lHash.$ps.chr(1).$m;
        $seed = random_bytes($hash->getLength());
        $dbMask = self::getMGF1($seed, $key->getModulusLength() - $hash->getLength() - 1, $hash/*MGF*/);
        $maskedDB = $db ^ $dbMask;
        $seedMask = self::getMGF1($maskedDB, $hash->getLength(), $hash/*MGF*/);
        $maskedSeed = $seed ^ $seedMask;
        $em = chr(0).$maskedSeed.$maskedDB;

        $m = self::convertOctetStringToInteger($em);
        $c = self::getRSAEP($key, $m);
        $c = self::convertIntegerToOctetString($c, $key->getModulusLength());

        return $c;
    }

    /**
     * RSAES-OAEP-DECRYPT.
     *
     * @param RSAKey $key
     * @param string $c
     * @param Hash   $hash
     *
     * @return string
     */
    private static function getRSAESOAEP(RSAKey $key, string $c, Hash $hash): string
    {
        $c = self::convertOctetStringToInteger($c);
        $m = self::getRSADP($key, $c);
        $em = self::convertIntegerToOctetString($m, $key->getModulusLength());
        $lHash = $hash->hash('');
        $maskedSeed = mb_substr($em, 1, $hash->getLength(), '8bit');
        $maskedDB = mb_substr($em, $hash->getLength() + 1, null, '8bit');
        $seedMask = self::getMGF1($maskedDB, $hash->getLength(), $hash/*MGF*/);
        $seed = $maskedSeed ^ $seedMask;
        $dbMask = self::getMGF1($seed, $key->getModulusLength() - $hash->getLength() - 1, $hash/*MGF*/);
        $db = $maskedDB ^ $dbMask;
        $lHash2 = mb_substr($db, 0, $hash->getLength(), '8bit');
        $m = mb_substr($db, $hash->getLength(), null, '8bit');
        Assertion::eq($lHash, $lHash2);
        $m = ltrim($m, chr(0));
        Assertion::eq(ord($m[0]), 1);

        return mb_substr($m, 1, null, '8bit');
    }

    /**
     * EMSA-PSS-ENCODE.
     *
     * @param string $m
     * @param int    $emBits
     * @param Hash   $hash
     *
     * @return string
     */
    private static function encodeEMSAPSS(string $m, int $emBits, Hash $hash): string
    {
        $emLen = ($emBits + 1) >> 3;
        $sLen = $hash->getLength();
        $mHash = $hash->hash($m);
        Assertion::greaterThan($emLen, $hash->getLength() + $sLen + 2);
        $salt = random_bytes($sLen);
        $m2 = "\0\0\0\0\0\0\0\0".$mHash.$salt;
        $h = $hash->hash($m2);
        $ps = str_repeat(chr(0), $emLen - $sLen - $hash->getLength() - 2);
        $db = $ps.chr(1).$salt;
        $dbMask = self::getMGF1($h, $emLen - $hash->getLength() - 1, $hash/*MGF*/);
        $maskedDB = $db ^ $dbMask;
        $maskedDB[0] = ~chr(0xFF << ($emBits & 7)) & $maskedDB[0];
        $em = $maskedDB.$h.chr(0xBC);

        return $em;
    }

    /**
     * EMSA-PSS-VERIFY.
     *
     * @param string $m
     * @param string $em
     * @param int    $emBits
     * @param Hash   $hash
     *
     * @return bool
     */
    private static function verifyEMSAPSS(string $m, string $em, int $emBits, Hash $hash): bool
    {
        $emLen = ($emBits + 1) >> 3;
        $sLen = $hash->getLength();
        $mHash = $hash->hash($m);
        Assertion::greaterThan($emLen, $hash->getLength() + $sLen + 2);
        Assertion::eq($em[mb_strlen($em, '8bit') - 1], chr(0xBC));
        $maskedDB = mb_substr($em, 0, -$hash->getLength() - 1, '8bit');
        $h = mb_substr($em, -$hash->getLength() - 1, $hash->getLength(), '8bit');
        $temp = chr(0xFF << ($emBits & 7));
        Assertion::eq(~$maskedDB[0] & $temp, $temp);
        $dbMask = self::getMGF1($h, $emLen - $hash->getLength() - 1, $hash/*MGF*/);
        $db = $maskedDB ^ $dbMask;
        $db[0] = ~chr(0xFF << ($emBits & 7)) & $db[0];
        $temp = $emLen - $hash->getLength() - $sLen - 2;
        Assertion::eq(mb_substr($db, 0, $temp, '8bit'), str_repeat(chr(0), $temp));
        Assertion::eq(ord($db[$temp]), 1);
        $salt = mb_substr($db, $temp + 1, null, '8bit'); // should be $sLen long
        $m2 = "\0\0\0\0\0\0\0\0".$mHash.$salt;
        $h2 = $hash->hash($m2);

        return hash_equals($h, $h2);
    }

    /**
     * Encryption.
     *
     * @param RSAKey $key
     * @param string $plaintext
     * @param string $hash_algorithm
     *
     * @return string
     */
    public static function encrypt(RSAKey $key, string $plaintext, string $hash_algorithm): string
    {
        /*
         * @var Hash
         */
        $hash = Hash::$hash_algorithm();
        $length = $key->getModulusLength() - 2 * $hash->getLength() - 2;
        Assertion::greaterThan($length, 0);
        $plaintext = str_split($plaintext, $length);
        $ciphertext = '';
        foreach ($plaintext as $m) {
            $ciphertext .= self::encryptRSAESOAEP($key, $m, $hash);
        }

        return $ciphertext;
    }

    /**
     * Decryption.
     *
     * @param RSAKey $key
     * @param string $ciphertext
     * @param string $hash_algorithm
     *
     * @return string
     */
    public static function decrypt(RSAKey $key, string $ciphertext, string $hash_algorithm): string
    {
        Assertion::greaterThan($key->getModulusLength(), 0);
        $hash = Hash::$hash_algorithm();
        $ciphertext = str_split($ciphertext, $key->getModulusLength());
        $ciphertext[count($ciphertext) - 1] = str_pad($ciphertext[count($ciphertext) - 1], $key->getModulusLength(), chr(0), STR_PAD_LEFT);
        $plaintext = '';
        foreach ($ciphertext as $c) {
            $temp = self::getRSAESOAEP($key, $c, $hash);
            $plaintext .= $temp;
        }

        return $plaintext;
    }

    /**
     * Create a signature.
     *
     * @param RSAKey $key
     * @param string $message
     * @param string $hash
     *
     * @return string
     */
    public static function sign(RSAKey $key, string $message, string $hash): string
    {
        Assertion::string($message);
        Assertion::string($hash);
        Assertion::inArray($hash, ['sha256', 'sha384', 'sha512']);
        $em = self::encodeEMSAPSS($message, 8 * $key->getModulusLength() - 1, Hash::$hash());
        Assertion::string($em);
        $message = self::convertOctetStringToInteger($em);
        $signature = self::getRSASP1($key, $message);

        return self::convertIntegerToOctetString($signature, $key->getModulusLength());
    }

    /**
     * Verifies a signature.
     *
     * @param RSAKey $key
     * @param string $message
     * @param string $signature
     * @param string $hash
     *
     * @return bool
     */
    public static function verify(RSAKey $key, string $message, string $signature, string $hash): bool
    {
        Assertion::inArray($hash, ['sha256', 'sha384', 'sha512']);
        Assertion::eq(strlen($signature), $key->getModulusLength());
        $modBits = 8 * $key->getModulusLength();
        $s2 = self::convertOctetStringToInteger($signature);
        $m2 = self::getRSAVP1($key, $s2);
        $em = self::convertIntegerToOctetString($m2, $modBits >> 3);

        return self::verifyEMSAPSS($message, $em, $modBits - 1, Hash::$hash());
    }
}
