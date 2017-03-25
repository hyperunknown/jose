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

use Assert\Assertion;
use Http\Client\HttpClient;
use Http\Message\RequestFactory;

/**
 * Class DownloadedJWKSet.
 */
abstract class DownloadedJWKSet implements JWKSetInterface
{
    use BaseJWKSet;
    use JWKSetPEM;

    /**
     * @var string
     */
    private $url;

    /**
     * @var HttpClient
     */
    private $client;

    /**
     * @var RequestFactory
     */
    private $requestFactory;

    /**
     * DownloadedJWKSet constructor.
     *
     * @param RequestFactory $requestFactory
     * @param HttpClient     $client
     * @param string         $url
     * @param bool           $allow_http_connection
     */
    public function __construct(RequestFactory $requestFactory, HttpClient $client, string $url, bool $allow_http_connection = false)
    {
        Assertion::false(false === filter_var($url, FILTER_VALIDATE_URL, FILTER_FLAG_SCHEME_REQUIRED | FILTER_FLAG_HOST_REQUIRED), 'Invalid URL.');
        $allowed_protocols = ['https'];
        if (true === $allow_http_connection) {
            $allowed_protocols[] = 'http';
        }
        Assertion::inArray(mb_substr($url, 0, mb_strpos($url, '://', 0, '8bit'), '8bit'), $allowed_protocols, sprintf('The provided sector identifier URI is not valid: scheme must be one of the following: %s.', json_encode($allowed_protocols)));

        $this->url = $url;
        $this->client = $client;
        $this->requestFactory = $requestFactory;
    }

    /**
     * {@inheritdoc}
     */
    public function addKey(JWKInterface $key)
    {
        //Not available
    }

    /**
     * {@inheritdoc}
     */
    public function removeKey($index)
    {
        //Not available
    }

    /**
     * @return string
     */
    protected function getContent()
    {
        $request = $this->requestFactory->createRequest('GET', $this->url);
        $response = $this->client->sendRequest($request);
        Assertion::true($response->getStatusCode() >= 200 && $response->getStatusCode() < 300, 'Unable to get the content.');
        return (string) $response->getBody()->getContents();
    }
}
