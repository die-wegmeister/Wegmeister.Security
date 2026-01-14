<?php

namespace Wegmeister\Security\Service;

use Neos\Flow\Annotations as Flow;

#[Flow\Scope('singleton')]
#[Flow\Proxy(false)]
class NonceService
{
    /**
     * A static nonce, that can be used to protect inline scripts
     */
    protected string $nonce;

    /**
     * Boolean, to check if the nonce has already been used.
     */
    protected bool $nonceIsUsed = false;

    /**
     * Initialize service with a static nonce
     */
    public function __construct()
    {
        $this->nonce = bin2hex(random_bytes(16));
    }

    /**
     * Check, if the nonce has already been used.
     *
     * @return bool
     */
    public function isNonceUsed(): bool
    {
        return $this->nonceIsUsed;
    }

    /**
     * Add nonce to all scripts
     * @param string $content
     * @return string
     */
    public function addNonceToScripts(string $content): string
    {
        $content = preg_replace(
            '/(<script((?! (nonce|src)=)[^>]*))>/i',
            '$1 nonce="' . $this->getNonce() . '">',
            $content
        );
        return $content;
    }

    /**
     * Add nonce to all styles
     * @param string $content
     * @return string
     */
    public function addNonceToStyles(string $content): string
    {
        $content = preg_replace(
            '/(<style((?! (nonce)=)[^>]*))>/i',
            '$1 nonce="' . $this->getNonce() . '">',
            $content
        );
        return $content;
    }

    /**
     * Create a static nonce, that will be the same for all calls to this method
     *
     * @return string
     */
    public function getNonce(): string
    {
        $this->nonceIsUsed = true;
        return $this->nonce;
    }
}
