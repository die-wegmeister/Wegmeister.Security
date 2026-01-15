<?php

namespace Wegmeister\Security\Service;

use DOMDocument;
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
        $dom = new DOMDocument();
        libxml_use_internal_errors(true);
        $dom->loadHTML($content, LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
        libxml_use_internal_errors(false);

        $scripts = $dom->getElementsByTagName('script');

        foreach ($scripts as $script) {
            if ($script->hasAttribute('src')) {
                continue;
            }

            // Add or replace nonce attribute
            $script->setAttribute('nonce', $this->getNonce());
        }

        $content = $dom->saveHTML();

        return $content;
    }

    /**
     * Add nonce to all styles
     * @param string $content
     * @return string
     */
    public function addNonceToStyles(string $content): string
    {
        $dom = new DOMDocument();
        libxml_use_internal_errors(true);
        $dom->loadHTML($content, LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
        libxml_use_internal_errors(false);

        $styles = $dom->getElementsByTagName('style');

        foreach ($styles as $style) {
            if ($style->hasAttribute('src')) {
                continue;
            }

            // Add or replace nonce attribute
            $style->setAttribute('nonce', $this->getNonce());
        }

        $content = $dom->saveHTML();

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
