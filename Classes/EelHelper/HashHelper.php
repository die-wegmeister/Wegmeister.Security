<?php

declare(strict_types=1);

namespace Wegmeister\Security\EelHelper;

use Wegmeister\Security\Service\NonceService;
use Neos\Flow\Annotations as Flow;
use Neos\Eel\ProtectedContextAwareInterface;

/**
 * Different felpers for using hashes and nonces for Eel contexts
 */
class HashHelper implements ProtectedContextAwareInterface
{
    /**
     * Class has to be defined the old way is typed properties and lazy loading will not work well together.
     * @var NonceService
     */
    #[Flow\Inject]
    protected $nonceService;

    /**
     * Return the desired hash of the given string
     *
     * @param string $string The string to hash
     * @param string $algorithm The algorithm to use
     * @param bool $binary Return the binary representation of the hash
     * @return string
     */
    public function hash(string $string, string $algorithm, bool $binary = false): string
    {
        return hash($algorithm, $string, $binary);
    }

    /**
     * Return the sha256 hash of the given string
     *
     * @param string $string The string to hash
     * @param bool $binary Return the binary representation of the hash
     * @return string The sha256 hashed value of the string
     */
    public function sha256(string $string, bool $binary = false): string
    {
        return hash('sha256', $string, $binary);
    }

    /**
     * Create a static nonce, that will be the same for all calls to this method
     *
     * @return string
     */
    public function nonce(): string
    {
        return $this->nonceService->getNonce();
    }

    /**
     * Add a nonce to all scripts, if it is used for the header
     *
     * @return string
     */
    public function addNonceToScripts(string $value): string
    {
        if ($this->nonceService->isNonceUsed()) {
            $value = $this->nonceService->addNonceToScripts($value);
        }

        return $value;
    }

    /**
     * Add a nonce to all styles, if it is used for the header
     *
     * @return string
     */
    public function addNonceToStyles(string $value): string
    {
        if ($this->nonceService->isNonceUsed()) {
            $value = $this->nonceService->addNonceToStyles($value);
        }

        return $value;
    }

    /**
     * All methods are considered safe
     *
     * @param string $methodName
     * @return boolean
     */
    public function allowsCallOfMethod($methodName)
    {
        return true;
    }
}
