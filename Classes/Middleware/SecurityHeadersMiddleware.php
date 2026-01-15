<?php

namespace Wegmeister\Security\Middleware;

use Neos\Flow\Annotations as Flow;
use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Wegmeister\Security\Service\NonceService;

class SecurityHeadersMiddleware implements MiddlewareInterface
{
    /** Header configuration */
    #[Flow\InjectConfiguration(path: "headers")]
    protected array $headersConfiguration;

    /**
     * Class has to be defined the old way is typed properties and lazy loading will not work well together.
     * @var NonceService
     */
    #[Flow\Inject]
    protected $nonceService;

    /**
     * Add security headers to the response, if they are not already present.
     *
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $next
     *
     * @return ResponseInterface
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $next): ResponseInterface
    {
        // Handle request and save the response passed from middleware chain
        $response = $next->handle($request);

        // Skip, if Location header is present
        if ($response->hasHeader('Location')) {
            return $response;
        }

        // Skip, if we do not have a 200 OK response
        if ($response->getStatusCode() !== 200) {
            return $response;
        }

        // Add security headers
        if (!$response->hasHeader('X-Content-Type-Options')) {
            $response = $response->withHeader('X-Content-Type-Options', 'nosniff');
        }
        if (!$response->hasHeader('X-XSS-Protection')) {
            $response = $response->withHeader('X-XSS-Protection', '0');
        }

        if ($response->hasHeader('Content-Security-Policy')) {
            // Update existing CSP header to add nonce
            $response = $this->updateCSPHeaderWithNonce($response);
        } else {
            $response = $this->addCSPHeader($request, $response);
        }

        if (!$response->hasHeader('Strict-Transport-Security')) {
            $config = $this->headersConfiguration['Strict-Transport-Security'] ?? [];
            $maxAge = $config['maxAge'] ?? 31536000;
            $includeSubDomains = $config['includeSubDomains'] ?? true;
            $preload = $config['preload'] ?? true;
            $headerValue = 'max-age=' . $maxAge;
            if ($includeSubDomains) {
                $headerValue .= '; includeSubDomains';
            }
            if ($preload) {
                $headerValue .= '; preload';
            }
            $response = $response->withHeader('Strict-Transport-Security', $headerValue);
        }
        if (!$response->hasHeader('X-Frame-Options')) {
            $response = $response->withHeader('X-Frame-Options', $this->headersConfiguration['X-Frame-Options'] ?? 'DENY');
        }
        if (!$response->hasHeader('Referrer-Policy')) {
            $response = $response->withHeader('Referrer-Policy', $this->headersConfiguration['Referrer-Policy'] ?? 'strict-origin');
        }
        if (!$response->hasHeader('X-Permitted-Cross-Domain-Policies')) {
            $response = $response->withHeader('X-Permitted-Cross-Domain-Policies', $this->headersConfiguration['X-Permitted-Cross-Domain-Policies'] ?? 'none');
        }
        if (!$response->hasHeader('Cross-Origin-Opener-Policy')) {
            $response = $response->withHeader('Cross-Origin-Opener-Policy', $this->headersConfiguration['Cross-Origin-Opener-Policy'] ?? 'same-origin');
        }
        if (!$response->hasHeader('Cross-Origin-Resource-Policy')) {
            $response = $response->withHeader('Cross-Origin-Resource-Policy', $this->headersConfiguration['Cross-Origin-Resource-Policy'] ?? 'same-origin');
        }
        if (!$response->hasHeader('Permissions-Policy')) {
            $response = $response->withHeader('Permissions-Policy', $this->headersConfiguration['Permissions-Policy'] ?? 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()');
        }

        return $response;
    }

    /**
     * Update existing Content-Security-Policy header to add nonce to script-src and style-src directives.
     * @param ResponseInterface $response
     * @return ResponseInterface
     */
    protected function updateCSPHeaderWithNonce(ResponseInterface $response): ResponseInterface
    {
        $cspHeader = $response->getHeaderLine('Content-Security-Policy');
        $cspDirectives = explode(';', $cspHeader);
        $updatedDirectives = [];
        foreach ($cspDirectives as $directive) {
            $directive = trim($directive);

            if (str_contains($directive, "'unsafe-inline'")) {
                // Skip adding nonce if 'unsafe-inline' is present
                $updatedDirectives[] = $directive;
                continue;
            }

            if (str_starts_with($directive, 'script-src')) {
                // Remove existing nonce entries
                $directive = preg_replace("/ 'nonce-[^']*'/", '', $directive);

                // Update script tags in the response body
                $content = $response->getBody()->getContents();
                $response = $response->withBody(
                    Utils::streamFor(
                        $this->nonceService->addNonceToScripts($content)
                    )
                );

                // Add nonce to script-src directive
                $directive .= " 'nonce-" . $this->nonceService->getNonce() . "'";
            } else if (str_starts_with($directive, 'style-src')) {
                // Remove existing nonce entries
                $directive = preg_replace("/ 'nonce-[^']*'/", '', $directive);

                // Update style tags in the response body
                $content = $response->getBody()->getContents();
                $response = $response->withBody(
                    Utils::streamFor(
                        $this->nonceService->addNonceToStyles($content)
                    )
                );

                // Add nonce to style-src directive
                $directive .= " 'nonce-" . $this->nonceService->getNonce() . "'";
            }

            $updatedDirectives[] = $directive;
        }

        $newCspHeader = implode('; ', $updatedDirectives);
        $response = $response->withHeader('Content-Security-Policy', $newCspHeader);

        return $response;
    }

    /**
     * Add Content-Security-Policy header to response.
     * @param ResponseInterface $response
     * @return ResponseInterface
     */
    protected function addCSPHeader(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {

        $cspConfig = $this->headersConfiguration['ContentSecurityPolicy']['parts'] ?? [];
        $cspDirectives = [];

        foreach ($cspConfig as $directive => $value) {
            // Skip null values
            if ($value === null) {
                continue;
            }

            // Add nonce to script-src and style-src
            if ($directive === 'script-src') {
                // Update script tags in the response body
                $content = $response->getBody()->getContents();
                $response = $response->withBody(
                    Utils::streamFor(
                        $this->nonceService->addNonceToScripts($content)
                    )
                );

                // Add nonce to CSP header
                $value .= " 'nonce-" . $this->nonceService->getNonce() . "'";

                // Allow unsafe-eval in Neos backend, if configured
                if (
                    $this->headersConfiguration['ContentSecurityPolicy']['allowUnsafeEvalInNeosBackend'] &&
                    $request->getUri()->getPath() === '/neos/content'
                ) {
                    $value .= " 'unsafe-eval'";
                }
            } else if ($directive === 'style-src') {
                if (
                    $this->headersConfiguration['ContentSecurityPolicy']['allowUnsafeInlineStylesInNeosBackend'] &&
                    str_starts_with($request->getUri()->getPath(), '/neos/')
                ) {
                    // Allow unsafe-inline in Neos backend (if configured).
                    // Therefore skip adding nonce to styles, as this would conflict with unsafe-inline.
                    $value .= " 'unsafe-inline'";
                } else {
                    // Update style tags in the response body
                    $content = $response->getBody()->getContents();
                    $response = $response->withBody(
                        Utils::streamFor(
                            $this->nonceService->addNonceToStyles($content)
                        )
                    );

                    // Add nonce to CSP header
                    $value .= " 'nonce-" . $this->nonceService->getNonce() . "'";
                }
            }
            $value = trim($value);

            // Skip empty values
            if ($value === '') {
                continue;
            }

            $cspDirectives[] = $directive . ' ' . $value;
        }

        if (!empty($cspDirectives)) {
            $response = $response->withHeader('Content-Security-Policy', implode('; ', $cspDirectives));
        }

        return $response;
    }
}
