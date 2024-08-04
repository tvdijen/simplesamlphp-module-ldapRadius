<?php

declare(strict_types=1);

namespace SimpleSAML\Module\ldapRadius\Controller;

use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Module\ldapRadius\Auth\Source\LdapRadius;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Controller class for the ldapRadius module.
 *
 * This class serves the different views available in the module.
 *
 * @package tvdijen/simplesamlphp-module-ldapRadius
 */
class Login
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    /**
     * @var \SimpleSAML\Auth\State|string
     * @psalm-var \SimpleSAML\Auth\State|class-string
     */
    protected $authState = Auth\State::class;


    /**
     * Controller constructor.
     *
     * It initializes the global configuration for the controllers implemented here.
     *
     * @param \SimpleSAML\Configuration $config The configuration to use by the controllers.
     *
     * @throws \Exception
     */
    public function __construct(
        Configuration $config,
    ) {
        $this->config = $config;
    }


    /**
     * Inject the \SimpleSAML\Auth\State dependency.
     *
     * @param \SimpleSAML\Auth\State $authState
     */
    public function setAuthState(Auth\State $authState): void
    {
        $this->authState = $authState;
    }


    /**
     * This page shows a username/password/otp login form, and passes information from it
     * to a primary and then a secondary auth source.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \SimpleSAML\XHTML\Template|\SimpleSAML\HTTP\RunnableResponse
     */
    public function login(Request $request): Response
    {
        // Retrieve the authentication state
        if (!$request->query->has('AuthState')) {
            throw new Error\BadRequest('Missing AuthState parameter.');
        }
        $authStateId = $request->query->get('AuthState');

        $state = $this->authState::loadState($authStateId, LdapRadius::STAGEID);
        $source = Auth\Source::getById($state[LdapRadius::AUTHID]);

        $errorCode = null;
        $errorParams = null;

        if (isset($state['error'])) {
            $errorCode = $state['error']['code'];
            $errorParams = $state['error']['params'];
        }

        if (
            $request->server->get('REQUEST_METHOD') === 'POST' &&
            $request->request->has('username') &&
            $request->request->has('password') &&
            $request->request->has('otp')
        ) {
            $username = $request->get('username');
            $password = $request->get('password');
            $otp = $request->get('otp');

            try {
                $source->handleLogin($state, $username, $password, $otp);
            } catch (Error\Error $e) {
                // Login failed. Extract error code and parameters, to display the error
                $errorCode = $e->getErrorCode();
                $errorParams = $e->getParameters();
                $state['error'] = [
                    'code' => $errorCode,
                    'params' => $errorParams,
                ];
            }

            if (isset($state['error'])) {
                unset($state['error']);
            }
        }

        // Build template
        $t = new Template($this->config, 'ldapRadius:login.twig');

        $t->data['AuthState'] = $this->authState::saveState($state, LdapRadius::STAGEID);
        $t->data['errorcode'] = $errorCode;
        $t->data['errorcodes'] = Error\ErrorCodes::getAllErrorCodeMessages();
        $t->data['errorparams'] = $errorParams;
        $t->data['forceUsername'] = $state['forceUsername'] ?? false;
        $t->data['username'] = $state['core:username'] ?? '';
        $t->data['usernameTypeHint'] = $state['ldapRadius:usernameTypeHint'];
        $t->data['usernamePattern'] = $state['ldapRadius:usernamePattern'];
        $t->data['passwordMinLength'] = $state['ldapRadius:passwordMinLength'];
        $t->data['otpInputMode'] = $state['ldapRadius:otpInputMode'];
        $t->data['otpPattern'] = $state['ldapRadius:otpPattern'];

        return $t;
    }
}
