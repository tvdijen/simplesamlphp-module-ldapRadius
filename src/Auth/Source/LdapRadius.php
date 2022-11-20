<?php

declare(strict_types=1);

namespace SimpleSAML\Module\ldapRadius\Auth\Source;

use Exception;
use SimpleSAML\Assert\Assert;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\ldap\Auth\Source\Ldap;
use SimpleSAML\Module\radius\Auth\Source\Radius;
use SimpleSAML\Utils;

use function array_keys;
use function array_merge;
use function in_array;
use function sprintf;

/**
 * Class for username/password/otp authentication.
 *
 * @package tvdijen/simplesamlphp-module-ldapRadius
 */
final class LdapRadius extends Auth\Source
{
    /**
     * The string used to identify our states.
     */
    public const STAGEID = '\SimpleSAML\Module\ldapRadius\Auth\Source\LdapRadius.state';

    /**
     * The key of the AuthId field in the state.
     */
    public const AUTHID = '\SimpleSAML\Module\ldapRadius\Auth\Source\LdapRadius.AuthId';

    /**
     * The primary authentication source to authenticate with.
     */
    private string $primarySource;

    /**
     * The secondary authentication source to authenticate with.
     */
    private string $secondarySource;

    /**
     * @var array  The names of all the configured auth sources
     */
//    private array $validSources;


    /**
     * Constructor for this authentication source.
     *
     * @param array $info  Information about this authentication source.
     * @param array &$config  Configuration for this authentication source.
     */
    public function __construct(array $info, array &$config)
    {
        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        Assert::keyExists($config, 'primary');
        Assert::keyExists($config, 'secondary');
        Assert::stringNotEmpty($config['primary']);
        Assert::stringNotEmpty($config['secondary']);

        $this->primarySource = $config['primary'];
        $this->secondarySource = $config['secondary'];

        $authsources = Configuration::getConfig('authsources.php')->toArray();
//        $this->validSources = array_keys($authsources->toArray());

        Assert::keyExists($authsources, $this->primarySource);
        Assert::keyExists($authsources, $this->secondarySource);
    }


    /**
     * Process a request.
     *
     * If an authentication source returns from this function, it is assumed to have
     * authenticated the user, and should have set elements in $state with the attributes
     * of the user.
     *
     * If the authentication process requires additional steps which make it impossible to
     * complete before returning from this function, the authentication source should
     * save the state, and at a later stage, load the state, update it with the authentication
     * information about the user, and call completeAuth with the state array.
     *
     * @param array &$state Information about the current authentication.
     */
    public function authenticate(array &$state): void
    {
        $state[self::AUTHID] = $this->authId;
//        $state['ldapRadius:primary'] = $this->primarySource;
//        $state['ldapRadius:secondary'] = $this->secondarySource;

        // Save the $state array, so that we can restore if after a redirect
        $id = Auth\State::saveState($state, self::STAGEID);

        /* Redirect to the select source page. We include the identifier of the
         * saved state array as a parameter to the login form
         */
        $url = Module::getModuleURL('ldapRadius/login');
        $params = ['AuthState' => $id];

        $httpUtils = new Utils\HTTP();
        $httpUtils->redirectTrustedURL($url, $params);

/**
        $source = $this->selectAuthSource();
        $as = Auth\Source::getById($source);

        if ($as === null || !in_array($source, $this->validSources, true)) {
            throw new Exception(sprintf("Invalid authentication source:  %s", $source));
        }

        static::doAuthentication($as, $state);
*/
    }


    /**
     * Handle login request.
     *
     * This function is used by the login form (ldapRadius/loginuserpassotp) when the user
     * enters a username, password and otp. On success, it will not return. On wrong
     * username/password failure, otp failure and other errors, it will throw an exception.
     *
     * @param string $authStateId  The identifier of the authentication state.
     * @param string $username  The username the user wrote.
     * @param string $password  The password the user wrote.
     * @param string $otp  The otp the user wrote.
     */
    public static function handleLogin(array $state, string $username, string $password, string $otp): void
    {
        // Retrieve the authentication source we are executing.
        Assert::keyExists($state, self::AUTHID);

        //** @var \SimpleSAML\Auth\Source|null $source
        $source = Auth\Source::getById($state[self::AUTHID]);
        if ($source === null) {
            throw new Exception(sprintf("Could not find authentication source with id '%s'", $state[self::AUTHID]));
        }

        //**
        // * $source now contains the authentication source on which authenticate()
        // * was called. We should call login() on the same authentication source.
        // *

        // Attempt to log in
        try {
            $attributes = $source->login($username, $password, $otp);
        } catch (Exception $e) {
            Logger::stats(sprintf("Unsuccessful login attempt from '%s'.", $_SERVER['REMOTE_ADDR']));
            throw $e;
        }
        Logger::stats(sprintf("User '%s' successfully authenticated from '%s'.", $username, $_SERVER['REMOTE_ADDR']));

        // Save the attributes we received from the login-function in the $state-array
        $state['Attributes'] = $attributes;

        // Return control to SimpleSAMLphp after successful authentication.
        parent::completeAuth($state);
    }


    public function login(string $username, string $password, string $otp): array
    {
        $primarySource = Auth\Source::getById($this->primarySource);

        $authsources = Configuration::getConfig('authsources.php')->toArray();
        $ldap = new class (['AuthId' => $this->primarySource], $authsources[$this->primarySource]) extends Ldap
        {
            public function loginOverload(string $username, string $password): array
            {
                return $this->login($username, $password);
            }
        };

        $ldapAttributes = $ldap->loginOverload($username, $password);

        $radius = new class(['AuthId' => $this->secondarySource], $authsources[$this->secondarySource]) extends Radius
        {
            public function loginOverload(string $username, string $otp): array
            {
                return $this->login($username, $otp);
            }
        };

        $radiusAttributes = $radius->loginOverload($username, $otp);
        return array_merge($ldapAttributes, $radiusAttributes);
    }
}
