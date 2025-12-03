<?php

declare(strict_types=1);

namespace SimpleSAML\Module\ldapRadius\Auth\Source;

use Exception;
use SimpleSAML\Assert\Assert;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\ldap\Auth\Source\Ldap;
use SimpleSAML\Module\radius\Auth\Source\Radius;
use SimpleSAML\Utils;

use function array_merge;
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
     * The input type for the username-field. Can be 'text' or 'email'.
     */
    private string $usernameTypeHint = 'text';

    private ?string $usernamePattern;

    private ?int $passwordMinLength;

    private ?string $otpInputMode;

    private ?string $otpPattern;


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

        $this->usernameTypeHint = $config['usernameTypeHint'] ?? 'text';
        Assert::oneOf($this->usernameTypeHint, ['text', 'email']);

        $this->usernamePattern = $config['usernamePattern'] ?? null;
        $this->passwordMinLength = $config['passwordMinLength'] ?? null;
        $this->otpInputMode = $config['otpInputMode'] ?? null;
        $this->otpPattern = $config['otpPattern'] ?? null;

        $authsources = Configuration::getConfig('authsources.php')->toArray();
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
        $state['ldapRadius:usernameTypeHint'] = $this->usernameTypeHint;
        $state['ldapRadius:usernamePattern'] = $this->usernamePattern;
        $state['ldapRadius:passwordMinLength'] = $this->passwordMinLength;
        $state['ldapRadius:otpInputMode'] = $this->otpInputMode;
        $state['ldapRadius:otpPattern'] = $this->otpPattern;

        // Save the $state array, so that we can restore if after a redirect
        $id = Auth\State::saveState($state, self::STAGEID);

        /* Redirect to the select source page. We include the identifier of the
         * saved state array as a parameter to the login form
         */
        $url = Module::getModuleURL('ldapRadius/login');
        $params = ['AuthState' => $id];

        $httpUtils = new Utils\HTTP();
        $httpUtils->redirectTrustedURL($url, $params);
    }


    /**
     * Handle login request.
     *
     * This function is used by the login form (ldapRadius/loginuserpassotp) when the user
     * enters a username, password and otp. On success, it will not return. On wrong
     * username/password failure, otp failure and other errors, it will throw an exception.
     *
     * @param array<mixed> $state The state.
     * @param string $username  The username the user wrote.
     * @param string $password  The password the user wrote.
     * @param string $otp  The otp the user wrote.
     */
    public static function handleLogin(
        array $state,
        string $username,
        #[\SensitiveParameter]
        string $password,
        #[\SensitiveParameter]
        string $otp,
    ): void {
        // Retrieve the authentication source we are executing.
        Assert::keyExists($state, self::AUTHID);

        /**
         * @var \SimpleSAML\Auth\Source|null $source
         */
        $source = Auth\Source::getById($state[self::AUTHID]);
        if ($source === null) {
            throw new Exception(sprintf("Could not find authentication source with id '%s'", $state[self::AUTHID]));
        }

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


    public function login(
        string $username,
        #[\SensitiveParameter]
        string $password,
        #[\SensitiveParameter]
        string $otp,
    ): array {
        Logger::info('ldapRadius: Attempting LDAP-authentication.');
        $authsources = Configuration::getConfig('authsources.php')->toArray();

        $radius = new class (['AuthId' => $this->secondarySource], $authsources[$this->secondarySource]) extends Radius
        {
            public function loginOverload(
                string $username,
                #[\SensitiveParameter]
                string $otp,
            ): array {
                return $this->login($username, $otp);
            }
        };
        $radiusAttributes = $radius->loginOverload($username, $otp);
        Logger::info('ldapRadius: RADIUS-authentication succeeded; continuing to LDAP-authentication.');

        $ldap = new class (['AuthId' => $this->primarySource], $authsources[$this->primarySource]) extends Ldap
        {
            public function loginOverload(
                string $username,
                #[\SensitiveParameter]
                string $password,
            ): array {
                return $this->login($username, $password);
            }
        };
        $ldapAttributes = $ldap->loginOverload($username, $password);

        return array_merge($ldapAttributes, $radiusAttributes);
    }
}
