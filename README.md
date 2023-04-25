# simplesamlphp-module-ldapRadius
Combined LDAP / Radius authsource

## Configuration

```php
    'LDAPRADIUS' => [
        'ldapRadius:LdapRadius',

        // The primary authsource to deal with username & password
        'primary' => 'LDAP',

        // The secondary authsource to deal with username & OTP
        'primary' => 'RADIUS',

        // Type hint to be enforced by the browser for the username-field
        // Defaults to 'text', possible values are 'text' and 'email'
        'usernameTypeHint' => 'email',

        // The pattern to be enforced by the browser for the username-field
        // Defaults to `null`
        'usernamePattern' => null,

        // The minimum password-length to be enforced on the password-field
        // Defaults to `null`
        'passwordMinLength' => 8,

        // The input mode for the OTP-field. This will select the appropriate keyboard on mobile devices
        // Defaults to `null`
        'otpInputMode' => null,

        // The pattern to be enforced by the browser for the OTP-field
        // Defaults to `null`
        'otpPattern' => null,
    ],
```
