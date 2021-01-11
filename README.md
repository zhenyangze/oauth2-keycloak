# A wrapper for the Keycloak OAuth 2.0 Client Provider

## Installation

To install, use composer:

```php
composer require yangze/oauth2-keycloak
```



## Usage

### Init

```php
$sso = SSO::init([
    'authServerUrl'         => 'http://127.0.0.1:8080/auth',
    'realm'                 => 'xxxx',
    'clientId'              => 'backend',
    'clientSecret'          => 'xxxxx',
    'redirectUri'           => 'http://127.0.0.1:8003/auto',
]);
```

### Login

```php
$user = $sso->checkLogin();
$user->getAttr('username');
$user->toArray();
```

### logout

```php
$sso->logout();
```

### Other Methd

```php
$sso->getAccessToken(); // can save in client
$sso->getToken(); // secret
$sso->getAuthorizationUrl();
$sso->getLogoutUrl();
```

