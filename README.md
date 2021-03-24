# Azure Functions Input Binding for JWT Tokens

This is an Azure Functions binding validating JWT Tokens for HTTP Triggered Azure Functions.

[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=nikneem_azure-functions-jwt-binding&metric=code_smells)](https://sonarcloud.io/dashboard?id=nikneem_azure-functions-jwt-binding)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=nikneem_azure-functions-jwt-binding&metric=alert_status)](https://sonarcloud.io/dashboard?id=nikneem_azure-functions-jwt-binding)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=nikneem_azure-functions-jwt-binding&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=nikneem_azure-functions-jwt-binding)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=nikneem_azure-functions-jwt-binding&metric=security_rating)](https://sonarcloud.io/dashboard?id=nikneem_azure-functions-jwt-binding)
[![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=nikneem_azure-functions-jwt-binding&metric=sqale_index)](https://sonarcloud.io/dashboard?id=nikneem_azure-functions-jwt-binding)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=nikneem_azure-functions-jwt-binding&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=nikneem_azure-functions-jwt-binding)

## Support & Usage
The binding is only tested on ASP.NET Core 3.1 Azure Functions with the Azure Functions v3.

[Find this package on NuGet](https://www.nuget.org/packages/HexMaster.Functions.JwtBinding/)  

Package Manager  
`Install-Package HexMaster.Functions.JwtBinding`

.NET CLI  
`dotnet add package HexMaster.Functions.JwtBinding`

## Validating tokens
Let's say you run a SPA in which you want users to log in. You'll probably end up with a JWT token (or Access Token if you like). But now, you want to call a backend system, and pass that token so your backend can verify and identify the user. In conventional ASP.NET Core projects, you can add token validation to the request pipeline. In Azure Functions you can not. And this is where the binding kicks in. You need to, _manually_, validate the token and verify the caller's identity. And I thought is was a good idea to create a custom binding validating the token and -in the end- make sure who calls our functions.

## Configuration
The JwtBinding prefixed is used to configure the binding. The binding uses the Options Pattern to inject the *JwtBinding* configuration section as a *JwtBindingConfiguration* object. The values in the configuration can be overridden by the Binding Attribute arguments.

The Issuer value is mandatory. When no issuer was configured using the app config, or the attribute an exception will be raised and no validation will be done.

The following properties are available using the configuration:


* **Issuer** is the name of the issuer. The binding new assumes this is a valid URL to your token provider. This URL is also used to download signatures when no signature was provided through configuration.

* **Audience** is the name of your current audience (client). The token contains a list of 0 or more valid audiences. When configured, the token will be inspected and the configured value must be in the list of token's audiences. When no value was configured, audience validation will be skipped.

* **Signature** is the value of your token signature. This is only when you're using a symmetric signature which is not recommended. If you don't use a symmetric signature, the binding is going to try and download the signature from your token provider. At this time it is not (yet) possible to configure a public key for signature validation.

* **Scopes** is an optional list of (comma separated) scopes. When configured, all configured scopes must be present in the token. If no scopes were configured, scope validation will be skipped.

* **Roles** is an optional list of (comma separated) roles. When configured, all configured roles must be present in the token. If no roles were configured, role validation will be skipped.

* **AllowedIdentities** is an optional list of (comma separated) identities. When configured, the subject of the token is matched against one of the specified identities. If not found, an exception is thrown. If no identities were configured, identity validation will be skipped.

* **Header** is an optional value to change the name of the header used for Authorization. i.e. if you want to use `X-Authorization` instead of `Authorization`

* **DebugConfiguration** is a nested object allowing you to configure your environment for running in debug (development) mode.
    * **Enabled** is a switch to turn debug mode on or off. Set this value to `true` to enable debugging mode.  
    Note that it's far safer to remove the entire configuration block in acceptance/production environments.
    * **Subject** is the fixed *Subject* to return when running in debug mode.
    * **Name** is the fixed *Name* to return when running in debug mode

### Example
This example is an example which you can use to paste in your *local.settings.json* when running your azure functions localhost:

```json
    "JwtBinding:Issuer": "https://your-token-provider.com",
    "JwtBinding:Audience": "your-secret-api",
    "JwtBinding:Scopes": "data:read,data:write",
    "JwtBinding:Roles": "Role1,Role2",
    "JwtBinding:Header": "X-Authorization",
    "JwtBinding:AllowedIdentities": "Identity1,Identity2",
    "JwtBinding:DebugConfiguration:Enabled": true,
    "JwtBinding:DebugConfiguration:Subject": "TheSubject",
    "JwtBinding:DebugConfiguration:Name": "TheName"
```


## Usage
To use the token binding, simply add an `AuthorizedModel` parameter to your function with the `JwtBinding` attribute and you're good to go.

```csharp
// This example fully relies on your app config
[JwtBinding] AuthorizedModel auth
```

```csharp
// This example relies on your app config, but overwrites
// the scopes configuration with a new value
[JwtBinding(scopes: "data:delete")] AuthorizedModel auth
```

## About token validation
With JWT Tokens you really want to validate some extra stuff before just accepting the request. The binding uses the [JwtSecurityTokenHandler ](https://docs.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens.jwt.jwtsecuritytokenhandler?view=azure-dotnet&WT.mc_id=AZ-MVP-5003924) class under the hood, which takes care of some validations for us. Not all of them however.

### Issuer and Audiences
You may want to validate the Issuer and/or Audience of the token.

Issuer check means
- Check if the token is generated by the provider that I expect

Audience check
- Check if the called is allowed to access this API

If you use the JwtBinding attribute without parameters, neither one of these checks are done. However, you can pass the issuer and audience as a parameter to the `JwtBindingAttribute` like so:
```csharp
[JwtBinding("%JwtBinding:Issuer%", "%JwtBinding:Audience%")] AuthorizedModel auth
```

Note `%JwtBinding:Issuer%` is a reference to the configuration of your Azure Function. Make sure the configuration values exist. To run your function locally, add the following to the values section in your `local.settings.json`

```json
"JwtBinding:Audience": "your-audience",
"JwtBinding:Issuer": "https://your-token-provider.com"
```
