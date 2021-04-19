using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using HexMaster.Functions.JwtBinding.Configuration;
using HexMaster.Functions.JwtBinding.Exceptions;
using HexMaster.Functions.JwtBinding.Model;
using HexMaster.Functions.JwtBinding.TokenValidator;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.WebJobs.Description;
using Microsoft.Azure.WebJobs.Host.Config;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace HexMaster.Functions.JwtBinding
{
    [Extension("JwtBinding", Constants.ConfigurationSectionName)]
    public class JwtBinding : IExtensionConfigProvider
    {
        private readonly TokenValidatorService _service;
        private readonly IOptions<JwtBindingConfiguration> _configuration;
        private readonly IHttpContextAccessor _http;
        private readonly ILogger<JwtBinding> _logger;

        public JwtBinding(
            TokenValidatorService service,
            IOptions<JwtBindingConfiguration> configuration,
            IHttpContextAccessor http, 
            ILogger<JwtBinding> logger)
        {
            _service = service;
            _configuration = configuration;
            _http = http;
            _logger = logger;
        }

        public void Initialize(ExtensionConfigContext context)
        {
            var rule = context.AddBindingRule<JwtBindingAttribute>();
            rule.BindToInput(BuildItemFromAttribute);
        }

        private AuthorizedModel BuildItemFromAttribute(JwtBindingAttribute arg)
        {
            var configuration = GetFunctionConfiguration(arg);

            if ((configuration.DebugConfiguration?.Enabled).GetValueOrDefault())
            {
                _logger.LogWarning("## WARNING ## - The JWT Validation Binding is running in DEBUG mode and currently returns fixed values!");
                return new AuthorizedModel
                {
                    Name = configuration.DebugConfiguration?.Name,
                    Subject = configuration.DebugConfiguration?.Subject,
                    User = GetUserFromDebugConfiguration(configuration)
                };
            }

            if (string.IsNullOrWhiteSpace(configuration.Issuer))
            {
                _logger.LogWarning("No valid issuer configured, cannot validate token");
                throw new ArgumentNullException(nameof(arg.Issuer), "The JwtBinding requires an issuer to validate JWT Tokens");
            }

            if (_http.HttpContext != null)
            {
                var authHeaderValue = _http.HttpContext.Request.Headers[configuration.Header];

                if (AuthenticationHeaderValue.TryParse(authHeaderValue, out AuthenticationHeaderValue headerValue))
                {
                    _logger.LogInformation("Now validating token");

                    return _service.ValidateToken(headerValue, configuration);
                }

                throw new AuthorizationFailedException(
                    new Exception("Authorization header is missing, add a bearer token to the header of your HTTP request")
                    );
            }

            throw new AuthorizationOperationException();
        }

        private JwtBindingConfiguration GetFunctionConfiguration(JwtBindingAttribute arg)
        {
            var configuration = _configuration.Value ?? new JwtBindingConfiguration();
            configuration.Issuer = arg.Issuer ?? configuration.Issuer;
            configuration.Audience = arg.Audience ?? configuration.Audience;
            configuration.Scopes = arg.Scopes ?? configuration.Scopes;
            configuration.Roles = arg.Roles ?? configuration.Roles;
            configuration.SymmetricSecuritySigningKey = arg.Signature ?? configuration.SymmetricSecuritySigningKey;
            configuration.X509CertificateSigningKey = arg.X509CertificateSigningKey ?? configuration.X509CertificateSigningKey;
            configuration.AllowedIdentities = arg.AllowedIdentities ?? configuration.AllowedIdentities;
            configuration.Header = arg.Header ?? configuration.Header ?? Constants.DefaultAuthorizationHeader;
            return configuration;
        }

        private ClaimsPrincipal GetUserFromDebugConfiguration(JwtBindingConfiguration configuration)
        {
            var subject = configuration.DebugConfiguration?.Subject;
            var name = configuration.DebugConfiguration?.Name;
            var claimsIdentity = new ClaimsIdentity();

            if (!string.IsNullOrEmpty(subject)) {
                claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.NameId, subject));
            }

            if (!string.IsNullOrEmpty(name)) {
                claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.GivenName, name));
            }

            return new ClaimsPrincipal(claimsIdentity);
        }
    }
}