using System;
using System.Net.Http.Headers;
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
                    Subject = configuration.DebugConfiguration?.Subject
                };
            }

            if (string.IsNullOrWhiteSpace(configuration.Issuer))
            {
                _logger.LogWarning("No valid issuer configured, cannot validate token");
                throw new ArgumentNullException(nameof(arg.Issuer), "The JwtBinding requires an issuer to validate JWT Tokens");
            }
            if (_http.HttpContext != null)
            {
                var authHeaderValue = _http.HttpContext.Request.Headers["Authorization"];
                var headerValue = AuthenticationHeaderValue.Parse(authHeaderValue);
                _logger.LogInformation("Now validating token");

                return _service.ValidateToken(headerValue, configuration);
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
            configuration.Signature = arg.Signature ?? configuration.Signature;
            configuration.AllowedIdentities = arg.AllowedIdentities ?? configuration.AllowedIdentities;
            return configuration;
        }
    }
}