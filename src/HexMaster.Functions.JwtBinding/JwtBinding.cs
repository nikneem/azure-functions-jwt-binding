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
            var configuration = _configuration.Value;

            if (string.IsNullOrWhiteSpace(arg.Issuer))
            {
                _logger.LogWarning("No valid issuer configured, cannot validate token");
                throw new ArgumentNullException(nameof(arg.Issuer), "The JwtBinding requires an issuer to validate JWT Tokens");
            }
            if (_http.HttpContext != null)
            {
                var authHeaderValue = _http.HttpContext.Request.Headers["Authorization"];
                var headerValue = AuthenticationHeaderValue.Parse(authHeaderValue);
                _logger.LogWarning("Now validating token");
                return _service.ValidateToken(
                    headerValue,
                    arg.Issuer,
                    arg.Audience,
                    arg.Signature,
                    arg.Scopes);
            }
            throw new AuthorizationOperationException();
        }
    }
}