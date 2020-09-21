using System;
using HexMaster.Functions.JwtBinding.TokenValidator;
using HexMaster.Functions.JwtBinding.TokenValidator.Contracts;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.DependencyInjection;

namespace HexMaster.Functions.JwtBinding
{
    public static class JwtBindingExtension
    {
        public static IWebJobsBuilder AddJwtBindingExtension(this IWebJobsBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            builder.Services.AddScoped<ITokenValidatorService, TokenValidatorService>();
            builder.AddExtension<JwtBinding>();
            return builder;
        }
    }
}