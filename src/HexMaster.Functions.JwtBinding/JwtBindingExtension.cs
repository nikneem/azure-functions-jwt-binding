using System;
using HexMaster.Functions.JwtBinding.Configuration;
using HexMaster.Functions.JwtBinding.TokenValidator;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Configuration;
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

            var serviceProvider = builder.Services.BuildServiceProvider();

            var configuration = serviceProvider.GetService<IConfiguration>();
            builder.Services.Configure<JwtBindingConfiguration>(configuration.GetSection(JwtBindingConfiguration.SectionName));
            
            builder.Services.AddSingleton<TokenValidatorService>();
            builder.AddExtension<JwtBinding>();
            return builder;
        }
    }
}