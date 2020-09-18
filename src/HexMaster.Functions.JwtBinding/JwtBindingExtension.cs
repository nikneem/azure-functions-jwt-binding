using System;
using Microsoft.Azure.WebJobs;

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

            builder.AddExtension<JwtBinding>();
            return builder;
        }
    }
}