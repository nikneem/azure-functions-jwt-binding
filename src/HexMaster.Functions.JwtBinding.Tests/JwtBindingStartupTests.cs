using HexMaster.Functions.JwtBinding.TokenValidator;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host.Config;
using Microsoft.Azure.WebJobs.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace HexMaster.Functions.JwtBinding.Tests
{
    public sealed class JwtBindingStartupTests
    {
        private class Fixture
        {
            public IHost GetHost()
            {
                return new HostBuilder()
                    .ConfigureWebJobs(builder => builder.UseWebJobsStartup<JwtBindingStartup>()
                    .Services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>())
                    .Build();
            }

            public List<Type> GetWebJobsStartupTypes()
            {
                return typeof(JwtBindingStartup).Assembly.GetCustomAttributes<WebJobsStartupAttribute>()
                    .Select(startupAttribute => startupAttribute.WebJobsStartupType).ToList();
            }
        }

        private readonly Fixture _fixture = new Fixture();


        [Test]
        public void JwtBindingStartup_RegistersExpectedServicesIntoDI()
        {
            var host = _fixture.GetHost();

            Assert.IsInstanceOf<JwtBinding>(host.Services.GetService<IExtensionConfigProvider>());
            Assert.IsInstanceOf<TokenValidatorService>(host.Services.GetService<TokenValidatorService>());
        }

        [Test]
        public void JwtBindingStartup_ShouldHaveOnlyOneRegisteredWebjobStartup()
        {
            var webJosStartup = _fixture.GetWebJobsStartupTypes();

            Assert.AreEqual(1, webJosStartup.Count);
            Assert.AreEqual(typeof(JwtBindingStartup), webJosStartup.First());
        }
    }
}
