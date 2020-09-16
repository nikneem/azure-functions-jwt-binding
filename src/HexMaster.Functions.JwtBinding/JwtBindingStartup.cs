using HexMaster.Functions.JwtBinding;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Hosting;

[assembly: WebJobsStartup(typeof(JwtBindingStartup))]
namespace HexMaster.Functions.JwtBinding
{
        public class JwtBindingStartup : IWebJobsStartup
        {
            public void Configure(IWebJobsBuilder builder)
            {
                builder.AddJwtBindingExtension();
            }
        }
}
