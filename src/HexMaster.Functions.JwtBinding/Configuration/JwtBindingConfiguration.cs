using System;
using System.Collections.Generic;
using System.Text;

namespace HexMaster.Functions.JwtBinding.Configuration
{
    public sealed class JwtBindingConfiguration
    {

        public string Issuer { get; set; }
        public string Audience { get; set; }

        public string Signature { get; set; }
        public string Scopes { get; set; }
        public string Roles { get; set; }

        

    }
}
