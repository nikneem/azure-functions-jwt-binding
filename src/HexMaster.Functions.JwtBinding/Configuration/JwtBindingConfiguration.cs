namespace HexMaster.Functions.JwtBinding.Configuration
{
    public sealed class JwtBindingConfiguration
    {

        public const string SectionName = Constants.ConfigurationSectionName;

        public string Issuer { get; set; }
        public string IssuerPattern { get; set; }
        public string Audience { get; set; }
        public string Signature { get; set; }
        public string Scopes { get; set; }
        public string Roles { get; set; }
        public string AllowedIdentities { get; set; }

        public JwtBindingDebugConfiguration DebugConfiguration { get; set; }



    }
}
