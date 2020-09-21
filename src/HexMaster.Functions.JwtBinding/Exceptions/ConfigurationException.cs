using System;

namespace HexMaster.Functions.JwtBinding.Exceptions
{
    public sealed class ConfigurationException : Exception
    {
        public ConfigurationException(string message, Exception ex = null) : base(message, ex)
        {
        }
    }
}
