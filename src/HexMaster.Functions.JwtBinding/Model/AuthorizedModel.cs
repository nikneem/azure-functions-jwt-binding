using System.Security.Claims;

namespace HexMaster.Functions.JwtBinding.Model
{
    public class AuthorizedModel
    {
        public string Subject { get; set; }
        public string Name { get; set; }
        public ClaimsPrincipal User { get; set; }
    }
}
