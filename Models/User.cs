
using Microsoft.AspNetCore.Identity;
namespace asp_net_core_identity_mvc.Models
{
    public class User : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }
}