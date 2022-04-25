using System.ComponentModel.DataAnnotations;

namespace asp_net_core_identity_mvc.Models.AccountViewModels
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
