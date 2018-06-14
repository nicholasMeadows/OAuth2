using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Web;
namespace OAuth2.Models
{
    
    public class UserPassModel
    {
        [Required]
        [MinLength(5, ErrorMessage ="Username must be at least 5 characters long")]
        [MaxLength(15, ErrorMessage = "Username cannot be longer than 15 characters")]
        public string username { get; set; }

        [Required]
        [MinLength(5, ErrorMessage = "Password must be at least 5 characters long")]
        [MaxLength(15, ErrorMessage = "Password cannot be longer than 15 characters")]
        public string password { get; set; }
    }
}
