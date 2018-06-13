using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;
namespace OAuth2.Models
{
    public class ParamModel
    {
        [Required]
        public string client_id { get; set; }
        [Required]
        public string response_type { get; set; }
        [Required]
        public string redirect_uri { get; set; }
    }
}
