using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;

namespace OAuth2.Models
{
    public class AccessTokenParams
    {
        //[Required(ErrorMessage ="Missing grant_type")]
        public string grant_type { get; set; }
        public string code { get; set; }
        public string redirect_uri { get; set; }
        public string client_id { get; set; }
        public string client_secret { get; set; }
        public string refresh_token {get; set;}
    }
}
