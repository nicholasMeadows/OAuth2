﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuth2.Models
{
    public class AccessTokenModel
    {
        public string access_token { get; set; }
        public string token_type { get; set; }
        public int expires_id { get; set; }
        public string refresh_token { get; set; }
        public string scope { get; set; }
    }
}
