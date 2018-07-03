using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using OAuth2.Models;

namespace OAuth2.Controllers
{
    [Route("api/token")]
    [ApiController]
    [RequireHttps]
    [Consumes("application/x-www-form-urlencoded")]
    public class AccessTokenController : ControllerBase
    {
        [HttpPost]
        public ActionResult postGetToken([FromForm] AccessTokenParams param, [FromHeader] string Authorization)
        {
            /*
             string response = DatabaseContext.ValidateAccessParams(param, Authorization);

             if (response.Equals("Refresh"))
             {
                 //Generate new refresh token and update database

                 return Ok(DatabaseContext.RefreshToken(param.refresh_token, param));
             }
             else if (response.Equals("Access"))
             {
                 return Ok(DatabaseContext.GenerateAccessToken(param.client_id));
             }
             else if (!response.Equals("Valid"))
             {
                 return Ok(response);
             }
             return Ok(response);*/

            return Ok("/API/TOKEN ENDPOINT");
        }
    }
}