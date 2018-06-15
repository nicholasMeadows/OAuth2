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
    //[RequireHttps]
    [Consumes("application/x-www-form-urlencoded")]
    public class AccessTokenController : ControllerBase
    {
        [HttpPost]
        public ActionResult postGetToken([FromForm] AccessTokenParams param, [FromHeader] string Authorization, [FromForm] string client_id, [FromForm] string client_secret)
        {
            
           if (Authorization != null)
            {
                Authorization = Authorization.Substring(6);
                byte[] data = Convert.FromBase64String(Authorization);
                string[] decodedAuth = Encoding.UTF8.GetString(data).Split(':');
                client_id = decodedAuth[0];
                client_secret = decodedAuth[1];

                //continue with validation
                string isValid = DatabaseContext.ValidateAccessParams(param, client_id, client_secret);
                if (isValid.Equals("Valid"))
                {
                    return Ok(DatabaseContext.GenerateAccessToken(client_id));
                }
                else {
                    return Ok(isValid);
                }

                
            }
            else if (client_id == null || client_secret == null)
            {
                return Ok("Missing Authorization header or client_id/client_secret in form");
            }

            //return Ok(param);
            return NotFound();
        }
    }
}