using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using OAuth2.Models;

namespace OAuth2.Controllers
{
    public class HomeController : Controller
    {
        [RequireHttps]
        [Route("/authorize")]
        public IActionResult Index(UserPassModel userPass, [FromQuery] ParamModel param)
        {
            //Validate the parameters passed in the url
            string validationResposne = DatabaseContext.ValidateParams(param);
            if (!validationResposne.Equals("Valid")) {
                return Ok(validationResposne);
            }

            //Server side password validation
            if (userPass.username != null && userPass.password != null)
            {
                if (userPass.password.Contains('\'') || userPass.password.Contains('/') || userPass.password.Contains('"'))
                {
                    TempData["err"] = "Invalid";
                    return View();
                }
                else if (userPass.username.Contains('\'') || userPass.username.Contains('/') || userPass.username.Contains('"'))
                {
                    TempData["err"] = "Invalid";
                    return View();
                }//Validates username and password 
                else if (DatabaseContext.ValidateUser(userPass.username, userPass.password))
                {
                    //Generate request token
                    string request_token = DatabaseContext.GenerateToken();
                    //redirects user to redirect_url with request code
                    return Redirect(param.redirect_uri+"?code=" + request_token);
                }
                else
                {
                    TempData["err"] = "Invalid";
                    return View();
                }
            }
            return View();
        }               
    }
}