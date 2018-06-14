using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using OAuth2.Models;
using System.Text.RegularExpressions;

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

                Regex regex = new Regex("(?![_.])(?!.*[_.]{2})[a-zA-Z0-9._]+(?<![_.])$");

                Match userMatch = regex.Match(userPass.username);
                Match passMatch = regex.Match(userPass.password);
               
                if (!userMatch.Success || !passMatch.Success)
                {
                    TempData["err"] = "Invalid 1";
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
                    TempData["err"] = "Invalid 2";
                    return View();
                }
            }
            ModelState.Remove("username");
            ModelState.Remove("password");
            return View();
        }

        public IActionResult Register(RegisterUserModel registerInfo)
        {
            
            if (registerInfo.username != null && registerInfo.password != null && registerInfo.confirmPassword != null)
            {
                Regex regex = new Regex("(?![_.])(?!.*[_.]{2})[a-zA-Z0-9._]+(?<![_.])$");

                Match userMatch = regex.Match(registerInfo.username);
                Match passMatch = regex.Match(registerInfo.password);
                Match confirmPassMatch = regex.Match(registerInfo.confirmPassword);

                if (!userMatch.Success || !passMatch.Success || !confirmPassMatch.Success)
                {
                    TempData["err"] = "Invalid info";
                    return View();
                }
                else {
                    DatabaseContext.RegisterUser(registerInfo);
                    return RedirectToAction("Index");
                }
                

            }

            ModelState.Remove("username");
            ModelState.Remove("password");
            ModelState.Remove("confirmPassword");
            registerInfo = new RegisterUserModel();
            return View(registerInfo);
        }
    }
}