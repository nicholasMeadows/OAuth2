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
        public IActionResult Index(UserPassModel userPass, [FromQuery] ParamModel param)
        {
            string validationResposne = DatabaseContext.ValidateParams(param);
            if (!validationResposne.Equals("Valid")) {
                return Ok(validationResposne);
            }

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
                }
                else if (DatabaseContext.ValidateUser(userPass.username, userPass.password))
                {
                    string request_token = DatabaseContext.GenerateToken();
                    return Redirect("/" + param.redirect_uri);
                    //return Redirect("http://www.google.com?code=" + request_token);
                }
                else
                {
                    TempData["err"] = "Invalid";
                    return View();
                }
            }

            return View();

            //return RedirectToAction("Login", param);
        }

        [RequireHttps]
        public IActionResult Login(UserPassModel userPass, [FromQuery] ParamModel param)
        {
            if (userPass.username != null)
            {
                return Ok(param.client_id);
            }

            return View("Index");
        }
            
        }
}





/*
            [RequireHttps]
            public IActionResult Login(UserPassModel userPass, [FromQuery] ParamModel param)
            {
                if (userPass.username != null && userPass.password != null)
                {
                    if (userPass.password.Contains('\'') || userPass.password.Contains('/') || userPass.password.Contains('"'))
                    {
                        TempData["err"] = "Invalid";
                        return View("~/Views/Home/Index.cshtml");
                    }
                    else if (userPass.username.Contains('\'') || userPass.username.Contains('/') || userPass.username.Contains('"'))
                    {
                        TempData["err"] = "Invalid";
                        return View("~/Views/Home/Index.cshtml");
                    }
                    else if (DatabaseContext.ValidateUser(userPass.username, userPass.password))
                    {
                        string request_token = DatabaseContext.GenerateToken();
                        return Redirect("/" + param.redirect_uri);
                        //return Redirect("http://www.google.com?code=" + request_token);
                    }
                    else
                    {
                        TempData["err"] = "Invalid";
                        return View("~/Views/Home/Index.cshtml");
                    }
                }
                TempData["err"] = "Invalid";
                return View("~/Views/Home/Index.cshtml");

            }*/
