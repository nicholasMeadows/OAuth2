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
        //[RequireHttps]
        public IActionResult Index([FromQuery] string param)
        {
            return View();
        }
        //[RequireHttps]
        public IActionResult Login(UserPassModel userPass)
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
                    return Redirect("http://www.google.com?code=alsdkjflask;zx,cmnLKJHVLkjansdfdsa");
                }
                else
                {
                    TempData["err"] = "Invalid";
                    return View("~/Views/Home/Index.cshtml");
                }
            }
            TempData["err"] = "Invalid";
            return View("~/Views/Home/Index.cshtml");
        }
    }
}
