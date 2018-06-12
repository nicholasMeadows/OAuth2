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

        public IActionResult Login(UserPassModel userPass)
        {
            if (userPass.username != null && userPass != null)
            {
                if (userPass.password.Contains('\'') || userPass.password.Contains('/') || userPass.password.Contains('"'))
                {
                    TempData["err"] = "Invalid";
                    return View("~/Views/Home/Index.cshtml");
                }

                if (userPass.username.Contains('\'') || userPass.username.Contains('/') || userPass.username.Contains('"'))
                {
                    TempData["err"] = "Invalid";
                    return View("~/Views/Home/Index.cshtml");
                }
            }
            else
            {
                TempData["err"] = "Invalid";
                return View("~/Views/Home/Index.cshtml");
            }

            return Redirect("lskdjf");
        }
    }
}
