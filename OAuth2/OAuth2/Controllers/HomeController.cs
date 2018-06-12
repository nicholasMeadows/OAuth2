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
            
            if (userPass.username == null || userPass.username.Length < 5 || userPass.username.Length > 15)
            {
                return View("~/Views/Home/Index.cshtml");
            }
            else if (userPass.password == null || userPass.password.Length < 5 || userPass.password.Length > 15)
            {
                return View("~/Views/Home/Index.cshtml");
            }

            return Redirect("http://www.github.com/nicholasMeadows");
           
        }
    }
}
