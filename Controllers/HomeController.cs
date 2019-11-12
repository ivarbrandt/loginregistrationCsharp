using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using loginandreg.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;

namespace loginandreg.Controllers
{
    public class HomeController : Controller
    {
        private MyContext dbContext;
        public HomeController(MyContext context)
        {
            dbContext = context;
        }
        [HttpGet("")]
        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Register(User user)
        {
            if(ModelState.IsValid)
            {
                if(dbContext.Users.Any(i => i.Email == user.Email))
                {
                    ModelState.AddModelError("Email", "Email already exists");
                    return View("Index");
                }
                PasswordHasher<User> Hasher = new PasswordHasher<User>();
                user.Password = Hasher.HashPassword(user, user.Password);
                dbContext.Add(user);
                dbContext.SaveChanges();
                HttpContext.Session.SetInt32("UserID", user.UserID);
                return RedirectToAction("SuccessPage");
            }
            return View("Index");
        }

        [HttpGet("login")]
        public IActionResult LoginPage()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Login(LoggedUser loggeduser)
        {
            if(ModelState.IsValid)
            {
                User userdb = dbContext.Users.FirstOrDefault(e => e.Email == loggeduser.LoginEmail);
                if(userdb == null)
                {
                    ModelState.AddModelError("LoginEmail", "Invalid Email");
                    return View("LoginPage");
                }
                var hasher = new PasswordHasher<LoggedUser>();
                var result = hasher.VerifyHashedPassword(loggeduser, userdb.Password, loggeduser.LoginPassword);
                if(result == 0)
                {
                    ModelState.AddModelError("LoginPassword", "Invalid Password");
                    return View ("LoginPage");
                }
                HttpContext.Session.SetInt32("UserID", userdb.UserID);
                return RedirectToAction("SuccessPage");
        }
        return View("LoginPage");
        }

        [HttpGet("success")]
        public IActionResult SuccessPage()
        {
            if(HttpContext.Session.GetInt32("UserID") != null)
            {
                return View();
            }
            return View("Index");
        }

        [HttpPost]
        public IActionResult Logout()
        {
            HttpContext.Session.Clear();
            return RedirectToAction("Index");
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
