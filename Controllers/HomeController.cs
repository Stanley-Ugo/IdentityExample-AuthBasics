using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NETCore.MailKit.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityExample.Controllers
{
    //HomeController class
    public class HomeController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IEmailService _emailService;

        //HomeController class Constructor
        public HomeController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IEmailService emailService)
        {
            //Dependency Injection
            //object initialization

            //Injecting UserManager Object
            _userManager = userManager;

            //Injecting Signing Manager
            _signInManager = signInManager;

            //Injecting EmailService
            _emailService = emailService;
        }

        //Index Action method
        public IActionResult Index()
        {

            return View();
        }

        //Secret action method
        [Authorize]
        public IActionResult Secret()
        {
            return View();
        }

        //Login action method
        public IActionResult Login()
        {
            return View();
        }

        //Login post Method
        [HttpPost]
        public async Task<IActionResult> Login(string username, string password)
        {
            var user = await _userManager.FindByNameAsync(username);

            if(user != null)
            {
                //Sign the User in
                var signInResult = await _signInManager.PasswordSignInAsync(user, password, false, false);

                if (signInResult.Succeeded)
                {
                    return RedirectToAction("Index");
                }
            }

            return RedirectToAction("Index");
        }

        //Register method
        public IActionResult Register()
        {
            return View();
        }

        //Register POST Method
        [HttpPost]
        public async Task<IActionResult> Register(string username, string password)
        {
            var user = new IdentityUser
            {
                UserName = username,

            };

            var result = await _userManager.CreateAsync(user, password);

            if (result.Succeeded)
            {
                //generation of the email confirmation token

                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                var link = Url.Action(nameof(VerifyEmail), "Home", new { userId = user.Id, code }, Request.Scheme, Request.Host.ToString());

                await _emailService.SendAsync("test@test.com", "Email Verify", $"<a href=\"{link}\">Verify Email</a>", true);

                return RedirectToAction("EmailVerification");
            }
            return RedirectToAction("Index");
        }


        //Verify Email Method
        public async Task<IActionResult> VerifyEmail(string userId, string code)
        {
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null) return BadRequest();

            var result = await _userManager.ConfirmEmailAsync(user, code);

            if (result.Succeeded)
            {
                return View();
            }

            return BadRequest(); 
        }


        //EmailVerification Action method
        public IActionResult EmailVerification()
        {

            return View();
        }

        //Logout Action Method
        public async Task<IActionResult> LogOut()
        {

            await _signInManager.SignOutAsync();

            return RedirectToAction("Index");
        }
    }
}
