using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace ExternalLogin.Controllers
{
   public class AccountController : Controller
   {
      private readonly SignInManager<IdentityUser> _signInManager;
      private readonly UserManager<IdentityUser> _userManager;

      public AccountController(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager)
      {
         _signInManager = signInManager;
         _userManager = userManager;
      }

      [HttpGet]
      public IActionResult Login()
      {
         return View();
      }

      [HttpPost]
      public IActionResult GetExternalLoginProvider(string provider)
      {
         var url = Url.Action("GetCallBack", "Account");
         var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, url);
         return Challenge(properties, provider);
      }

      public async Task<IActionResult> GetCallBack()
      {
         var info = await _signInManager.GetExternalLoginInfoAsync();
         if(info == null)
            return Redirect(Url.Action("Error", "Home",
               new { message = "You are not allowed to access this page until you try to login via google :)" }));

         var email = info.Principal.FindFirstValue(ClaimTypes.Email);
         var username = info.Principal.FindFirstValue(ClaimTypes.Name);

         var user = await _userManager.FindByEmailAsync(email);
         if(user == null) {
            var newUser = new IdentityUser {
               Email = email,
               UserName = username,
               EmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(newUser);
            if(result.Succeeded) {
               result = await _userManager.AddLoginAsync(newUser, info);

               if(result.Succeeded) {
                  await _signInManager.SignInAsync(newUser, false);

                  return Redirect(Url.Action("Index", "Home"));
               }
            }

            return Redirect(Url.Action("Error", "Home"));
         }
         else {
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, false);
            if(result.Succeeded)
               return Redirect(Url.Action("Index", "Home"));

            else if(result.IsLockedOut)
               return Redirect(Url.Action("Error", "Home",
                  new { message = "Due to many failure login attempts you are currently locked out :)" }));
            else if(result.RequiresTwoFactor)
               return Redirect(Url.Action("Error", "Home",
                  new { message = "How did you enabled two-factor while I haven't implemented this it yet! :|" }));
            else {
               var extResult = await _userManager.AddLoginAsync(user, info);

               if(extResult.Succeeded) {
                  await _signInManager.SignInAsync(user, false);

                  return Redirect(Url.Action("Index", "Home"));
               }
            }

            return Redirect(Url.Action("Error", "Home"));
         }
      }
   }
}
