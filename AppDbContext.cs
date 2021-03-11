using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace ExternalLogin
{
   public class AppDbContext : IdentityDbContext
   {
      public AppDbContext(DbContextOptions options) : base(options)
      {

      }
   }
}
