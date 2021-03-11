using System;

namespace ExternalLogin.Models
{
   public class ErrorViewModel
   {
      public string Message { get; set; }

      public string RequestId { get; set; }

      public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);
   }
}
