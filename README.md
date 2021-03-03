# Simple Multifactor for .NET
Leverage Time-Based/HMAC-Based One-Time Password function and algorithm to authenticate and customize multifactor features easily.

## Quick Start
* Dependency injection in Startup.cs
``` C#
public void ConfigureServices(IServiceCollection services)
{
  // some dependency...
  services.UseGoogleAuthenticator();
  // another dependency...
} 
```

* Get depenecy in constructor parameters
``` C#
public class MyService
{
  private readonly IOTPAuthenticator authenticator;

  public MyService(IOTPAuthenticator authenticator)
  {
    this.authenticator = authenticator;
  }

  public bool VerifyPasscode(string passcode)
  {
    string secretKey = RetrieveSecretKey();
    return authenticator.VerifyCode(secretKey, passcode);
  }

  private string RetrieveSecretKey()
  {
    // secret key should be persist in some safe storage
  }
}
```

## Supported Software-Based MFA Authenticator
* Google Authenticator([Google Play](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2&hl=zh_TW&gl=US)/[Apple Store](https://apps.apple.com/tw/app/google-authenticator/id388497605))

## Reference
* Time-Based One-Time Password: https://tools.ietf.org/html/rfc6238
* HMAC-Based One-Time Password: https://tools.ietf.org/html/rfc4226