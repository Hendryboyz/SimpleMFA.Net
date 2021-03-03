using Microsoft.Extensions.DependencyInjection;
using SimpleMFA.Net.Core.Providers;

namespace SimpleMFA.Net.Core.Extensions
{
    public static class AuthenticatorExtensions
    {
        public static IServiceCollection UseGoogleAuthenticator(this IServiceCollection services)
        {
            services.AddSingleton<IOTPAuthenticator, GoogleAuthenticator>();
            services.AddSingleton<ITimeProvider, DefaultTimeProvider>(); 
            return services;
        }
    }
}
