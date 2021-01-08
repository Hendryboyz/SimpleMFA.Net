using System.Web;

namespace SimpleMFA.Net.Core.Helpers
{
    public static class SharedSecretHelper
    {
        public static string GenerateQRCodeURL(string secret, string username, string title = "")
        {
            string url = "https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=";
            string otpUrl = HttpUtility.UrlEncode($"otpauth://totp/{username}?secret={secret}");
            if (!string.IsNullOrEmpty(title))
            {
                otpUrl += HttpUtility.UrlEncode("&issuer=" + HttpUtility.UrlEncode(title));
            }
            return url + otpUrl;
        }
    }
}
