namespace SimpleMFA.Net.Core
{
    public interface IOTPAuthenticator
    {
        string GetCode(string base32Secret, long? unixEpoch = null);
        bool VerifyCode(string base32Secret, string passcode, int discrepancy = 1, long? unixEpoch = null);
    }
}
