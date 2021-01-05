namespace SimpleMFA.Net.Core
{
    public interface IOTPAuthenticator
    {
        bool Verify(string rawSecret, string passcode, int discrepancy = 1, long? currentUnixEpoch = null);
    }
}
