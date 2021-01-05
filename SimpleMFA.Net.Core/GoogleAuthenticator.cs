using SimpleMFA.Net.Core.Helpers;
using SimpleMFA.Net.Core.Providers;

namespace SimpleMFA.Net.Core
{
    public class GoogleAuthenticator : IOTPAuthenticator
    {
        private ITimeProvider timeProvider;

        public GoogleAuthenticator(ITimeProvider timeProvider)
        {
            this.timeProvider = timeProvider;
        }

        public bool Verify(string rawSecret, string passcode, int discrepancy = 1, long? currentUnixEpoch = null)
        {
            if (currentUnixEpoch == null)
            {
                currentUnixEpoch = timeProvider.GetNowTimeStamps();
            }

            long currentTimesteps = OneTimePasswordHelper.CaculateTimesteps((long)currentUnixEpoch);

            byte[] bytesSecretKey = EncodingHelper.Base32DecodeString(rawSecret);

            for (int step = -discrepancy; step <= discrepancy; ++step)
            {
                string calculateCode = OneTimePasswordHelper.ComputeTimeBasedOneTimePassword(bytesSecretKey, currentTimesteps + step);
                if (calculateCode.Equals(passcode))
                {
                    return true;
                }
            }
            return false;
        }
    }
}
