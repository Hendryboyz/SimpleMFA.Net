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

        public string GetCode(string base32Secret, long? unixEpoch = null)
        {
            unixEpoch = ProvideUnixEpoch(unixEpoch);
            long currentTimesteps = OneTimePasswordHelper.CaculateTimesteps((long)unixEpoch);
            byte[] bytesSecretKey = EncodingHelper.Base32DecodeString(base32Secret);

            return OneTimePasswordHelper.ComputeTimeBasedOneTimePassword(bytesSecretKey, currentTimesteps);
        }

        public bool VerifyCode(string base32Secret, string passcode, int discrepancy = 1, long? unixEpoch = null)
        {
            unixEpoch = ProvideUnixEpoch(unixEpoch);
            long currentTimesteps = OneTimePasswordHelper.CaculateTimesteps((long)unixEpoch);
            byte[] bytesSecretKey = EncodingHelper.Base32DecodeString(base32Secret);

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

        private long? ProvideUnixEpoch(long? currentUnixEpoch)
        {
            if (currentUnixEpoch == null)
            {
                currentUnixEpoch = timeProvider.GetNowTimeStamps();
            }
            
            return currentUnixEpoch;
        }
    }
}
