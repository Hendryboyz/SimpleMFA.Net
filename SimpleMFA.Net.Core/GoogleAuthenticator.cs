using SimpleMFA.Net.Core.Helpers;
using SimpleMFA.Net.Core.Providers;
using System;
using System.Security.Cryptography;
using System.Text;

namespace SimpleMFA.Net.Core
{
    public class GoogleAuthenticator : IOTPAuthenticator
    {
        private readonly ITimeProvider timeProvider;
        private readonly RandomNumberGenerator randomNumberGenerator;

        public GoogleAuthenticator() : this(null, null) { }

        public GoogleAuthenticator(ITimeProvider timeProvider) : this(timeProvider, null) { }

        public GoogleAuthenticator(ITimeProvider timeProvider, RandomNumberGenerator randomNumberGenerator)
        {
            if (timeProvider is null)
            {
                timeProvider = new DefaultTimeProvider();
            }
            this.timeProvider = timeProvider;
            if (randomNumberGenerator is null)
            {
                randomNumberGenerator = new RNGCryptoServiceProvider();
            }
            this.randomNumberGenerator = randomNumberGenerator;
        }

        public string CreateSecret(int length = 16)
        {
            if (length < 16 || 32 < length)
            {
                throw new ArgumentException();
            }

            byte[] byteIndex = GetRandomIndex(length);

            StringBuilder secretResult = new StringBuilder();
            for (int i = 0; i < length; i++)
            {
                int charIndex = byteIndex[i] & 31;
                secretResult.Append(EncodingHelper.BASE32_CHARACTERS[charIndex]);
            }
            return secretResult.ToString();
        }

        private byte[] GetRandomIndex(int length)
        {
            byte[] byteIndex = new byte[length];
            randomNumberGenerator.GetBytes(byteIndex);
            return byteIndex;
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
