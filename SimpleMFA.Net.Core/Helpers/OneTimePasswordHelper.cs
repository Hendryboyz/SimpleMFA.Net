using System;
using System.Security.Cryptography;

namespace SimpleMFA.Net.Core.Helpers
{
    public static class OneTimePasswordHelper
    {
        public static double DEFAULT_TIMESTEP_UNIT = 30.0;

		public static string ComputeTimeBasedOneTimePassword(byte[] secretKey, long timesteps = 0)
        {
            if (timesteps == 0)
            {
                timesteps = CaculateTimesteps(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            }
            byte[] steps = BitConverter.GetBytes(timesteps);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(steps);
            }
            return ComputeHMACBasedOneTimePassword(secretKey, steps);
        }

        public static long CaculateTimesteps(long timestamps)
        {
            return (long)Math.Floor(timestamps / DEFAULT_TIMESTEP_UNIT);
        }

        public static string ComputeHMACBasedOneTimePassword(byte[] key, byte[] data, int digit = 6)
        {
            byte[] hmacSHA1 = ComputeHMACSHA1(key, data);
            uint binaryCode = ComputeDynamicTruncation(hmacSHA1);

            int codeLength = digit;
            int code = (int)(binaryCode % Math.Pow(10, codeLength));
            return code.ToString().PadLeft(digit, '0');
        }

        private static byte[] ComputeHMACSHA1(byte[] key, byte[] data)
        {
            using (var hmac = new HMACSHA1(key))
            {
                return hmac.ComputeHash(data);
            }
        }

        private static uint ComputeDynamicTruncation(byte[] hmacSHA1)
        {
            int offset = hmacSHA1[19] & 0xf;
            uint binaryCode = (uint)((hmacSHA1[offset] & 0x7f) << 24 |
            (hmacSHA1[offset + 1] & 0xff) << 16 |
            (hmacSHA1[offset + 2] & 0xff) << 8 |
            (hmacSHA1[offset + 3]));
            return binaryCode;
        }
    }
}