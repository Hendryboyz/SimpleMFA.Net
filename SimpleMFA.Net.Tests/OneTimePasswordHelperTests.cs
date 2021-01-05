using FluentAssertions;
using NUnit.Framework;
using SimpleMFA.Net.Core.Helpers;
using System;
using System.Globalization;
using System.Linq;
using System.Text;

namespace SimpleMFA.Net.Tests
{
    public class OneTimePasswordHelperTests
    {
        [TestCase(59, 1)]
        [TestCase(60, 2)]
        public void CaculateTimesteps_GivenEpochUnixTime_WhenNormal_ThenCheckTimeSteps(long timestamps, long result)
        {
            long timeSteps = OneTimePasswordHelper.CaculateTimesteps(timestamps);

            timeSteps.Should().Be(result);
        }

        [Test]
        public void ComputeTimeBasedOneTimePassword_GivenKeyAndTimeSteps_WhenNormal_ThenVerifyOTP()
        {
            DateTime current = DateTime.Parse("2020-12-30T07:42:36.0000000Z", null, DateTimeStyles.AdjustToUniversal);
            long timeSteps = OneTimePasswordHelper.CaculateTimesteps((new DateTimeOffset(current)).ToUnixTimeSeconds());
            byte[] key = EncodingHelper.Base32DecodeString("7MN3WERAWLSX6S24");
            
            string result = OneTimePasswordHelper.ComputeTimeBasedOneTimePassword(key, timeSteps);

            result.Should().Be("133161");
        }

        [TestCase(0, "755224")]
        [TestCase(1, "287082")]
        [TestCase(2, "359152")]
        [TestCase(3, "969429")]
        [TestCase(4, "338314")]
        [TestCase(5, "254676")]
        [TestCase(6, "287922")]
        [TestCase(7, "162583")]
        [TestCase(8, "399871")]
        [TestCase(9, "520489")]
        public void ComputeHMACBasedOneTimePassword_Given0To9_WhenNormalThenVerifyHashBasedOTP(long count, string OTP)
        {
            byte[] key = Encoding.ASCII.GetBytes("12345678901234567890");
            byte[] data = BitConverter.GetBytes(count);
            if (BitConverter.IsLittleEndian)
            {
                data = data.Reverse().ToArray();
            }
            var result = OneTimePasswordHelper.ComputeHMACBasedOneTimePassword(key, data);
            result.Should().Be(OTP);
        }
    }
}
