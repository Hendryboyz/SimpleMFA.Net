using FluentAssertions;
using NUnit.Framework;
using SimpleMFA.Net.Core.Helpers;

namespace SimpleMFA.Net.Tests
{
    public class EncodingHelperTests
    {
        [Test]
        public void Base32DecodingString_GivenBase32String_WhenNormal_ThenCheckCorrectBytesConut()
        {
            string base32String = "7MN3WERAWLSX6S24";

            byte[] result = EncodingHelper.Base32DecodeString(base32String);

            result.Should().HaveCount(10);
        }
    }
}