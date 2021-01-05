using FluentAssertions;
using NSubstitute;
using NUnit.Framework;
using SimpleMFA.Net.Core;
using SimpleMFA.Net.Core.Providers;
using System;
using System.Globalization;

namespace SimpleMFA.Net.Tests
{
    public class GoogleAuthenticatorTests
    {
        private ITimeProvider _timeProvider;
        private IOTPAuthenticator autenticator;

        [SetUp]
        public void SetUp()
        {
            FakeDependencies();
            autenticator = new GoogleAuthenticator(_timeProvider);
        }

        private void FakeDependencies()
        {
            _timeProvider = Substitute.For<ITimeProvider>();
        }

        [TestCase("133161", true)]
        [TestCase("123456", false)]
        public void Verify_GivenTrendTwoFactorSecretAndPasscode_WhenNormalInvocation_ThenReturnValidStatus(string passcode, bool expected)
        {
            #region Arrange
            string rawSecret = "7MN3WERAWLSX6S24";
            DateTime current = DateTime.Parse("2020-12-30T07:42:36.0000000Z", null, DateTimeStyles.AdjustToUniversal);
            _timeProvider.GetNowTimeStamps().Returns(x =>
            {
                return (new DateTimeOffset(current)).ToUnixTimeSeconds();
            });
            #endregion

            #region Action
            bool isValid = autenticator.Verify(rawSecret, passcode);
            #endregion

            #region Assert
            isValid.Should().Be(expected);
            #endregion
        }
    }
}
