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
            FakeCurrentTimestamps();
            #endregion

            #region Action
            bool isValid = autenticator.VerifyCode(rawSecret, passcode);
            #endregion

            #region Assert
            isValid.Should().Be(expected);
            #endregion
        }

        private void FakeCurrentTimestamps()
        {
            DateTime current = DateTime.Parse("2020-12-30T07:42:36.0000000Z", null, DateTimeStyles.AdjustToUniversal);
            _timeProvider.GetNowTimeStamps().Returns(x =>
            {
                return (new DateTimeOffset(current)).ToUnixTimeSeconds();
            });
        }

        [Test]
        public void GetCode_GivenNothing_WhenNormalInvocation_ThenGenerateCodeWithCurrentTime()
        {
            #region Arrange
            string rawSecret = "7MN3WERAWLSX6S24";
            FakeCurrentTimestamps();
            #endregion

            #region Action
            autenticator.GetCode(rawSecret);
            #endregion

            #region Assert
            _timeProvider.Received().GetNowTimeStamps();
            #endregion
        }

        [Test]
        public void GetCode_GivenUnixEpoch_WhenNormalInvocation_ThenGenerateCodeWithGivenTime()
        {
            #region Arrange
            string rawSecret = "7MN3WERAWLSX6S24";
            #endregion

            #region Action
            autenticator.GetCode(rawSecret, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            #endregion

            #region Assert
            _timeProvider.DidNotReceive().GetNowTimeStamps();
            #endregion
        }

        [Test]
        public void GetCode_GivenNothing_WhenNormalInvocation_ThenVerifyGeneratedCode()
        {
            #region Arrange
            string rawSecret = "7MN3WERAWLSX6S24";
            string passcode = "133161";
            FakeCurrentTimestamps();
            #endregion

            #region Action
            string result = autenticator.GetCode(rawSecret);
            #endregion

            #region Assert
            result.Should().Be(passcode);
            #endregion
        }

        [Test]
        public void CreateSecret_GivenNothing_WhenNormalInvocation_ThenVerifyDefaultSecretLength()
        {
            #region Arrange
            #endregion

            #region Action
            #endregion

            #region Assert
            #endregion
        }
    }
}
