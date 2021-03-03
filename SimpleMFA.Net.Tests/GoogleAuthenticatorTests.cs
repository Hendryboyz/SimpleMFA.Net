using FluentAssertions;
using NSubstitute;
using NUnit.Framework;
using SimpleMFA.Net.Core;
using SimpleMFA.Net.Core.Helpers;
using SimpleMFA.Net.Core.Providers;
using System;
using System.Globalization;
using System.Security.Cryptography;

namespace SimpleMFA.Net.Tests
{
    public class GoogleAuthenticatorTests
    {
        private ITimeProvider _timeProvider;
        private RandomNumberGenerator _randomNumberGenerator;

        private IOTPAuthenticator autenticator;

        [SetUp]
        public void SetUp()
        {
            FakeDependencies();
            autenticator = new GoogleAuthenticator(_timeProvider, _randomNumberGenerator);
        }

        private void FakeDependencies()
        {
            _timeProvider = Substitute.For<ITimeProvider>();
            _randomNumberGenerator = Substitute.For<RandomNumberGenerator>();
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

        [TestCase(15)]
        [TestCase(33)]
        public void CreateSecret_GivenLength_WhenInvalidLength_ThenThrowArgumentException(int secretLength)
        {
            #region Action
            Exception ex = Assert.Catch(() => autenticator.CreateSecret(secretLength));
            #endregion

            #region Assert
            ex.Should().BeOfType<ArgumentException>();
            #endregion
        }

        [TestCase(new byte[] { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF }, "ABCDEFGHIJKLMNOP")]
        [TestCase(new byte[] { 0xF, 0xE, 0xD, 0xC, 0xB, 0xA, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0 }, "PONMLKJIHGFEDCBA")]
        public void CreateSecret_GivenNothing_WhenNormalInvocation_ThenGiven16LengthSecret(
            byte[] randomResult, string expected)
        {
            #region Arrange
            _randomNumberGenerator.GetBytes(Arg.Do<byte[]>(x => 
            {
                for (int i = 0; i < 16; i++)
                {
                    x[i] = randomResult[i];
                }
            }));
            #endregion

            #region Action
            string resultSecret = autenticator.CreateSecret();
            #endregion

            #region Assert
            resultSecret.Length.Should().Be(16);
            resultSecret.Should().Be(expected);
            Console.WriteLine(SharedSecretHelper.GenerateQRCodeURL(resultSecret, "henry_chou", "trendmicro.com"));
            #endregion
        }
    }
}
