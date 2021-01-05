using System;

namespace SimpleMFA.Net.Core.Providers
{
    public class DefaultTimeProvider : ITimeProvider
    {
        public long GetNowTimeStamps()
        {
            return DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        }
    }
}
