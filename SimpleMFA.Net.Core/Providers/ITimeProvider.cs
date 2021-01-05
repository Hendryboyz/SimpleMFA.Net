namespace SimpleMFA.Net.Core.Providers
{
    public interface ITimeProvider
    {
        long GetNowTimeStamps();
    }
}
