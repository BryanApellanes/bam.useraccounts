namespace Bam.UserAccounts
{
    /// <summary>
    /// Not actually an exception
    /// </summary>
    public class NullException: Exception
    {
        public NullException() : base(string.Empty) { }
    }
}
