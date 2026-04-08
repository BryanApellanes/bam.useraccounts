namespace Bam.UserAccounts;

public class ValidationResult
{
    public bool IsValid { get; set; }
    public List<string> Errors { get; set; } = new();

    public static ValidationResult Valid() => new() { IsValid = true };

    public static ValidationResult Invalid(params string[] errors) => new()
    {
        IsValid = false,
        Errors = new List<string>(errors)
    };
}
