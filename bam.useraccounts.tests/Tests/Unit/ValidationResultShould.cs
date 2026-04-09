using Bam.DependencyInjection;
using Bam.Test;
using Bam.UserAccounts;

namespace Bam.UserAccounts.Tests.Unit;

[UnitTestMenu("ValidationResult Should", Selector = "vr")]
public class ValidationResultShould : UnitTestMenuContainer
{
    public ValidationResultShould(ServiceRegistry serviceRegistry) : base(serviceRegistry) { }

    [UnitTest]
    public void CreateValidResult()
    {
        When.A<ValidationResult>("creates a valid result",
            () => ValidationResult.Valid(),
            (result) => result)
        .TheTest
        .ShouldPass(because =>
        {
            because.TheObjectUnderTest
                .IsNotNull()
                .As<ValidationResult>("is valid", r => r!.IsValid)
                .As<ValidationResult>("has no errors", r => r!.Errors.Count == 0);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void CreateInvalidResultWithErrors()
    {
        When.A<ValidationResult>("creates an invalid result with errors",
            () => ValidationResult.Invalid("Error 1", "Error 2"),
            (result) => result)
        .TheTest
        .ShouldPass(because =>
        {
            because.TheObjectUnderTest
                .IsNotNull()
                .As<ValidationResult>("is not valid", r => !r!.IsValid)
                .As<ValidationResult>("has two errors", r => r!.Errors.Count == 2)
                .As<ValidationResult>("first error is correct", r => r!.Errors[0] == "Error 1")
                .As<ValidationResult>("second error is correct", r => r!.Errors[1] == "Error 2");
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void CreateInvalidResultWithSingleError()
    {
        When.A<ValidationResult>("creates an invalid result with one error",
            () => ValidationResult.Invalid("Something went wrong"),
            (result) => result)
        .TheTest
        .ShouldPass(because =>
        {
            because.TheObjectUnderTest
                .IsNotNull()
                .As<ValidationResult>("is not valid", r => !r!.IsValid)
                .As<ValidationResult>("has one error", r => r!.Errors.Count == 1)
                .As<ValidationResult>("error message is correct", r => r!.Errors[0] == "Something went wrong");
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}
