using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.Config
{
    [TestClass]
    public class WeakPasswordValidatorPropertyAnalyzerConfigTests : ConfigurationTest
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[] { new WeakPasswordValidatorPropertyAnalyzerCSharp(), new TaintAnalyzerCSharp() };

            return new DiagnosticAnalyzer[] { new WeakPasswordValidatorPropertyAnalyzerVisualBasic(), new TaintAnalyzerVisualBasic(), };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(PasswordValidator).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestMethod]
        public async Task PasswordValidatorIncreaseRequiredLenght()
        {
            var cSharpTest = @"
using Microsoft.AspNet.Identity;

namespace WebApplicationSandbox.Controllers
{
    public class TestApp
    {
        public void TestMethod()
        {
            PasswordValidator pwdv = new PasswordValidator
            {
                RequiredLength = " + 8 + @",
                RequireNonLetterOrDigit = true,
                RequireDigit = true,
                RequireLowercase = true,
                RequireUppercase = true,
            };
        }
    }
}
";

            var visualBasicTest = @"
Imports Microsoft.AspNet.Identity

Namespace WebApplicationSandbox.Controllers
    Public Class TestApp
        Public Sub TestMethod()
            Dim pwdv As New PasswordValidator() With { _
                .RequiredLength = " + 8 + @", _
                .RequireNonLetterOrDigit = True, _
                .RequireDigit = True, _
                .RequireLowercase = True, _
                .RequireUppercase = True _
            }
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);

            var testConfig = @"
PasswordValidatorRequiredLength: 9
";

            var optionsWithProjectConfig = CreateAnalyzersOptionsWithConfig(testConfig);
            var expected = new DiagnosticResult
            {
                Id       = "SCS0032",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task PasswordValidatorDecreaseRequiredLenght()
        {
            var cSharpTest = @"
using Microsoft.AspNet.Identity;

namespace WebApplicationSandbox.Controllers
{
    public class TestApp
    {
        public void TestMethod()
        {
            PasswordValidator pwdv = new PasswordValidator
            {
                RequiredLength = " + 7 + @",
                RequireNonLetterOrDigit = true,
                RequireDigit = true,
                RequireLowercase = true,
                RequireUppercase = true,
            };
        }
    }
}
";

            var visualBasicTest = @"
Imports Microsoft.AspNet.Identity

Namespace WebApplicationSandbox.Controllers
    Public Class TestApp
        Public Sub TestMethod()
            Dim pwdv As New PasswordValidator() With { _
                .RequiredLength = " + 7 + @", _
                .RequireNonLetterOrDigit = True, _
                .RequireDigit = True, _
                .RequireLowercase = True, _
                .RequireUppercase = True _
            }
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0032",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);

            var testConfig = @"
PasswordValidatorRequiredLength: 7
";

            var optionsWithProjectConfig = CreateAnalyzersOptionsWithConfig(testConfig);

            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task PasswordValidatorIncreaseNumberOfRequiredProperties()
        {
            var cSharpTest = @"
using Microsoft.AspNet.Identity;

namespace WebApplicationSandbox.Controllers
{
    public class TestApp
    {
        public void TestMethod()
        {
            PasswordValidator pwdv = new PasswordValidator
            {
                RequiredLength = " + 8 + @",
                RequireNonLetterOrDigit = true,
                RequireDigit = true,
            };
        }
    }
}
";

            var visualBasicTest = @"
Imports Microsoft.AspNet.Identity

Namespace WebApplicationSandbox.Controllers
    Public Class TestApp
        Public Sub TestMethod()
            Dim pwdv As New PasswordValidator() With { _
                .RequiredLength = " + 8 + @", _
                .RequireNonLetterOrDigit = True, _
                .RequireDigit = True _
            }
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);

            var testConfig = @"
MinimumPasswordValidatorProperties: 4
";

            var optionsWithProjectConfig = CreateAnalyzersOptionsWithConfig(testConfig);
            var expected = new DiagnosticResult
            {
                Id       = "SCS0033",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task PasswordValidatorDecreaseNumberOfRequiredProperties()
        {
            var cSharpTest = @"
using Microsoft.AspNet.Identity;

namespace WebApplicationSandbox.Controllers
{
    public class TestApp
    {
        public void TestMethod()
        {
            PasswordValidator pwdv = new PasswordValidator
            {
                RequiredLength = " + 8 + @",
                RequireNonLetterOrDigit = true,
            };
        }
    }
}
";

            var visualBasicTest = @"
Imports Microsoft.AspNet.Identity

Namespace WebApplicationSandbox.Controllers
    Public Class TestApp
        Public Sub TestMethod()
            Dim pwdv As New PasswordValidator() With { _
                .RequiredLength = " + 8 + @", _
                .RequireNonLetterOrDigit = True _
            }
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0033",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);

            var testConfig = @"
MinimumPasswordValidatorProperties: 2
";

            var optionsWithProjectConfig = CreateAnalyzersOptionsWithConfig(testConfig);

            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [DataTestMethod]
        [DataRow("RequireNonLetterOrDigit", 1)]
        [DataRow("RequireDigit", 1)]
        [DataRow("RequireLowercase", 1)]
        [DataRow("RequireUppercase", 1)]
        [DataRow("RequireUppercase, RequireDigit", 2)]
        public async Task PasswordValidatorRequireSpecificProperty(string properties, int propertiesCount)
        {
            var cSharpTest = @"
using Microsoft.AspNet.Identity;

namespace WebApplicationSandbox.Controllers
{
    public class TestApp
    {
        public void TestMethod()
        {
            PasswordValidator pwdv = new PasswordValidator
            {
                RequiredLength = " + 8 + @"
            };
        }
    }
}
";

            var visualBasicTest = @"
Imports Microsoft.AspNet.Identity

Namespace WebApplicationSandbox.Controllers
    Public Class TestApp
        Public Sub TestMethod()
            Dim pwdv As New PasswordValidator() With { _
                .RequiredLength = " + 8 + @"
            }
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0033",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);

            var testConfig = $@"
MinimumPasswordValidatorProperties: 0
PasswordValidatorRequiredProperties: [{properties}]
";

            var optionsWithProjectConfig = CreateAnalyzersOptionsWithConfig(testConfig);
            expected = new DiagnosticResult
            {
                Id       = "SCS0034",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, Enumerable.Repeat(expected, propertiesCount).ToArray(), optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Enumerable.Repeat(expected, propertiesCount).ToArray(), optionsWithProjectConfig).ConfigureAwait(false);
        }
    }
}
