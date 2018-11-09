using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.Config
{
    [TestClass]
    public class UnknownPasswordApiAnalyzerConfigTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            return new DiagnosticAnalyzer[] { new TaintAnalyzerCSharp(), new TaintAnalyzerVisualBasic(),
                                              new UnknownPasswordApiAnalyzerCSharp(), new UnknownPasswordApiAnalyzerVisualBasic() };
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task AddPotentialPasswordFieldName()
        {
            var cSharpTest = @"
namespace VulnerableApp
{
    class HardCodedPassword
    {
        private string TestPassword;

        string GetTestPassword()
        {
            TestPassword =  ""t0ps3cr3t"";
            return TestPassword;
        }
    }
}
";

            var visualBasicTest = @"
Namespace VulnerableApp
    Class HardCodedPassword
        Private TestPassword As String

        Private Function TestCookie()
            TestPassword = ""t0ps3cr3t""
            Return TestPassword
        End Function
    End Class
End Namespace
";
    
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);

            var testConfig = @"
PasswordFields: [TestPassword]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            var expected = new DiagnosticResult
            {
                Id       = "SCS0015",
                Severity = DiagnosticSeverity.Warning
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);

            testConfig = @"
PasswordFields: [TeStPassWORD]
";

            optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
        }
    }
}
