using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test
{
    [TestClass]
    public class WeakRandomAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[] { new WeakRandomAnalyzerCSharp() };
            else
                return new DiagnosticAnalyzer[] { new WeakRandomAnalyzerVisualBasic() };
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task RandomFalsePositive()
        {
            var cSharpTest = @"
using System;
using System.Security.Cryptography;

public class WeakRandom
{
    static String generateSecureToken()
    {

        RandomNumberGenerator rnd = RandomNumberGenerator.Create();

        byte[] buffer = new byte[16];
        rnd.GetBytes(buffer);
        return BitConverter.ToString(buffer);
    }
}
";

            var visualBasicTest = @"
Imports System
Imports System.Security.Cryptography

Public Class WeakRandom
    Private Shared Function generateSecureToken() As String
        Dim rnd As RandomNumberGenerator = RandomNumberGenerator.Create()
        Dim buffer As Byte() = New Byte(15) {}
        rnd.GetBytes(buffer)
        Return BitConverter.ToString(buffer)
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }


        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("Rndm = System.Random",    "Rndm")]
        [DataRow("System",                  "Random")]
        public async Task WeakRandomNumberGeneration(string alias, string name)
        {
            var cSharpTest = $@"
using {alias};

public class WeakRandom
{{
    static string generateWeakToken()
    {{
        {name} rnd = new {name}();
        return rnd.Next().ToString(); 
    }}
}}
";

            var visualBasicTest = $@"
Imports {alias}

Public Class WeakRandom
    Private Shared Function generateWeakToken() As String
        Dim rnd As New {name}()
        Return rnd.Next().ToString()
    End Function
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0005",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation(9)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation(7)).ConfigureAwait(false);
        }
    }
}
