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
    public class WeakHashingAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new[] { new WeakHashingAnalyzer() };
        }

        [TestMethod]
        public async Task SHA256Create()
        {
            var cSharpTest = @"
using System.Security.Cryptography;

class Test
{
    static void foo()
    {
        var hash = SHA256.Create();
    }
}";

            var visualBasicTest = @"
Imports System.Security.Cryptography

Class Test
    Private Shared Sub foo()
        Dim hash As SHA256 = SHA256.Create()
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task NotSHA1Create()
        {
            var cSharpTest = @"
class SHA1
{
    public static void Create()
    {
    }
}

class WeakHashing
{
    static void generateWeakHashingSHA1()
    {
        SHA1.Create();
    }
}
";

            var visualBasicTest = @"
Class SHA1
    Public Shared Sub Create()
    End Sub
End Class

Class WeakHashing
    Private Shared Sub generateWeakHashingSHA1()
        SHA1.Create()
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [DataRow("MD5.Create()")]
        [DataRow("new MD5CryptoServiceProvider()")]
        [DataRow("new MD5Cng()")]
        [DataRow("SHA1.Create()")]
        [DataRow("new SHA1CryptoServiceProvider()")]
        [DataRow("new SHA1Managed()")]
        [DataRow("new SHA1Cng()")]
        [DataRow("CryptoConfig.CreateFromName(\"MD5\")")]
        [DataRow("CryptoConfig.CreateFromName(\"System.Security.Cryptography.MD5\")")]
        [DataRow("CryptoConfig.CreateFromName(\"System.Security.Cryptography.SHA1\")")]
        [DataRow("CryptoConfig.CreateFromName(\"SHA\")")]
        [DataRow("CryptoConfig.CreateFromName(\"SHA1\")")]
        [DataRow("CryptoConfig.CreateFromName(\"System.Security.Cryptography.HashAlgorithm\")")]
        [DataRow("HashAlgorithm.Create(\"MD5\")")]
        [DataRow("HashAlgorithm.Create(\"System.Security.Cryptography.MD5\")")]
        [DataRow("HashAlgorithm.Create(\"System.Security.Cryptography.SHA1\")")]
        [DataRow("HashAlgorithm.Create(\"SHA\")")]
        [DataRow("HashAlgorithm.Create(\"SHA1\")")]
        [DataRow("HashAlgorithm.Create(\"System.Security.Cryptography.HashAlgorithm\")")]
        [DataRow("HashAlgorithm.Create()")] // the default is sha1 https://msdn.microsoft.com/en-us/library/b0ky3sbb(v=vs.110).aspx
        [DataTestMethod]
        public async Task Create(string create)
        {
            var cSharpTest = $@"
using System.Security.Cryptography;

class WeakHashing
{{
    static void Foo()
    {{
        var hash = {create};
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Security.Cryptography

Class WeakHashing
    Private Shared Sub Foo()
        Dim hash As System.Object = {create}
    End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0006",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [TestMethod]
        public async Task CreateByNameSha256()
        {
            var cSharpTest = @"
using System.Security.Cryptography;

class WeakHashing
{
    static void Foo()
    {
        var sha = HashAlgorithm.Create(""System.Security.Cryptography.SHA256"");
    }
}
";

            var visualBasicTest = @"
Imports System.Security.Cryptography

Class WeakHashing
    Private Shared Sub Foo()
        Dim sha As HashAlgorithm = HashAlgorithm.Create(""System.Security.Cryptography.SHA256"")
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }
    }
}
