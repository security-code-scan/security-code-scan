using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test
{
    [TestClass]
    public class WeakHashingAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[] { new WeakHashingAnalyzerCSharp() };
            else
                return new DiagnosticAnalyzer[] { new WeakHashingAnalyzerVisualBasic() };
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task NotSHA1Create()
        {
            var cSharpTest = @"
public class SHA1
{
    public static void Create()
    {
    }
}

public class WeakHashing
{
    static void generateWeakHashingSHA1()
    {
        SHA1.Create();
    }
}
";

            var visualBasicTest = @"
Public Class SHA1
    Public Shared Sub Create()
    End Sub
End Class

Public Class WeakHashing
    Private Shared Sub generateWeakHashingSHA1()
        SHA1.Create()
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataRow("MD5",  "MD5.Create")]
        [DataRow("SHA1", "SHA1.Create")]
        [DataTestMethod]
        public async Task Delegate(string type, string create)
        {
            var cSharpTest = $@"
using System.Security.Cryptography;

public class WeakHashing
{{
    public delegate {type} Del();

    static void foo()
    {{
        Del a = {create};
        var h = a();
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Security.Cryptography

Public Class WeakHashing
    Public Delegate Function Del() As {type}
    Private Shared Sub foo()
        Dim a As Del = AddressOf {create}
        Dim h = a()
    End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0006",
                Severity = DiagnosticSeverity.Warning
            };
            await VerifyCSharpDiagnostic     (cSharpTest,      new[] { expected, expected }).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new[] { expected, expected }).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataRow("MD5",  "MD5.Create")]
        [DataRow("SHA1", "SHA1.Create")]
        [DataTestMethod]
        public async Task Func(string type, string create)
        {
            var cSharpTest = $@"
using System;
using System.Security.Cryptography;

public class WeakHashing
{{
    static void foo()
    {{
        new Func<{type}>
            ({create})();
    }}
}}
";

            var visualBasicTest = $@"
Imports System
Imports System.Security.Cryptography

Public Class WeakHashing
    Private Shared Sub foo()
        Dim func As Func(Of {type}) =
            AddressOf {create}
        Dim mD As {type} =
            func()
    End Sub
End Class
";

            var expectedCSharp = new []
            {
                new DiagnosticResult
                {
                    Id       = "SCS0006",
                    Severity = DiagnosticSeverity.Warning
                }.WithLocation(9, 9),
                new DiagnosticResult
                {
                    Id       = "SCS0006",
                    Severity = DiagnosticSeverity.Warning
                }.WithLocation(10, 14)
            };
            await VerifyCSharpDiagnostic(cSharpTest, expectedCSharp).ConfigureAwait(false);

            var expectedVBnet = new[]
            {
                new DiagnosticResult
                {
                    Id       = "SCS0006",
                    Severity = DiagnosticSeverity.Warning
                }.WithLocation(8, 23),
                new DiagnosticResult
                {
                    Id       = "SCS0006",
                    Severity = DiagnosticSeverity.Warning
                }.WithLocation(10, 13)
            };
            await VerifyVisualBasicDiagnostic(visualBasicTest, expectedVBnet).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataRow("MD5",  "MD5.Create")]
        [DataRow("SHA1", "SHA1.Create")]
        [DataTestMethod]
        public async Task SameLine(string type, string create)
        {
            var cSharpTest = $@"
using System.Security.Cryptography;

public class WeakHashing
{{
    static void f({type} a, {type} b)
    {{
    }}

    static void foo()
    {{
        f({create}(), {create}());
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Security.Cryptography

Public Class WeakHashing
    Private Shared Sub f(a As {type}, b As {type})
    End Sub
    Private Shared Sub foo()
        f({create}(), {create}())
    End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0006",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, new[] { expected, expected }).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new[] { expected, expected }).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataRow("MD5", "MD5.Create")]
        [DataRow("SHA1", "SHA1.Create")]
        [DataTestMethod]
        public async Task Lazy(string type, string create)
        {
            var cSharpTest = $@"
using System;
using System.Security.Cryptography;

public class WeakHashing
{{
    static void foo()
    {{
        var l = new Lazy<{type}>({create}).Value;
    }}
}}
";

            var visualBasicTest = $@"
Imports System
Imports System.Security.Cryptography

Public Class WeakHashing
    Private Shared Sub foo()
        Dim a = New Lazy(Of {type}) (AddressOf {create}).Value
    End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0006",
                Severity = DiagnosticSeverity.Warning
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataRow("MD5")]
        [DataRow("SHA1")]
        [DataRow("MD5Cng")]
        [DataRow("MD5CryptoServiceProvider")]
        [DataRow("SHA1CryptoServiceProvider")]
        [DataRow("SHA1Managed")]
        [DataRow("SHA1Cng")]
        [DataTestMethod]
        public async Task ExternalFunction(string type)
        {
            var cSharpTest = $@"
using System.Security.Cryptography;

public class WeakHashing
{{
    static {type} GetHash()
    {{
        return null;
    }}
    static void foo()
    {{
        {type} a = GetHash();
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Security.Cryptography

Public Class WeakHashing
    Private Shared Function GetHash() As {type}
        return Nothing
    End Function
    Private Shared Sub foo()
        Dim mD As {type} = GetHash()
    End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0006",
                Severity = DiagnosticSeverity.Warning
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
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

public class WeakHashing
{{
    static void Foo()
    {{
        var hash = {create};
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Security.Cryptography

Public Class WeakHashing
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

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [DataRow("HashAlgorithm.Create(\"System.Security.Cryptography.SHA256\")")]
        [DataRow("SHA256.Create()")]
        [DataRow("HashAlgorithm.Create(name)")]
        [DataRow("HashAlgorithm.Create(Sha1Name)")]
        // [DataRow("HashAlgorithm.Create(Sha256Name)")] todo: property check not implemented
        [DataTestMethod]
        public async Task HashCreateSafe(string create)
        {
            var cSharpTest = $@"
using System.Security.Cryptography;

public class WeakHashing
{{
    static string Sha256Name {{ get {{ return ""System.Security.Cryptography.SHA256""; }} }}
    static string Sha1Name   {{ get {{ return ""System.Security.Cryptography.SHA1""; }} }}

    static void Foo(string name)
    {{
        var sha = {create};
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Security.Cryptography

Public Class WeakHashing
    Private Shared ReadOnly Property Sha256Name() As String
        Get
            Return ""System.Security.Cryptography.SHA256""
        End Get
    End Property
    Private Shared ReadOnly Property Sha1Name() As String
        Get
            Return ""System.Security.Cryptography.SHA1""
        End Get
    End Property
    Private Shared Sub Foo(name As System.String)
        Dim sha As HashAlgorithm = {create}
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task GivenAliasDirective_DetectDiagnostic()
        {
            var cSharpTest = @"
using System.Security.Cryptography;
using SH = System.Security.Cryptography.SHA1CryptoServiceProvider;

namespace VulnerableApp
{
    public class Test
    {
        static void Foo()
        {
            SHA1 sha = new SH();
        }
    }
}
";

            var visualBasicTest = $@"
Imports SH = System.Security.Cryptography.SHA1CryptoServiceProvider

Public Class WeakHashing
    Private Shared Sub foo()
        Dim sha As New SH()
    End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id = "SCS0006",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);

        }
    }
}
