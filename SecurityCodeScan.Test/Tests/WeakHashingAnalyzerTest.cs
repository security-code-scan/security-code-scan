using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using TestHelper;

namespace SecurityCodeScan.Tests
{
    [TestClass]
    public class WeakHashingAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new[] { new WeakHashingAnalyzer() };
        }

        [TestMethod]
        public async Task WeakHashingFalsePositive()
        {
            var cSharpTest = @"
using System;
using System.Text;
using System.Security.Cryptography;

class Sha256OK
{
    static String generateSecureHashing()
    {
        string source = ""Hello World!"";
        SHA256 sha256 = SHA256.Create();
        byte[] data = sha256.ComputeHash(Encoding.UTF8.GetBytes(source));

        StringBuilder sBuilder = new StringBuilder();
        for (int i = 0; i < data.Length; i++)
        {
            sBuilder.Append(data[i].ToString(""x2""));
        }

        // Return the hexadecimal string. 
        return sBuilder.ToString();
    }
}";

            var visualBasicTest = @"
Imports System.Text
Imports System.Security.Cryptography

Class Sha256OK
	Private Shared Function generateSecureHashing() As String
		Dim source As String = ""Hello World!""
        Dim sha256__1 As SHA256 = SHA256.Create()
        Dim data As Byte() = sha256__1.ComputeHash(Encoding.UTF8.GetBytes(source))
        Dim sBuilder As New StringBuilder()
        For i As Integer = 0 To data.Length - 1
            sBuilder.Append(data(i).ToString(""x2""))
        Next
        ' Return the hexadecimal string. 
        Return sBuilder.ToString()
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task WeakHashingVulnerableMd5()
        {
            var cSharpTest = @"
using System;
using System.Text;
using System.Security.Cryptography;

class WeakHashing
{
    static String generateWeakHashingMD5()
    {
        string source = ""Hello World!"";
        MD5 md5 = MD5.Create();
        byte[] data = md5.ComputeHash(Encoding.UTF8.GetBytes(source));

        StringBuilder sBuilder = new StringBuilder();
        for (int i = 0; i < data.Length; i++)
        {
            sBuilder.Append(data[i].ToString(""x2""));
        }

        // Return the hexadecimal string. 
        return sBuilder.ToString();
    }
}
";

            var visualBasicTest = @"
Imports System.Text
Imports System.Security.Cryptography

Class WeakHashing
	Private Shared Function generateWeakHashingMD5() As String
		Dim source As String = ""Hello World!""
        Dim md5__1 As MD5 = MD5.Create()
        Dim data As Byte() = md5__1.ComputeHash(Encoding.UTF8.GetBytes(source))
        Dim sBuilder As New StringBuilder()
        For i As Integer = 0 To data.Length - 1
            sBuilder.Append(data(i).ToString(""x2""))
        Next
        ' Return the hexadecimal string. 
        Return sBuilder.ToString()
    End Function
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
        public async Task WeakHashingVulnerableSha1()
        {
            var cSharpTest = @"
using System;
using System.Text;
using System.Security.Cryptography;

class WeakHashing
{

    static String generateWeakHashingSHA1()
    {
        string source = ""Hello World!"";
        SHA1 sha1 = SHA1.Create();
        byte[] data = sha1.ComputeHash(Encoding.UTF8.GetBytes(source));

        StringBuilder sBuilder = new StringBuilder();
        for (int i = 0; i < data.Length; i++)
        {
            sBuilder.Append(data[i].ToString(""x2""));
        }

        // Return the hexadecimal string. 
        return sBuilder.ToString();
    }
}
";

            var visualBasicTest = @"
Imports System.Text
Imports System.Security.Cryptography

Class WeakHashing
	Private Shared Function generateWeakHashingSHA1() As String
		Dim source As String = ""Hello World!""
        Dim sha1__1 As SHA1 = SHA1.Create()
        Dim data As Byte() = sha1__1.ComputeHash(Encoding.UTF8.GetBytes(source))
        Dim sBuilder As New StringBuilder()
        For i As Integer = 0 To data.Length - 1
            sBuilder.Append(data(i).ToString(""x2""))
        Next
        ' Return the hexadecimal string. 
        Return sBuilder.ToString()
    End Function
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
    }
}
