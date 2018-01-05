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
    public class WeakCertificateValidationAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new[] { new WeakCertificateValidationAnalyzer() };
        }

        [TestMethod]
        public async Task WeakCertFalsePositive()
        {
            var cSharpTest = @"
using System.Net;

class OkCert {
    public void DoGetRequest1()
    {
        string url = ""https://hack.me/"";
        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
        HttpWebResponse response = (HttpWebResponse)request.GetResponse();
        response.GetResponseStream();
    }
}
";

            var visualBsicTest = @"
Imports System.Net

Class OkCert
	Public Sub DoGetRequest1()
		Dim url As String = ""https://hack.me/""
        Dim request As HttpWebRequest = DirectCast(WebRequest.Create(url), HttpWebRequest)
        Dim response As HttpWebResponse = DirectCast(request.GetResponse(), HttpWebResponse)
        response.GetResponseStream()
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBsicTest);
        }

        [TestMethod]
        public async Task WeakCertVulnerable1()
        {
            var cSharpTest = @"
using System.Net;

class weakCert {
    public void DoGetRequest1()
    {
/**/    ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;

        string url = ""https://hack.me/"";
        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
        request.GetResponse();
    }
}
";

            var visualBsicTest = @"
Imports System.Net

Class weakCert
    Public Sub DoGetRequest1()        '
        ServicePointManager.ServerCertificateValidationCallback = Function(sender, cert, chain, sslPolicyErrors)
                                                                      Return True
                                                                  End Function
        Dim url As String = ""https://hack.me/""
        Dim request As HttpWebRequest = DirectCast(WebRequest.Create(url), HttpWebRequest)
        request.GetResponse()
    End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0004",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation(7));
            await VerifyVisualBasicDiagnostic(visualBsicTest, expected.WithLocation("Test0.vb", 6));
        }

        [TestMethod]
        public async Task WeakCertVulnerable2()
        {
            var cSharpTest = @"
using System.Net;

class weakCert {
    public void DoGetRequest1()
    {
/**/    ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, sslPolicyErrors) => true;

        string url = ""https://hack.me/"";
        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
        HttpWebResponse response = (HttpWebResponse)request.GetResponse();
        response.GetResponseStream();
    }
}
";

            var visualBsicTest = @"
Imports System.Net

Class weakCert
    Public Sub DoGetRequest1()        '
        ServicePointManager.ServerCertificateValidationCallback = Function(sender, cert, chain, sslPolicyErrors)
                                                                      Return True
                                                                  End Function
        Dim url As String = ""https://hack.me/""
        Dim request As HttpWebRequest = DirectCast(WebRequest.Create(url), HttpWebRequest)
        Dim response As HttpWebResponse = DirectCast(request.GetResponse(), HttpWebResponse)
		response.GetResponseStream()
    End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0004",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation(7));
            await VerifyVisualBasicDiagnostic(visualBsicTest, expected.WithLocation("Test0.vb", 6));
        }
    }
}
