﻿using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Test.Helpers;
using System.Collections.Generic;
using System.Threading.Tasks;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test
{
    [TestClass]
    public class WeakCertificateValidationAnalyzerTest : DiagnosticVerifier
    {
        private DiagnosticResult _expected = new DiagnosticResult
        {
            Id = "SCS0004",
            Severity = DiagnosticSeverity.Warning,
        };

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            return new DiagnosticAnalyzer[] { new WeakCertificateValidationAnalyzerCSharp(), new WeakCertificateValidationAnalyzerVisualBasic() };
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

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBsicTest).ConfigureAwait(false);
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

            await VerifyCSharpDiagnostic(cSharpTest, _expected.WithLocation(7)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBsicTest, _expected.WithLocation("Test0.vb", 6)).ConfigureAwait(false);
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

            await VerifyCSharpDiagnostic(cSharpTest, _expected.WithLocation(7)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBsicTest, _expected.WithLocation("Test0.vb", 6)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task Given_HttpWebRequestServerCertificateValidationCallback_ThenWeakCertVulnerableWarning()
        {
            var cSharpTest = @"
using System.Net;

class weakCert {
    public void DoGetRequest1()
    {
/**/    string url = ""https://hack.me/"";
        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
        request.GetResponse();
        request.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;
    }
}
";

            var visualBsicTest = @"
Imports System.Net

Class weakCert
    Public Sub DoGetRequest1()        '
        Dim url As String = ""https://hack.me/""
        Dim request As HttpWebRequest = DirectCast(WebRequest.Create(url), HttpWebRequest)
        request.GetResponse()
        request.ServerCertificateValidationCallback = Function(sender, cert, chain, sslPolicyErrors)
                                                                      Return True
                                                                  End Function
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest, _expected.WithLocation(10)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBsicTest, _expected.WithLocation("Test0.vb", 9)).ConfigureAwait(false);
        }
    }
}
