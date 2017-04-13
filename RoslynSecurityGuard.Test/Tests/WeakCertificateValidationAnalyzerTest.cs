using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using TestHelper;

namespace RoslynSecurityGuard.Tests
{
    [TestClass]
    public class WeakCertificateValidationAnalyzerTest : DiagnosticVerifier
    {

        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new[] { new WeakCertificateValidationAnalyzer() };
        }

        [TestMethod]
        public async Task WeakCertFalsePositive()
        {
            var code = @"
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
            await VerifyCSharpDiagnostic(code);
        }

        [TestMethod]
        public async Task WeakCertVulnerable1()
        {
            var code = @"
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

            var expected = new DiagnosticResult
            {
                Id = "SG0004",
                Severity = DiagnosticSeverity.Warning,
            }.WithLocation(7,-1);

            await VerifyCSharpDiagnostic(code, expected);
        }

        [TestMethod]
        public async Task WeakCertVulnerable2()
        {
            var code = @"
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

            var expected = new DiagnosticResult
            {
                Id = "SG0004",
                Severity = DiagnosticSeverity.Warning,
            }.WithLocation(7, -1);

            await VerifyCSharpDiagnostic(code, expected);
        }
    }
}
