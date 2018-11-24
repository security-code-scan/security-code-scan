using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Test.Helpers;
using System.Collections.Generic;
using System.Threading.Tasks;
using SecurityCodeScan.Test.Config;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test
{
    [TestClass]
    public class WeakCertificateValidationAnalyzerTest : DiagnosticVerifier
    {
        private DiagnosticResult Expected = new DiagnosticResult
        {
            Id = "SCS0004",
            Severity = DiagnosticSeverity.Warning,
        };

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            return new DiagnosticAnalyzer[] { new WeakCertificateValidationAnalyzerCSharp(), new WeakCertificateValidationAnalyzerVisualBasic() };
        }

        [TestCategory("Safe")]
        [DataTestMethod]
        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => Unknown;")]
        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback =  (sender, cert, chain, sslPolicyErrors) => Unknown;")]
        [DataRow(@"request.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => Unknown;")]
        [DataRow(@"request.ServerCertificateValidationCallback = (sender, cert, chain, sslPolicyErrors) => Unknown;")]

        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => {return Unknown;};")]
        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback =  (sender, cert, chain, sslPolicyErrors) => {return Unknown;};")]
        [DataRow(@"request.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => {return Unknown;};")]
        [DataRow(@"request.ServerCertificateValidationCallback = (sender, cert, chain, sslPolicyErrors) => {return Unknown;};")]

        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback += delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) { return Unknown; };")]
        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback =  delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) { return Unknown; };")]
        [DataRow(@"request.ServerCertificateValidationCallback += delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) { return Unknown; };")]
        [DataRow(@"request.ServerCertificateValidationCallback = delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) { return Unknown; };")]

        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback += delegate { return Unknown; };")]
        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback =  delegate { return Unknown; };")]
        [DataRow(@"request.ServerCertificateValidationCallback += delegate { return Unknown; };")]
        [DataRow(@"request.ServerCertificateValidationCallback = delegate { return Unknown; };")]

        [DataRow("")]

        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => false;")]
        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback =  (sender, cert, chain, sslPolicyErrors) => false;")]
        [DataRow(@"request.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => false;")]
        [DataRow(@"request.ServerCertificateValidationCallback = (sender, cert, chain, sslPolicyErrors) => false;")]

        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => {return false;};")]
        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback =  (sender, cert, chain, sslPolicyErrors) => {return false;};")]
        [DataRow(@"request.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => {return false;};")]
        [DataRow(@"request.ServerCertificateValidationCallback = (sender, cert, chain, sslPolicyErrors) => {return false;};")]

        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback += delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) { return false; };")]
        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback =  delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) { return false; };")]
        [DataRow(@"request.ServerCertificateValidationCallback += delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) { return false; };")]
        [DataRow(@"request.ServerCertificateValidationCallback = delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) { return false; };")]

        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback += delegate { return false; };")]
        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback =  delegate { return false; };")]
        [DataRow(@"request.ServerCertificateValidationCallback += delegate { return false; };")]
        [DataRow(@"request.ServerCertificateValidationCallback = delegate { return false; };")]
        public async Task WeakCertFalsePositiveCSharp(string payload)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System.Security.Cryptography.X509Certificates;
    using System.Net.Security;
    using System.Net;
    using Rqst = System.Net.HttpWebRequest;
#pragma warning restore 8019

class WeakCert
{{
    private bool Unknown;

    public WeakCert(bool val)
    {{
        Unknown = val;
    }}

    public void DoGetRequest()
    {{
        Rqst request = (Rqst)WebRequest.Create(""https://hack.me/"");
        {payload}
    }}
}}
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [DataTestMethod]
        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => Unknown;")]
        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback =  (sender, cert, chain, sslPolicyErrors) => Unknown;")]
        [DataRow(@"request.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => Unknown;")]
        [DataRow(@"request.ServerCertificateValidationCallback = (sender, cert, chain, sslPolicyErrors) => Unknown;")]

        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => {return Unknown;};")]
        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback =  (sender, cert, chain, sslPolicyErrors) => {return Unknown;};")]
        [DataRow(@"request.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => {return Unknown;};")]
        [DataRow(@"request.ServerCertificateValidationCallback = (sender, cert, chain, sslPolicyErrors) => {return Unknown;};")]

        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback += delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) { return Unknown; };")]
        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback =  delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) { return Unknown; };")]
        [DataRow(@"request.ServerCertificateValidationCallback += delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) { return Unknown; };")]
        [DataRow(@"request.ServerCertificateValidationCallback = delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) { return Unknown; };")]

        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback += delegate { return Unknown; };")]
        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback =  delegate { return Unknown; };")]
        [DataRow(@"request.ServerCertificateValidationCallback += delegate { return Unknown; };")]
        [DataRow(@"request.ServerCertificateValidationCallback = delegate { return Unknown; };")]
        public async Task WeakCertAuditCSharp(string payload)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System.Security.Cryptography.X509Certificates;
    using System.Net.Security;
    using System.Net;
    using Rqst = System.Net.HttpWebRequest;
#pragma warning restore 8019

class WeakCert
{{
    private bool Unknown;

    public WeakCert(bool val)
    {{
        Unknown = val;
    }}

    public void DoGetRequest()
    {{
        Rqst request = (Rqst)WebRequest.Create(""https://hack.me/"");
        {payload}
    }}
}}
";

            var testConfig = @"
AuditMode: true
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        // todo: add ServicePointManager.CertificatePolicy tests

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;")]
        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback =  (sender, cert, chain, sslPolicyErrors) => true;")]
        [DataRow(@"request.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;")]
        [DataRow(@"request.ServerCertificateValidationCallback = (sender, cert, chain, sslPolicyErrors) => true;")]

        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => {return true;};")]
        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback =  (sender, cert, chain, sslPolicyErrors) => {return true;};")]
        [DataRow(@"request.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => {return true;};")]
        [DataRow(@"request.ServerCertificateValidationCallback = (sender, cert, chain, sslPolicyErrors) => {return true;};")]

        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback += delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) { return true; };")]
        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback =  delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) { return true; };")]
        [DataRow(@"request.ServerCertificateValidationCallback += delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) { return true; };")]
        [DataRow(@"request.ServerCertificateValidationCallback = delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) { return true; };")]

        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback += delegate { return true; };")]
        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback =  delegate { return true; };")]
        [DataRow(@"request.ServerCertificateValidationCallback += delegate { return true; };")]
        [DataRow(@"request.ServerCertificateValidationCallback = delegate { return true; };")]
        public async Task WeakCertVulnerableCSharp(string payload)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System.Security.Cryptography.X509Certificates;
    using System.Net.Security;
    using System.Net;
    using Rqst = System.Net.HttpWebRequest;
#pragma warning restore 8019

class WeakCert {{
    public void DoGetRequest()
    {{
        Rqst request = (Rqst)WebRequest.Create(""https://hack.me/"");
        {payload}
    }}
}}
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback = Function(sender, cert, chain, sslPolicyErrors) True")]
        [DataRow(@"request.ServerCertificateValidationCallback = Function(sender, cert, chain, sslPolicyErrors) True")]
        // todo: error BC30676: 'ServerCertificateValidationCallback' is not an event of 'ServicePointManager'.
        //[DataRow(@"AddHandler ServicePointManager.ServerCertificateValidationCallback, Function(sender, cert, chain, sslPolicyErrors) True")]
        // todo: error BC30452: Operator '+' is not defined for types 'RemoteCertificateValidationCallback' and
        // 'Function <generated method>(sender As Object, cert As Object, chain As Object, sslPolicyErrors As Object) As Boolean'.
        //[DataRow(@"ServicePointManager.ServerCertificateValidationCallback += Function(sender, cert, chain, sslPolicyErrors) True")]//

        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback = Function(sender, cert, chain, sslPolicyErrors)
                                                                                Return True
                                                                             End Function")]
        [DataRow(@"request.ServerCertificateValidationCallback = Function(sender, cert, chain, sslPolicyErrors)
                                                                    Return True
                                                                 End Function")]
        [DataRow(@"ServicePointManager.ServerCertificateValidationCallback = Function(ByVal sender As Object, ByVal certificate As X509Certificate, ByVal chain As X509Chain, ByVal errors As SslPolicyErrors) True")]
        [DataRow(@"request.ServerCertificateValidationCallback = Function(ByVal sender As Object, ByVal certificate As X509Certificate, ByVal chain As X509Chain, ByVal errors As SslPolicyErrors) True")]

        public async Task WeakCertVulnerableVBasic(string payload)
        {
            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System.Security.Cryptography.X509Certificates
    Imports System.Net.Security
    Imports System.Net
    Imports Rqst = System.Net.HttpWebRequest
#Enable Warning BC50001

Class OkCert
    Public Sub DoGetRequest()
        Dim request As Rqst = CType(WebRequest.Create(""https://hack.me/""), Rqst)
        {payload}
    End Sub
End Class
";

            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }
    }
}
