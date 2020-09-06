using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Test.Helpers;
using System.Collections.Generic;
using System.Threading.Tasks;
using SecurityCodeScan.Test.Config;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;
using System;

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
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[] { new WeakCertificateValidationAnalyzerCSharp() };
            else
                return new DiagnosticAnalyzer[] { new WeakCertificateValidationAnalyzerVisualBasic() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.Net.Http.WebRequestHandler).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Net.Http.HttpClientHandler).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestCategory("Safe")]
        [DataTestMethod]
        [DataRow("var httpClientHandler = new HttpClientHandler();",             "httpClientHandler.ServerCertificateCustomValidationCallback", "GetCallbacks2")]
        [DataRow("var request = (Rqst)WebRequest.Create(\"https://hack.me/\");", "request.ServerCertificateValidationCallback",                 "GetCallbacks")]
        [DataRow("var request = new WebRequestHandler();",                       "request.ServerCertificateValidationCallback",                 "GetCallbacks")]
        [DataRow("",                                                             "ServicePointManager.ServerCertificateValidationCallback",     "GetCallbacks")]
        public async Task WeakCertFalsePositiveCSharp(string factory, string left, string callbackFunctionName)
        {
            var method = GetType().GetMethod(callbackFunctionName, System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            Func<string[]> getCallbacks = () => (string[])method.Invoke(null, null);

            foreach (var returnValue in new[] {"false", "Unknown"})
            {
                foreach (var assignment in new[] {"=", "+="})
                {
                    foreach (var right in getCallbacks())
                    {
                        var payload = $"{left} {assignment} {string.Format(right, returnValue)}";

                        var cSharpTest = $@"
#pragma warning disable 8019
    using System.Security.Cryptography.X509Certificates;
    using System.Net.Security;
    using System.Net;
    using Rqst = System.Net.HttpWebRequest;
    using System.Net.Http;
#pragma warning restore 8019

public class WeakCert
{{
    private bool Unknown;

    public WeakCert(bool val)
    {{
        Unknown = val;
    }}

    public void DoGetRequest()
    {{
        {factory}
        {payload}
    }}
}}
";
                        await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
                    }
                }
            }
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("var httpClientHandler = new HttpClientHandler();",             "httpClientHandler.ServerCertificateCustomValidationCallback", "GetCallbacks2")]
        [DataRow("var request = (Rqst)WebRequest.Create(\"https://hack.me/\");", "request.ServerCertificateValidationCallback",                 "GetCallbacks")]
        [DataRow("var request = new WebRequestHandler();",                       "request.ServerCertificateValidationCallback",                 "GetCallbacks")]
        [DataRow("",                                                             "ServicePointManager.ServerCertificateValidationCallback",     "GetCallbacks")]
        public async Task WeakCertAuditCSharp(string factory, string left, string callbackFunctionName)
        {
            var method = GetType().GetMethod(callbackFunctionName, System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            Func<string[]> getCallbacks = () => (string[])method.Invoke(null, null);

            foreach (var returnValue in new[] { "Unknown" })
            {
                foreach (var assignment in new[] { "=", "+=" })
                {
                    foreach (var right in getCallbacks())
                    {
                        var payload = $"{left} {assignment} {string.Format(right, returnValue)}";

                        var cSharpTest = $@"
#pragma warning disable 8019
    using System.Security.Cryptography.X509Certificates;
    using System.Net.Security;
    using System.Net;
    using Rqst = System.Net.HttpWebRequest;
    using System.Net.Http;
#pragma warning restore 8019

public class WeakCert
{{
    private bool Unknown;

    public WeakCert(bool val)
    {{
        Unknown = val;
    }}

    public void DoGetRequest()
    {{
        {factory}
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
                }
            }
        }

        private static string[] GetCallbacks()
        {
            return new[]
            {
                "delegate {{ return {0}; }};",
                "delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) {{ return {0}; }};",
                "(sender, cert, chain, sslPolicyErrors) => {{ return {0}; }};",
                "(sender, cert, chain, sslPolicyErrors) => {0};"
            };
        }

        private static string[] GetCallbacks2()
        {
            return new[]
            {
                "delegate {{ return {0}; }};",
                "delegate(HttpRequestMessage message, X509Certificate2 certificate, X509Chain chain, SslPolicyErrors errors) {{ return {0}; }};",
                "(message, cert, chain, sslPolicyErrors) => {{ return {0}; }};",
                "(message, cert, chain, sslPolicyErrors) => {0};"
            };
        }

        // todo: add ServicePointManager.CertificatePolicy tests

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("var httpClientHandler = new HttpClientHandler();",             "httpClientHandler.ServerCertificateCustomValidationCallback", "GetCallbacks2")]
        [DataRow("var request = (Rqst)WebRequest.Create(\"https://hack.me/\");", "request.ServerCertificateValidationCallback",                 "GetCallbacks")]
        [DataRow("var request = new WebRequestHandler();",                       "request.ServerCertificateValidationCallback",                 "GetCallbacks")]
        [DataRow("",                                                             "ServicePointManager.ServerCertificateValidationCallback",     "GetCallbacks")]
        public async Task WeakCertVulnerableCSharp(string factory, string left, string callbackFunctionName)
        {
            var method = GetType().GetMethod(callbackFunctionName, System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            Func<string[]> getCallbacks = () => (string[])method.Invoke(null, null);

            foreach (var returnValue in new[] { "true" })
            {
                foreach (var assignment in new[] { "=", "+=" })
                {
                    foreach (var right in getCallbacks())
                    {
                        var payload = $"{left} {assignment} {string.Format(right, returnValue)}";

                        var cSharpTest = $@"
#pragma warning disable 8019
    using System.Security.Cryptography.X509Certificates;
    using System.Net.Security;
    using System.Net;
    using Rqst = System.Net.HttpWebRequest;
    using System.Net.Http;
#pragma warning restore 8019

public class WeakCert
{{
    public void DoGetRequest()
    {{
        {factory}
        {payload}
    }}
}}
";
                        await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
                    }
                }
            }
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        // todo: error BC30676: 'ServerCertificateValidationCallback' is not an event of 'ServicePointManager'.
        //[DataRow(@"AddHandler ServicePointManager.ServerCertificateValidationCallback, Function(sender, cert, chain, sslPolicyErrors) True")]
        // todo: error BC30452: Operator '+' is not defined for types 'RemoteCertificateValidationCallback' and
        // 'Function <generated method>(sender As Object, cert As Object, chain As Object, sslPolicyErrors As Object) As Boolean'.
        //[DataRow(@"ServicePointManager.ServerCertificateValidationCallback += Function(sender, cert, chain, sslPolicyErrors) True")]
        //[DataRow("",                                                                           "ServicePointManager.ServerCertificateValidationCallback")]
        [DataRow("Dim request As Rqst = CType(WebRequest.Create(\"https://hack.me/\"), Rqst)", "request.ServerCertificateValidationCallback")]
        [DataRow("Dim request As New WebRequestHandler()",                                     "request.ServerCertificateValidationCallback")]
        [DataRow("Dim request As New HttpClientHandler()",                                     "request.ServerCertificateCustomValidationCallback")]
        public async Task WeakCertVulnerableVBasic(string factory, string left)
        {
            foreach (var returnValue in new[] { "True" })
            {
                foreach (var assignment in new[] { "="/*, "+="*/ })
                {
                    foreach (var right in new[]
                    {
                        "Function(sender, cert, chain, sslPolicyErrors) {0}",
                        @"Function(sender, cert, chain, sslPolicyErrors)
                             Return {0}
                          End Function",
                        "Function(ByVal sender As Object, ByVal certificate As X509Certificate, ByVal chain As X509Chain, ByVal errors As SslPolicyErrors) {0}"
                    })
                    {
                        var payload = $"{left} {assignment} {string.Format(right, returnValue)}";

                        var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System.Security.Cryptography.X509Certificates
    Imports System.Net.Security
    Imports System.Net
    Imports Rqst = System.Net.HttpWebRequest
    Imports System.Net.Http
#Enable Warning BC50001

Public Class OkCert
    Public Sub DoGetRequest()
        {factory}
        {payload}
    End Sub
End Class
";
                        await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
                    }
                }
            }
        }
    }
}
