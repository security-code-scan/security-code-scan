using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Audit;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test.Password
{
    [TestClass]
    public class HardcodedPasswordFieldTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new[] { new HardcodedPasswordAnalyzer() };
        }

        [TestCategory("Safe")]
        [DataRow("null")]
        [DataRow("String.Empty")]
        [DataRow("\"\"")]
        [DataRow("input")]
        [DataTestMethod]
        public async Task HardCodePasswordFalsePositive(string value)
        {
            var vbValue = value.CSharpReplaceToVBasic();

            var cSharpTest = $@"
using System;

namespace VulnerableApp
{{
    class HardCodedPassword
    {{
        static void TestCookie(string input)
        {{
            var uri = new UriBuilder();
            uri.Password = {value};
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System

Namespace VulnerableApp
    Class HardCodedPassword
        Private Shared Sub TestCookie(input As String)
            Dim uri = New UriBuilder()
            uri.Password = {vbValue}
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);

            cSharpTest = $@"
using System;

namespace VulnerableApp
{{
    class HardCodedPassword
    {{
        static void TestCookie(string input)
        {{
            var uri = new UriBuilder {{Password = {value}}};
        }}
    }}
}}
";

            visualBasicTest = $@"
Imports System

Namespace VulnerableApp
    Class HardCodedPassword
        Private Shared Sub TestCookie(input As String)
            Dim uri = New UriBuilder With {{.Password = {vbValue}}}
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task HardCodePasswordAssignment()
        {
            var cSharpTest = @"
using System;

namespace VulnerableApp
{
    class HardCodedPassword
    {
        static void TestCookie()
        {
            var uri = new UriBuilder();
            uri.Password = ""t0ps3cr3t"";
        }
    }
}
";

            var visualBasicTest = @"
Imports System

Namespace VulnerableApp
    Class HardCodedPassword
        Private Shared Sub TestCookie()
            Dim uri = New UriBuilder()
            uri.Password = ""t0ps3cr3t""
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0015",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected, await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false)).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task HardCodePasswordInitializer()
        {
            var cSharpTest = @"
using System;

namespace VulnerableApp
{
    class HardCodedPassword
    {
        static void TestCookie()
        {
            var uri = new UriBuilder {Password = ""t0ps3cr3t""};
        }
    }
}
";

            var visualBasicTest = @"
Imports System

Namespace VulnerableApp
    Class HardCodedPassword
        Private Shared Sub TestCookie()
            Dim uri = New UriBuilder With {.Password = ""t0ps3cr3t""}
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0015",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected, await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false)).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task HardCodedInitializer()
        {
            var cSharpTest = @"
using System;

namespace VulnerableApp
{
    class HardCodedPassword
    {
        static void TestCookie()
        {
            var uri = new UriBuilder {Port = 443};
        }
    }
}
";

            var visualBasicTest = @"
Imports System

Namespace VulnerableApp
    Class HardCodedPassword
        Private Shared Sub TestCookie()
            Dim uri = New UriBuilder With {.Port = 443}
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, null, await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false)).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        [Ignore("Const is not really a taint")]
        public async Task HardCodePasswordInitializerFromStaticReadonlyMember()
        {
            var cSharpTest = @"
using System;

namespace VulnerableApp
{
    class HardCodedPassword
    {
        static readonly string PWD = ""t0ps3cr3t"";

        static void TestCookie()
        {
            var uri = new UriBuilder {Password = PWD};
        }
    }
}
";

            var visualBasicTest = @"
Imports System

Namespace VulnerableApp
    Class HardCodedPassword
        Shared ReadOnly PWD As String = ""t0ps3cr3t""

        Private Shared Sub TestCookie()
            Dim uri = New UriBuilder With {.Password = PWD}
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0015",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected, await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task HardCodePasswordInitializerFromConstMember()
        {
            var cSharpTest = @"
using System;

namespace VulnerableApp
{
    class HardCodedPassword
    {
        const string PWD = ""t0ps3cr3t"";

        static void TestCookie()
        {
            var uri = new UriBuilder {Password = PWD};
        }
    }
}
";

            var visualBasicTest = @"
Imports System

Namespace VulnerableApp
    Class HardCodedPassword
        Const PWD As String = ""t0ps3cr3t""

        Private Shared Sub TestCookie()
            Dim uri = New UriBuilder With {.Password = PWD}
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0015",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected, await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false)).ConfigureAwait(false);
        }

        [TestMethod]
        [Ignore("Const is not really a taint")]
        public async Task HardCodePasswordInitializerFromConstMemberFlowPlusNonConst()
        {
            var cSharpTest = @"
using System;

namespace VulnerableApp
{
    class HardCodedPassword
    {
        const string PWD = ""t0ps3cr3t"";

        static void Run(string input)
        {
            TestCookie(PWD + input);
        }

        static void TestCookie(string pwd)
        {
            var uri = new UriBuilder {Password = pwd};
        }
    }
}
";

            var visualBasicTest = @"
Imports System

Namespace VulnerableApp
    Class HardCodedPassword
        Const PWD As String = ""t0ps3cr3t""

        Private Shared Sub Run(input As String)
            TestCookie(PWD + input)
        End Sub

        Private Shared Sub TestCookie(ByVal pwd As String)
            Dim uri = New UriBuilder With {
                .Password = pwd
            }
            End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, null, await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false)).ConfigureAwait(false);
        }

        [TestMethod]
        [Ignore("Const is not really a taint")]
        public async Task HardCodePasswordInitializerFromConstMemberFlow()
        {
            var cSharpTest = @"
using System;

namespace VulnerableApp
{
    class HardCodedPassword
    {
        const string PWD = ""t0ps3cr3t"";

        static void Run()
        {
            TestCookie(PWD);
        }

        static void TestCookie(string pwd)
        {
            var uri = new UriBuilder {Password = pwd};
        }
    }
}
";

            var visualBasicTest = @"
Imports System

Namespace VulnerableApp
    Class HardCodedPassword
        Const PWD As String = ""t0ps3cr3t""

        Private Shared Sub Run()
            TestCookie(PWD)
        End Sub

        Private Shared Sub TestCookie(ByVal pwd As String)
            Dim uri = New UriBuilder With {
                .Password = pwd
            }
            End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0015",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected, await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false)).ConfigureAwait(false);
        }
    }
}
