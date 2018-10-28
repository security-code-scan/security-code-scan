using System;
using System.Threading.Tasks;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test.XXE
{
    public abstract class XxeAnalyzerTestBase : DiagnosticVerifier
    {
        /// <summary> Defaults are safe starting 4.5.2 </summary>
        private static readonly Version SafeVersion       = new Version(4, 5, 2);
        private static readonly Version VulnerableVersion = new Version(4, 5, 1);

        protected async Task VerifyDiagnosticSafeUnsafe(string cSharpTest, string visualBasicTest, DiagnosticResult[] expected)
        {
            if (cSharpTest == null && visualBasicTest == null)
                throw new ArgumentException();

            if (cSharpTest != null)
            {
                await VerifyCSharpDiagnostic(cSharpTest, expected, dotNetVersion: VulnerableVersion).ConfigureAwait(false);
                // defaults are safe starting 4.5.2
                await VerifyCSharpDiagnostic(cSharpTest, dotNetVersion: SafeVersion).ConfigureAwait(false);
            }

            if (visualBasicTest != null)
            {
                await VerifyVisualBasicDiagnostic(visualBasicTest, expected, dotNetVersion: VulnerableVersion).ConfigureAwait(false);
                // defaults are safe starting 4.5.2
                await VerifyVisualBasicDiagnostic(visualBasicTest, dotNetVersion: SafeVersion).ConfigureAwait(false);
            }
        }

        protected async Task VerifyAlwaysWarnings(string cSharpTest, string visualBasicTest, DiagnosticResult[] expected)
        {
            if (cSharpTest == null && visualBasicTest == null)
                throw new ArgumentException();

            if (cSharpTest != null)
            {
                await VerifyCSharpDiagnostic(cSharpTest, expected, dotNetVersion: VulnerableVersion).ConfigureAwait(false);
                await VerifyCSharpDiagnostic(cSharpTest, expected, dotNetVersion: SafeVersion).ConfigureAwait(false);
            }

            if (visualBasicTest != null)
            {
                await VerifyVisualBasicDiagnostic(visualBasicTest, expected, dotNetVersion: VulnerableVersion).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, expected, dotNetVersion: SafeVersion).ConfigureAwait(false);
            }
        }

        protected async Task VerifyNoWarnings(string cSharpTest, string visualBasicTest)
        {
            if (cSharpTest == null && visualBasicTest == null)
                throw new ArgumentException();

            if (cSharpTest != null)
            {
                await VerifyCSharpDiagnostic(cSharpTest, dotNetVersion: VulnerableVersion).ConfigureAwait(false);
                await VerifyCSharpDiagnostic(cSharpTest, dotNetVersion: SafeVersion).ConfigureAwait(false);
            }

            if (visualBasicTest != null)
            {
                await VerifyVisualBasicDiagnostic(visualBasicTest, dotNetVersion: VulnerableVersion).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, dotNetVersion: SafeVersion).ConfigureAwait(false);
            }
        }

        public enum Warnings
        {
            None,
            Always,
            OnFramework,
        }

        protected async Task Verify(string cSharpTest, string visualBasicTest, DiagnosticResult[] expected, Warnings expectWarnings)
        {
            switch (expectWarnings)
            {
                case Warnings.Always:
                    await VerifyAlwaysWarnings(cSharpTest, visualBasicTest, expected).ConfigureAwait(false);
                    break;
                case Warnings.OnFramework:
                    await VerifyDiagnosticSafeUnsafe(cSharpTest, visualBasicTest, expected).ConfigureAwait(false);
                    break;
                case Warnings.None:
                    await VerifyNoWarnings(cSharpTest, visualBasicTest).ConfigureAwait(false);
                    break;
            }
        }
    }
}
