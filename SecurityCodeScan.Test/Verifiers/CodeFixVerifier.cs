using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Formatting;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;

namespace SecurityCodeScan.Test.Helpers
{
    /// <summary>
    /// Superclass of all Unit tests made for diagnostics with codefixes.
    /// Contains methods used to verify correctness of codefixes
    /// </summary>
    public abstract partial class CodeFixVerifier : DiagnosticVerifier
    {
        /// <summary>
        /// Returns the codefix being tested (C#) - to be implemented in non-abstract class
        /// </summary>
        /// <returns>The CodeFixProvider to be used for CSharp code</returns>
        protected virtual CodeFixProvider GetCSharpCodeFixProvider()
        {
            return null;
        }

        /// <summary>
        /// Returns the codefix being tested (VB) - to be implemented in non-abstract class
        /// </summary>
        /// <returns>The CodeFixProvider to be used for VisualBasic code</returns>
        protected virtual CodeFixProvider GetBasicCodeFixProvider()
        {
            return null;
        }

        /// <summary>
        /// Called to test a C# codefix when applied on the inputted string as a source
        /// </summary>
        /// <param name="oldSource">A class in the form of a string before the CodeFix was applied to it</param>
        /// <param name="newSource">A class in the form of a string after the CodeFix was applied to it</param>
        /// <param name="codeFixIndex">Index determining which codefix to apply if there are multiple</param>
        /// <param name="allowNewCompilerDiagnostics">A bool controlling whether or not the test will fail if
        /// the CodeFix introduces other warnings after being applied</param>
        protected async Task VerifyCSharpFix(string  oldSource,
                                             string  newSource,
                                             int?    codeFixIndex                = null,
                                             bool    allowNewCompilerDiagnostics = false,
                                             Version dotNetVersion               = null)
        {
            //This fix avoid new line problems when comparing the generated source code with the one hard coded in the test.
            var normalizeOld = oldSource.Replace("\r\n", "\n").Replace("\r", "\n").Replace("\n", "\r\n");
            var normalizeNew = newSource.Replace("\r\n", "\n").Replace("\r", "\n").Replace("\n", "\r\n");
            //Console.WriteLine("== New source (START) ==");
            //Console.WriteLine(normalizeNew);
            //Console.WriteLine("== New source (END) ==");

            var a = GetDiagnosticAnalyzers(LanguageNames.CSharp).ToList();
            a.Add(new DebugAnalyzer());

            await VerifyFix(LanguageNames.CSharp,
                            a.ToImmutableArray(),
                            GetCSharpCodeFixProvider(),
                            normalizeOld,
                            normalizeNew,
                            codeFixIndex,
                            allowNewCompilerDiagnostics,
                            dotNetVersion,
                            CancellationToken.None).ConfigureAwait(false);
        }

        /// <summary>
        /// General verifier for codefixes.
        /// Creates a Document from the source string, then gets diagnostics on it and applies the relevant codefixes.
        /// Then gets the string after the codefix is applied and compares it with the expected result.
        /// Note: If any codefix causes new diagnostics to show up, the test fails unless allowNewCompilerDiagnostics is
        /// set to true.
        /// </summary>
        /// <param name="language">The language the source code is in</param>
        /// <param name="analyzers">The analyzers to be applied to the source code</param>
        /// <param name="codeFixProvider">The codefix to be applied to the code wherever the relevant Diagnostic is
        /// found</param>
        /// <param name="oldSource">A class in the form of a string before the CodeFix was applied to it</param>
        /// <param name="newSource">A class in the form of a string after the CodeFix was applied to it</param>
        /// <param name="codeFixIndex">Index determining which codefix to apply if there are multiple</param>
        /// <param name="allowNewCompilerDiagnostics">A bool controlling whether or not the test will fail if
        /// the CodeFix introduces other warnings after being applied</param>
        private async Task VerifyFix(string                             language,
                                     ImmutableArray<DiagnosticAnalyzer> analyzers,
                                     CodeFixProvider                    codeFixProvider,
                                     string                             oldSource,
                                     string                             newSource,
                                     int?                               codeFixIndex,
                                     bool                               allowNewCompilerDiagnostics,
                                     Version                            dotNetVersion,
                                     CancellationToken                  cancellationToken)
        {
            var document            = CreateDocument(oldSource, dotNetVersion, language, GetAdditionalReferences());
            var analyzerDiagnostics = await GetSortedDiagnosticsFromDocuments(analyzers,
                                                                              null,
                                                                              new[] { document },
                                                                              cancellationToken).ConfigureAwait(false);
            var compilerDiagnostics = await GetCompilerDiagnostics(document, cancellationToken).ConfigureAwait(false);
            foreach (Diagnostic diag in compilerDiagnostics)
            {
                Console.WriteLine("/!\\: " + diag);
            }

            //Some compiler diagnostic are simply warnings, we can not fail once a warning is present..
            //Assert.AreEqual(compilerDiagnostics.Count(),0);
            var attempts = analyzerDiagnostics.Length;

            for (int i = 0; i < attempts; ++i)
            {
                var actions = new List<CodeAction>();
                var context = new CodeFixContext(document, analyzerDiagnostics[0], (a, d) => actions.Add(a), cancellationToken);
                await codeFixProvider.RegisterCodeFixesAsync(context).ConfigureAwait(false);

                if (!actions.Any())
                {
                    break;
                }

                if (codeFixIndex != null)
                {
                    document = await ApplyFix(document, actions.ElementAt((int)codeFixIndex), cancellationToken).ConfigureAwait(false);
                    break;
                }

                document            = await ApplyFix(document, actions.ElementAt(0), cancellationToken).ConfigureAwait(false);
                analyzerDiagnostics = await GetSortedDiagnosticsFromDocuments(analyzers,
                                                                              null,
                                                                              new[] { document },
                                                                              cancellationToken).ConfigureAwait(false);

                var newCompilerDiagnostics = GetNewDiagnostics(compilerDiagnostics,
                                                               await GetCompilerDiagnostics(document,
                                                                                            cancellationToken).ConfigureAwait(false));

                //check if applying the code fix introduced any new compiler diagnostics
                if (!allowNewCompilerDiagnostics && newCompilerDiagnostics.Any())
                {
                    // Format and get the compiler diagnostics again so that the locations make sense in the output
                    document = document.WithSyntaxRoot(Formatter.Format(await document.GetSyntaxRootAsync(cancellationToken)
                                                                                      .ConfigureAwait(false),
                                                                        Formatter.Annotation,
                                                                        document.Project.Solution.Workspace));

                    newCompilerDiagnostics = GetNewDiagnostics(compilerDiagnostics,
                                                               await GetCompilerDiagnostics(document,
                                                                                            cancellationToken).ConfigureAwait(false));

                    var diagnostics = string.Join("\r\n", newCompilerDiagnostics.Select(d => d.ToString()));
                    var doc = (await document.GetSyntaxRootAsync(cancellationToken).ConfigureAwait(false)).ToFullString();
                    Assert.IsTrue(false,
                                  $"Fix introduced new compiler diagnostics:\r\n{diagnostics}\r\n\r\nNew document:\r\n{doc}\r\n");
                }

                //check if there are analyzer diagnostics left after the code fix
                if (!analyzerDiagnostics.Any())
                {
                    break;
                }
            }

            //after applying all of the code fixes, compare the resulting string to the inputted one
            var actual = await GetStringFromDocument(document, cancellationToken).ConfigureAwait(false);
            Assert.AreEqual(newSource, actual);
        }
    }
}
