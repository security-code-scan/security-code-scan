using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Analyzers.Utils;

namespace SecurityCodeScan.Test.Helpers
{
    /// <summary>
    /// Superclass of all Unit Tests for DiagnosticAnalyzers
    /// </summary>
    public abstract partial class DiagnosticVerifier
    {
        #region To be implemented by Test classes

        /// <summary>
        /// Get the CSharp analyzer being tested - to be implemented in non-abstract class
        /// </summary>
        protected abstract IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language);

        protected virtual IEnumerable<MetadataReference> GetAdditionalReferences()
        {
            return null;
        }

        #endregion

        #region Verifier wrappers

        /// <summary>
        /// Called to test a C# DiagnosticAnalyzer when applied on the single inputted string as a source
        /// Note: input a DiagnosticResult for each Diagnostic expected
        /// </summary>
        /// <param name="source">A class in the form of a string to run the analyzer on</param>
        /// <param name="expected">DiagnosticResults that should appear after the analyzer is run on the source</param>
        /// <param name="verifyIfCompiles">Verify if the source compiles</param>
        protected async Task VerifyCSharpDiagnostic(string             source,
                                                    DiagnosticResult[] expected          = null,
                                                    bool               verifyIfCompiles  = true,
                                                    Version            dotNetVersion     = null,
                                                    CancellationToken  cancellationToken = default(CancellationToken))
        {
            var a = GetDiagnosticAnalyzers(LanguageNames.CSharp).ToList();
            a.Add(new DebugAnalyzer());
            await VerifyDiagnostics(new[] { source },
                                    LanguageNames.CSharp,
                                    a.ToImmutableArray(),
                                    expected ?? new DiagnosticResult[0],
                                    dotNetVersion,
                                    cancellationToken,
                                    verifyIfCompiles).ConfigureAwait(false);
        }

        /// <summary>
        /// Called to test a VB.NET DiagnosticAnalyzer when applied on the single inputted string as a source
        /// Note: input a DiagnosticResult for each Diagnostic expected
        /// </summary>
        /// <param name="source">A class in the form of a string to run the analyzer on</param>
        /// <param name="expected">DiagnosticResults that should appear after the analyzer is run on the source</param>
        /// <param name="verifyIfCompiles">Verify if the source compiles</param>
        protected async Task VerifyVisualBasicDiagnostic(string             source,
                                                         DiagnosticResult[] expected          = null,
                                                         bool               verifyIfCompiles  = true,
                                                         Version            dotNetVersion     = null,
                                                         CancellationToken  cancellationToken = default(CancellationToken))
        {
            var a = GetDiagnosticAnalyzers(LanguageNames.VisualBasic).ToList();
            a.Add(new DebugAnalyzer());
            await VerifyDiagnostics(new[] { source },
                                    LanguageNames.VisualBasic,
                                    a.ToImmutableArray(),
                                    expected ?? new DiagnosticResult[0],
                                    dotNetVersion,
                                    cancellationToken,
                                    verifyIfCompiles).ConfigureAwait(false);
        }

        /// <summary>
        /// Called to test a C# DiagnosticAnalyzer when applied on the single inputted string as a source
        /// Note: input a DiagnosticResult for each Diagnostic expected
        /// </summary>
        /// <param name="source">A class in the form of a string to run the analyzer on</param>
        /// <param name="expected">DiagnosticResults that should appear after the analyzer is run on the source</param>
        /// <param name="verifyIfCompiles">Verify if the source compiles</param>
        protected async Task VerifyCSharpDiagnostic(string            source,
                                                    DiagnosticResult  expected,
                                                    bool              verifyIfCompiles  = true,
                                                    Version           dotNetVersion     = null,
                                                    CancellationToken cancellationToken = default(CancellationToken))
        {
            await VerifyCSharpDiagnostic(source,
                                         new[] { expected },
                                         verifyIfCompiles,
                                         dotNetVersion,
                                         cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Called to test a VB.NET DiagnosticAnalyzer when applied on the single inputted string as a source
        /// Note: input a DiagnosticResult for each Diagnostic expected
        /// </summary>
        /// <param name="source">A class in the form of a string to run the analyzer on</param>
        /// <param name="expected">DiagnosticResults that should appear after the analyzer is run on the source</param>
        /// <param name="verifyIfCompiles">Verify if the source compiles</param>
        protected async Task VerifyVisualBasicDiagnostic(string            source,
                                                         DiagnosticResult  expected,
                                                         bool              verifyIfCompiles  = true,
                                                         Version           dotNetVersion     = null,
                                                         CancellationToken cancellationToken = default(CancellationToken))
        {
            await VerifyVisualBasicDiagnostic(source,
                                              new[] { expected },
                                              verifyIfCompiles,
                                              dotNetVersion,
                                              cancellationToken: cancellationToken).ConfigureAwait(false);
        }

        [TestInitialize]
        public void InitOutput()
        {
            Logger.LoggerHandler = Console.WriteLine;
        }

        /// <summary>
        /// General method that gets a collection of actual diagnostics found in the source after the analyzer is run, 
        /// then verifies each of them.
        /// </summary>
        /// <param name="sources">An array of strings to create source documents from to run the analyzers on</param>
        /// <param name="language">The language of the classes represented by the source strings</param>
        /// <param name="analyzers">The analyzers to be run on the source code</param>
        /// <param name="expected">DiagnosticResults that should appear after the analyzer is run on the sources</param>
        /// <param name="includeCompilerDiagnostics">Verify built-in compile diagnostics</param>
        private async Task VerifyDiagnostics(string[]                           sources,
                                             string                             language,
                                             ImmutableArray<DiagnosticAnalyzer> analyzers,
                                             DiagnosticResult[]                 expected,
                                             Version                            dotNetVersion,
                                             CancellationToken                  cancellationToken,
                                             bool                               includeCompilerDiagnostics = true)
        {
            var diagnostics = await GetSortedDiagnostics(sources,
                                                         language,
                                                         analyzers,
                                                         dotNetVersion,
                                                         cancellationToken,
                                                         GetAdditionalReferences(),
                                                         includeCompilerDiagnostics).ConfigureAwait(false);
            VerifyDiagnosticResults(diagnostics, analyzers, language, expected);
        }

        #endregion

        #region Actual comparisons and verifications

        /// <summary>
        /// Checks each of the actual Diagnostics found and
        /// compares them with the corresponding DiagnosticResult in the array of expected results.
        /// Diagnostics are considered equal only if the DiagnosticResultLocation, Id,
        /// Severity, and Message of the DiagnosticResult match the actual diagnostic.
        /// </summary>
        /// <param name="actualResults">The Diagnostics found by the compiler after
        /// running the analyzer on the source code</param>
        /// <param name="analyzers">The analyzers that was being run on the sources</param>
        /// <param name="expectedResults">Diagnostic Results that should have appeared in the code</param>
        private static void VerifyDiagnosticResults(ICollection<Diagnostic>            actualResults,
                                                    ImmutableArray<DiagnosticAnalyzer> analyzers,
                                                    string                             language,
                                                    params DiagnosticResult[]          expectedResults)
        {
            int expectedCount = expectedResults.Length;
            int actualCount   = actualResults.Count;

            if (expectedCount != actualCount)
            {
                string diagnosticsOutput = actualResults.Any()
                                               ? FormatDiagnostics(analyzers[0], actualResults.ToArray())
                                               : "    NONE.";

                var msg =
                    $@"Mismatch between number of diagnostics returned, expected ""{expectedCount}"" actual ""{actualCount}"" (Language:{language})

Diagnostics:
{diagnosticsOutput}
";
                Assert.IsTrue(false,
                              msg);
            }

            //For debug purpose
            foreach (var actual in actualResults)
            {
                var lineSpan = actual.Location.GetLineSpan();
                Console.WriteLine($"{actual.Id} ({actual.Severity}): {lineSpan.Path} {lineSpan.StartLinePosition}");
            }

            for (int i = 0; i < expectedResults.Length; i++)
            {
                var actual = actualResults.ElementAt(i);

                var expected = expectedResults[i];

                if (expected.Line == -1 && expected.Column == -1)
                {
                    //if (actual.Location != Location.None)
                    //{
                    //    Assert.IsTrue(false,
                    //        string.Format("Expected:\nA project diagnostic with No location\nActual:\n{0}",
                    //        FormatDiagnostics(analyzer, actual)));
                    //}
                }
                else
                {
                    VerifyDiagnosticLocation(analyzers[0],
                                             actual,
                                             actual.Location,
                                             expected.Locations.First(),
                                             language);
                    var additionalLocations = actual.AdditionalLocations.ToArray();

                    if (additionalLocations.Length != expected.Locations.Length - 1)
                    {
                        Assert.IsTrue(false,
                                      $@"Expected {expected.Locations.Length - 1} additional locations but got {additionalLocations.Length} for Diagnostic:
    {FormatDiagnostics(analyzers[0], actual)}
(Language: {language})
 ");
                    }

                    for (int j = 0; j < additionalLocations.Length; ++j)
                    {
                        VerifyDiagnosticLocation(analyzers[0],
                                                 actual,
                                                 additionalLocations[j],
                                                 expected.Locations[j + 1],
                                                 language);
                    }
                }

                if (actual.Id != expected.Id)
                {
                    Assert.IsTrue(false,
                                  $@"Expected diagnostic id to be ""{expected.Id}"" was ""{actual.Id}""

Diagnostic:
    {FormatDiagnostics(analyzers[0], actual)}
(Language: {language})
 ");
                }

                if (actual.Severity != expected.Severity && expected.Severity.HasValue)
                {
                    Assert.IsTrue(false,
                                  $@"Expected diagnostic severity to be ""{expected.Severity}"" was ""{actual.Severity}""

Diagnostic:
    {FormatDiagnostics(analyzers[0], actual)}
(Language: {language})
 ");
                }

                if (expected.Message != null && actual.GetMessage() != expected.Message)
                {
                    Assert.IsTrue(false,
                                  $@"Expected diagnostic message to be ""{expected.Message}"" was ""{actual.GetMessage()}""

Diagnostic:
    {FormatDiagnostics(analyzers[0], actual)}
(Language: {language})
 ");
                }
            }
        }

        /// <summary>
        /// Helper method to VerifyDiagnosticResult that checks the location of a diagnostic and
        /// compares it with the location in the expected DiagnosticResult.
        /// </summary>
        /// <param name="analyzer">The analyzer that was being run on the sources</param>
        /// <param name="diagnostic">The diagnostic that was found in the code</param>
        /// <param name="actual">The Location of the Diagnostic found in the code</param>
        /// <param name="expected">The DiagnosticResultLocation that should have been found</param>
        private static void VerifyDiagnosticLocation(DiagnosticAnalyzer       analyzer,
                                                     Diagnostic               diagnostic,
                                                     Location                 actual,
                                                     DiagnosticResultLocation expected,
                                                     string                   language)
        {
            var actualSpan = actual.GetLineSpan();

            Assert.IsTrue(actualSpan.Path == expected.Path ||
                          (actualSpan.Path != null && actualSpan.Path.Contains("Test0.") && expected.Path.Contains("Test.")),
                          $@"Expected diagnostic to be in file ""{expected.Path}"" was actually in file ""{actualSpan.Path}""

Diagnostic:
    {FormatDiagnostics(analyzer, diagnostic)}
(Language: {language})
 ");

            var actualLinePosition = actualSpan.StartLinePosition;

            // Only check line position if there is an actual line in the real diagnostic
            if (actualLinePosition.Line > 0)
            {
                if (actualLinePosition.Line + 1 != expected.Line)
                {
                    Assert.IsTrue(false,
                                  $@"Expected diagnostic to be on line ""{expected.Line}"" was actually on line ""{actualLinePosition.Line + 1}""

Diagnostic:
    {FormatDiagnostics(analyzer, diagnostic)}
(Language: {language})
 ");
                }
            }

            // Only check column position if there is an actual column position in the real diagnostic
            if (expected.Column == -1 || actualLinePosition.Character <= 0)
                return;

            if (actualLinePosition.Character + 1 != expected.Column)
            {
                Assert.IsTrue(false,
                              $@"Expected diagnostic to start at column ""{expected.Column}"" was actually at column ""{actualLinePosition.Character + 1}""

Diagnostic:
    {FormatDiagnostics(analyzer, diagnostic)}
(Language: {language})
 ");
            }
        }

        #endregion

        #region Formatting Diagnostics

        /// <summary>
        /// Helper method to format a Diagnostic into an easily readable string
        /// </summary>
        /// <param name="analyzer">The analyzer that this verifier tests</param>
        /// <param name="diagnostics">The Diagnostics to be formatted</param>
        /// <returns>The Diagnostics formatted as a string</returns>
        private static string FormatDiagnostics(DiagnosticAnalyzer analyzer, params Diagnostic[] diagnostics)
        {
            var builder = new StringBuilder();
            for (int i = 0; i < diagnostics.Length; ++i)
            {
                builder.AppendLine("// " + diagnostics[i]);

                var analyzerType = analyzer.GetType();
                var rules        = analyzer.SupportedDiagnostics;

                foreach (var rule in rules)
                {
                    if (rule == null || rule.Id != diagnostics[i].Id)
                        continue;

                    var location = diagnostics[i].Location;
                    if (location == Location.None)
                    {
                        builder.AppendFormat("GetGlobalResult({0}.{1})", analyzerType.Name, rule.Id);
                    }
                    else
                    {
                        Assert.IsTrue(location.IsInSource,
                                      $"Test base does not currently handle diagnostics in metadata locations. Diagnostic in metadata: {diagnostics[i]}\r\n");

                        string resultMethodName = diagnostics[i].Location.SourceTree.FilePath.EndsWith(".cs")
                                                      ? "GetCSharpResultAt"
                                                      : "GetBasicResultAt";
                        var    linePosition     = diagnostics[i].Location.GetLineSpan().StartLinePosition;

                        builder.AppendFormat("{0}({1}, {2}, {3}.{4})",
                                             resultMethodName,
                                             linePosition.Line      + 1,
                                             linePosition.Character + 1,
                                             analyzerType.Name,
                                             rule.Id);
                    }

                    if (i != diagnostics.Length - 1)
                    {
                        builder.Append(',');
                    }

                    builder.AppendLine();
                    break;
                }
            }

            return builder.ToString();
        }

        #endregion
    }
}
