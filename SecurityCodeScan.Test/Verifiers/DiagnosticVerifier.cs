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
using Moq;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;

namespace SecurityCodeScan.Test.Helpers
{
    /// <summary>
    /// Superclass of all Unit Tests for DiagnosticAnalyzers
    /// </summary>
    public abstract partial class DiagnosticVerifier
    {
        protected DiagnosticVerifier()
        {
            // Tests ignore global user configuration files if they exist
            var mockConfigReader = new Mock<ConfigurationReader>();
            mockConfigReader.Setup(mr => mr.GetUserConfiguration()).Returns(default(ConfigData)); // For the partially mocked methods
            mockConfigReader.CallBase = true; // To wire-up the concrete class.
            ConfigurationManager.Reader = mockConfigReader.Object;
        }

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
        /// <param name="options"> Analysis context options</param>
        /// <param name="verifyIfCompiles">Verify if the source compiles</param>
        protected async Task VerifyCSharpDiagnostic(string             source,
                                                    DiagnosticResult[] expected = null,
                                                    AnalyzerOptions    options  = null,
                                                    bool               verifyIfCompiles  = true,
                                                    Version            dotNetVersion     = null,
                                                    CancellationToken  cancellationToken = default(CancellationToken))
        {
            var a = GetDiagnosticAnalyzers(LanguageNames.CSharp).ToList();
            a.Add(new DebugAnalyzer());
            await VerifyDiagnostics(new[] { source },
                                    LanguageNames.CSharp,
                                    a.ToImmutableArray(),
                                    options,
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
        /// <param name="options">Analysis context options</param>
        /// <param name="verifyIfCompiles">Verify if the source compiles</param>
        protected async Task VerifyVisualBasicDiagnostic(string             source,
                                                         DiagnosticResult[] expected          = null,
                                                         AnalyzerOptions    options           = null,
                                                         bool               verifyIfCompiles  = true,
                                                         Version            dotNetVersion     = null,
                                                         CancellationToken  cancellationToken = default(CancellationToken))
        {
            var a = GetDiagnosticAnalyzers(LanguageNames.VisualBasic).ToList();
            a.Add(new DebugAnalyzer());
            await VerifyDiagnostics(new[] { source },
                                    LanguageNames.VisualBasic,
                                    a.ToImmutableArray(),
                                    options,
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
        /// <param name="options">Analysis context options</param>
        /// <param name="verifyIfCompiles">Verify if the source compiles</param>
        protected async Task VerifyCSharpDiagnostic(string            source,
                                                    DiagnosticResult  expected,
                                                    AnalyzerOptions   options           = null,
                                                    bool              verifyIfCompiles  = true,
                                                    Version           dotNetVersion     = null,
                                                    CancellationToken cancellationToken = default(CancellationToken))
        {
            await VerifyCSharpDiagnostic(source,
                                         new[] { expected },
                                         options,
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
        /// <param name="options">Analysis context options</param>
        /// <param name="verifyIfCompiles">Verify if the source compiles</param>
        protected async Task VerifyVisualBasicDiagnostic(string            source,
                                                         DiagnosticResult  expected,
                                                         AnalyzerOptions   options           = null,
                                                         bool              verifyIfCompiles  = true,
                                                         Version           dotNetVersion     = null,
                                                         CancellationToken cancellationToken = default(CancellationToken))
        {
            await VerifyVisualBasicDiagnostic(source,
                                              new[] { expected },
                                              options,
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
        /// <param name="options">Analysis context options</param>
        /// <param name="expected">DiagnosticResults that should appear after the analyzer is run on the sources</param>
        /// <param name="includeCompilerDiagnostics">Verify built-in compile diagnostics</param>
        private async Task VerifyDiagnostics(string[]                           sources,
                                             string                             language,
                                             ImmutableArray<DiagnosticAnalyzer> analyzers,
                                             AnalyzerOptions                    options,
                                             DiagnosticResult[]                 expected,
                                             Version                            dotNetVersion,
                                             CancellationToken                  cancellationToken,
                                             bool                               includeCompilerDiagnostics = true)
        {
            var diagnostics = await GetSortedDiagnostics(sources,
                                                         language,
                                                         analyzers,
                                                         options,
                                                         dotNetVersion,
                                                         cancellationToken,
                                                         GetAdditionalReferences(),
                                                         includeCompilerDiagnostics).ConfigureAwait(false);

            await VerifyDiagnosticResults(diagnostics.Diagnostics, diagnostics.Documents, analyzers, language, cancellationToken, expected)
                .ConfigureAwait(false);
        }

        #endregion

        #region Actual comparisons and verifications

        private static async Task<string> GetSourceWithLineNumbers(IEnumerable<Document> documents,
                                                                   CancellationToken     cancellationToken)
        {
            var msg = new StringBuilder(1024);
            foreach (var document in documents)
            {
                msg.AppendLine($"\r\n{document.Name}");
                var sourceText = await document.GetTextAsync(cancellationToken).ConfigureAwait(false);
                foreach (var line in sourceText.Lines)
                {
                    msg.AppendLine($"{line.LineNumber + 1:00} {sourceText.ToString(line.Span)}");
                }
            }

            return msg.ToString();
        }

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
        private static async Task VerifyDiagnosticResults(ICollection<Diagnostic>            actualResults,
                                                          IEnumerable<Document>              documents,
                                                          ImmutableArray<DiagnosticAnalyzer> analyzers,
                                                          string                             language,
                                                          CancellationToken                  cancellationToken,
                                                          params DiagnosticResult[]          expectedResults)
        {
            int expectedCount = expectedResults.Length;
            int actualCount   = actualResults.Count;
            var documentsWithLineNumbers = await GetSourceWithLineNumbers(documents, cancellationToken).ConfigureAwait(false);

            if (expectedCount != actualCount)
            {
                string diagnosticsOutput = actualResults.Any()
                                               ? FormatDiagnostics(analyzers, actualResults.ToArray())
                                               : "    NONE.";

                var msg = $@"{documentsWithLineNumbers}
Mismatch between number of diagnostics returned, expected ""{expectedCount}"" actual ""{actualCount}"" (Language:{language})

Diagnostics:
{diagnosticsOutput}
";
                Assert.IsTrue(false, msg);
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

                if (expected.Line != -1 || expected.Column != -1)
                {
                    VerifyDiagnosticLocation(analyzers,
                                             documentsWithLineNumbers,
                                             actual,
                                             actual.Location,
                                             expected.Locations.First(),
                                             language);

                    var additionalLocations = actual.AdditionalLocations.ToArray();

                    if (additionalLocations.Length != expected.Locations.Count - 1)
                    {
                        Assert.IsTrue(false,
                                      $@"{documentsWithLineNumbers}
Expected {expected.Locations.Count - 1} additional locations but got {additionalLocations.Length} for Diagnostic:
{FormatDiagnostics(analyzers, actual)}
(Language: {language})
");
                    }

                    for (int j = 0; j < additionalLocations.Length; ++j)
                    {
                        VerifyDiagnosticLocation(analyzers,
                                                 documentsWithLineNumbers,
                                                 actual,
                                                 additionalLocations[j],
                                                 expected.Locations[j + 1],
                                                 language);
                    }
                }

                if (actual.Id != expected.Id)
                {
                    Assert.IsTrue(false,
                                  $@"{documentsWithLineNumbers}
Expected diagnostic id to be ""{expected.Id}"" was ""{actual.Id}""

Diagnostic:
    {FormatDiagnostics(analyzers, actual)}
(Language: {language})
 ");
                }

                if (actual.Severity != expected.Severity && expected.Severity.HasValue)
                {
                    Assert.IsTrue(false,
                                  $@"{documentsWithLineNumbers}
Expected diagnostic severity to be ""{expected.Severity}"" was ""{actual.Severity}""

Diagnostic:
    {FormatDiagnostics(analyzers, actual)}
(Language: {language})
 ");
                }

                if (expected.Message != null && actual.GetMessage() != expected.Message)
                {
                    Assert.IsTrue(false,
                                  $@"{documentsWithLineNumbers}
Expected diagnostic message to be ""{expected.Message}"" was ""{actual.GetMessage()}""

Diagnostic:
    {FormatDiagnostics(analyzers, actual)}
(Language: {language})
 ");
                }
            }
        }

        /// <summary>
        /// Helper method to VerifyDiagnosticResult that checks the location of a diagnostic and
        /// compares it with the location in the expected DiagnosticResult.
        /// </summary>
        private static void VerifyDiagnosticLocation(ImmutableArray<DiagnosticAnalyzer> analyzers,
                                                     string                             documentsWithLineNumbers,
                                                     Diagnostic                         diagnostic,
                                                     Location                           actual,
                                                     DiagnosticResultLocation           expected,
                                                     string                             language)
        {
            var actualSpan = actual.GetLineSpan();
            var extension = language == LanguageNames.CSharp ? CSharpDefaultFileExt : VisualBasicDefaultExt;

            Assert.IsTrue(actualSpan.Path == $"{expected.Path}.{extension}",
                          $@"{documentsWithLineNumbers}
Expected diagnostic to be in file ""{expected.Path}.{extension}"" was actually in file ""{actualSpan.Path}""

Diagnostic:
    {FormatDiagnostics(analyzers, diagnostic)}
(Language: {language})
 ");

            var actualLinePosition = actualSpan.StartLinePosition;

            // Only check line position if there is an actual line in the real diagnostic
            if (actualLinePosition.Line > 0)
            {
                if (actualLinePosition.Line + 1 != expected.Line)
                {
                    Assert.IsTrue(false,
                                  $@"{documentsWithLineNumbers}
Expected diagnostic to be on line ""{expected.Line}"" was actually on line ""{actualLinePosition.Line + 1}""

Diagnostic:
    {FormatDiagnostics(analyzers, diagnostic)}
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
                              $@"{documentsWithLineNumbers}
Expected diagnostic to start at column ""{expected.Column}"" was actually at column ""{actualLinePosition.Character + 1}""

Diagnostic:
    {FormatDiagnostics(analyzers, diagnostic)}
(Language: {language})
 ");
            }
        }

        #endregion

        #region Formatting Diagnostics

        /// <summary>
        /// Helper method to format a Diagnostic into an easily readable string
        /// </summary>
        /// <returns>The Diagnostics formatted as a string</returns>
        private static string FormatDiagnostics(ImmutableArray<DiagnosticAnalyzer> analyzers, params Diagnostic[] diagnostics)
        {
            var builder = new StringBuilder();
            for (int i = 0; i < diagnostics.Length; ++i)
            {
                builder.AppendLine("// " + diagnostics[i]);
                FormatDiagnostic(builder, analyzers, diagnostics[i], i == diagnostics.Length - 1);
            }

            return builder.ToString();
        }

        private static void FormatDiagnostic(StringBuilder builder, ImmutableArray<DiagnosticAnalyzer> analyzers, Diagnostic diagnostic, bool lastDiagnostic)
        {
            foreach (var analyzer in analyzers)
            {
                var analyzerType = analyzer.GetType();
                var rules        = analyzer.SupportedDiagnostics;

                foreach (var rule in rules)
                {
                    if (rule.Id != diagnostic.Id)
                        continue;

                    var location = diagnostic.Location;
                    if (location == Location.None)
                    {
                        builder.AppendFormat("GetGlobalResult({0}.{1})", analyzerType.Name, rule.Id);
                    }
                    else
                    {
                        Assert.IsTrue(location.IsInSource,
                                      $"Test base does not currently handle diagnostics in metadata locations. Diagnostic in metadata: {diagnostic}\r\n");

                        string resultMethodName = diagnostic.Location.SourceTree.FilePath.EndsWith(".cs")
                                                      ? "GetCSharpResultAt"
                                                      : "GetBasicResultAt";
                        var linePosition = diagnostic.Location.GetLineSpan().StartLinePosition;

                        builder.Append($"{resultMethodName}({linePosition.Line + 1}, {linePosition.Character + 1}, {analyzerType.Name}.{rule.Id})");
                    }

                    if (!lastDiagnostic)
                    {
                        builder.Append(',');
                    }

                    builder.AppendLine();
                    return;
                }
            }
        }

        #endregion
    }
}
