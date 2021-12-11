using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Testing;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.VisualBasic;
using Microsoft.VisualStudio.TestTools.UnitTesting.Logging;

namespace SecurityCodeScan.Test.Helpers
{
    /// <summary>
    /// Class for turning strings into documents and getting the diagnostics on them
    /// All methods are static
    /// </summary>
    public abstract partial class DiagnosticVerifier
    {
        private static readonly MetadataReference CodeAnalysisReference = MetadataReference.CreateFromFile(typeof(Compilation).Assembly.Location);

        private static readonly CompilationOptions CSharpDefaultOptions      = new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary);
        private static readonly CompilationOptions VisualBasicDefaultOptions = new VisualBasicCompilationOptions(OutputKind.DynamicallyLinkedLibrary, embedVbCoreRuntime: true);

        public const string DefaultFilePathPrefix = "Test";
        public const string CSharpDefaultFileExt  = "cs";
        public const string VisualBasicDefaultExt = "vb";
        private const string TestProjectName       = "TestProject";

        #region  Get Diagnostics

        /// <summary>
        /// Given classes in the form of strings, their language, and an IDiagnosticAnlayzer to apply to it,
        /// return the diagnostics found in the string after converting it to a document.
        /// </summary>
        /// <param name="sources">Classes in the form of strings</param>
        /// <param name="language">The language the source classes are in</param>
        /// <param name="analyzers">The analyzers to be run on the sources</param>
        /// <param name="references">Additional referenced modules</param>
        /// <param name="includeCompilerDiagnostics">Get compiler diagnostics too</param>
        /// <returns>An IEnumerable of Diagnostics that surfaced in the source code, sorted by Location</returns>
        private static async Task<(Diagnostic[] Diagnostics, IEnumerable<Document> Documents)> GetSortedDiagnostics(
            string[]                           sources,
            string                             language,
            ImmutableArray<DiagnosticAnalyzer> analyzers,
            AnalyzerOptions                    options,
            Version                            dotNetVersion,
            CancellationToken                  cancellationToken,
            IEnumerable<MetadataReference>     references                 = null,
            bool                               includeCompilerDiagnostics = false)
        {
            foreach (var source in sources)
            {
                Logger.LogMessage("{0}", source);
            }

            var documents = await GetDocuments(sources, dotNetVersion, language, cancellationToken, references).ConfigureAwait(false);
            return (await GetSortedDiagnosticsFromDocuments(analyzers,
                                                           options,
                                                           documents,
                                                           cancellationToken,
                                                           includeCompilerDiagnostics).ConfigureAwait(false), documents);
        }

        /// <summary>
        /// Given an analyzer and a document to apply it to,
        /// run the analyzer and gather an array of diagnostics found in it.
        /// The returned diagnostics are then ordered by location in the source document.
        /// </summary>
        /// <param name="analyzers">The analyzers to run on the documents</param>
        /// <param name="documents">The Documents that the analyzer will be run on</param>
        /// <param name="includeCompilerDiagnostics">Get compiler diagnostics too</param>
        /// <returns>An IEnumerable of Diagnostics that surfaced in the source code, sorted by Location</returns>
        protected static async Task<Diagnostic[]> GetSortedDiagnosticsFromDocuments(
            ImmutableArray<DiagnosticAnalyzer> analyzers,
            AnalyzerOptions                    options,
            IEnumerable<Document>              documents,
            CancellationToken                  cancellationToken,
            bool                               includeCompilerDiagnostics = false)
        {
            var projects = new HashSet<Project>();
            foreach (var document in documents)
            {
                projects.Add(document.Project);
            }

            var diagnostics = new List<Diagnostic>();
            foreach (var project in projects)
            {
                var compilation  = await project.GetCompilationAsync(cancellationToken).ConfigureAwait(false);
                var specOptions = compilation.Options.SpecificDiagnosticOptions;
                foreach (var analyzer in analyzers)
                {
                    specOptions = specOptions.AddRange(analyzer.SupportedDiagnostics.Select(x => new KeyValuePair<string, ReportDiagnostic>(x.Id, ReportDiagnostic.Warn)));
                }
                compilation = compilation.WithOptions(compilation.Options.WithSpecificDiagnosticOptions(specOptions));

                var compilationWithAnalyzers = compilation.WithAnalyzers(analyzers, options);
                var diags                    = includeCompilerDiagnostics
                                                   ? await compilationWithAnalyzers.GetAllDiagnosticsAsync().ConfigureAwait(false)
                                                   : await compilationWithAnalyzers.GetAnalyzerDiagnosticsAsync().ConfigureAwait(false);

                // workaround to suppress:
                // warning CS1701: Assuming assembly reference 'mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089' used by 'NHibernate' matches identity 'mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089' of 'mscorlib', you may need to supply runtime policy
                // in NHibernateSqlInjection
                var filtered = diags.Where(x => x.Id != "CS1701");

                foreach (var diag in filtered)
                {
                    if (diag.Location == Location.None || diag.Location.IsInMetadata)
                    {
                        diagnostics.Add(diag);
                    }
                    else
                    {
                        foreach (var document in documents)
                        {
                            var tree = await document.GetSyntaxTreeAsync(cancellationToken).ConfigureAwait(false);
                            if (tree == diag.Location.SourceTree)
                            {
                                diagnostics.Add(diag);
                            }
                        }
                    }
                }
            }

            var results = SortDiagnostics(diagnostics);
            return results;
        }

        /// <summary>
        /// Sort diagnostics by location in source document
        /// </summary>
        /// <param name="diagnostics">The list of Diagnostics to be sorted</param>
        /// <returns>An IEnumerable containing the Diagnostics in order of Location</returns>
        private static Diagnostic[] SortDiagnostics(IEnumerable<Diagnostic> diagnostics)
        {
            return diagnostics.OrderBy(d => d.Location.SourceSpan.Start).ToArray();
        }

        #endregion

        #region Set up compilation and documents

        /// <summary>
        /// Given an array of strings as sources and a language,
        /// turn them into a project and return the documents and spans of it.
        /// </summary>
        /// <param name="sources">Classes in the form of strings</param>
        /// <param name="language">The language the source code is in</param>
        /// <returns>A Tuple containing the Documents
        ///  produced from the sources and their TextSpans if relevant</returns>
        private static async Task<IEnumerable<Document>> GetDocuments(
            string[]                       sources,
            Version                        dotNetVersion,
            string                         language,
            CancellationToken              cancellationToken,
            IEnumerable<MetadataReference> references = null)
        {
            if (language != LanguageNames.CSharp && language != LanguageNames.VisualBasic)
            {
                throw new ArgumentException("Unsupported Language");
            }

            var project = await CreateProject(sources, dotNetVersion, cancellationToken, language, references).ConfigureAwait(false);
            return project.Documents;
        }

        /// <summary>
        /// Create a Document from a string through creating a project that contains it.
        /// </summary>
        /// <param name="source">Classes in the form of a string</param>
        /// <param name="language">The language the source code is in</param>
        /// <returns>A Document created from the source string</returns>
        protected static async Task<Document> CreateDocument(
            string                         source,
            Version                        dotNetVersion,
            CancellationToken              cancellationToken,
            string                         language   = LanguageNames.CSharp,
            IEnumerable<MetadataReference> references = null)
        {
            return (await CreateProject(new[] { source },
                                        dotNetVersion,
                                        cancellationToken,
                                        language,
                                        references).ConfigureAwait(false)).Documents.First();
        }

        private static ReferenceAssemblies GetReferenceAssemblies(Version version)
        {
            if (version == new Version(2, 0, 0))
                return ReferenceAssemblies.NetFramework.Net20.Default;
            else if (version == new Version(4, 0, 0))
                return ReferenceAssemblies.NetFramework.Net40.Default;
            else if (version == new Version(4, 5, 0))
                return ReferenceAssemblies.NetFramework.Net45.Default;
            else if (version == new Version(4, 5, 1))
                return ReferenceAssemblies.NetFramework.Net451.Default;
            else if (version == new Version(4, 6, 0))
                return ReferenceAssemblies.NetFramework.Net46.Default;
            else if (version == new Version(4, 6, 1))
                return ReferenceAssemblies.NetFramework.Net461.Default;
            else if (version == new Version(4, 6, 2))
                return ReferenceAssemblies.NetFramework.Net462.Default;
            else if (version == new Version(4, 7, 0))
                return ReferenceAssemblies.NetFramework.Net47.Default;
            else if (version == new Version(4, 7, 1))
                return ReferenceAssemblies.NetFramework.Net471.Default;
            else if (version == new Version(4, 7, 2))
                return ReferenceAssemblies.NetFramework.Net472.Default;
            else if (version == new Version(4, 8, 0))
                return ReferenceAssemblies.NetFramework.Net48.Default;
            else
                return ReferenceAssemblies.NetFramework.Net452.Default;
        }

        /// <summary>
        /// Create a project using the inputted strings as sources.
        /// </summary>
        /// <param name="sources">Classes in the form of strings</param>
        /// <param name="language">The language the source code is in</param>
        /// <returns>A Project created out of the Documents created from the source strings</returns>
        private static async Task<Project> CreateProject(
            string[]                           sources,
            Version                            dotNetVersion,
            CancellationToken                  cancellationToken,
            string                             language        = LanguageNames.CSharp,
            IEnumerable<MetadataReference>     references      = null)
        {
            string fileNamePrefix = DefaultFilePathPrefix;
            string fileExt        = language == LanguageNames.CSharp ? CSharpDefaultFileExt : VisualBasicDefaultExt;

            var options = language == LanguageNames.CSharp ? CSharpDefaultOptions : VisualBasicDefaultOptions;

            var projectId = ProjectId.CreateNewId(debugName: TestProjectName);

            var refAssemblies = await GetReferenceAssemblies(dotNetVersion).ResolveAsync(language, cancellationToken).ConfigureAwait(false);

            var solution = new AdhocWorkspace()
                           .CurrentSolution
                           .AddProject(projectId, TestProjectName, TestProjectName, language)
                           .AddMetadataReferences(projectId, refAssemblies)
                           .AddMetadataReference(projectId, CodeAnalysisReference)
                           .WithProjectCompilationOptions(projectId, options);

            if (references != null)
            {
                solution = solution.AddMetadataReferences(projectId, references);
            }

            int count = 0;
            foreach (var source in sources)
            {
                var newFileName = $"{fileNamePrefix}{count}.{fileExt}";
                var documentId  = DocumentId.CreateNewId(projectId, debugName: newFileName);
                solution        = solution.AddDocument(documentId, newFileName, SourceText.From(source));
                count++;
            }

            var newProject = solution.GetProject(projectId);
            return newProject;

            //var parseOptions = newProject.ParseOptions.WithFeatures(
            //        newProject.ParseOptions.Features.Concat(
            //            new[] { new KeyValuePair<string, string>("flow-analysis", "true") }));

            //return newProject.WithParseOptions(parseOptions);
        }

        #endregion
    }
}
