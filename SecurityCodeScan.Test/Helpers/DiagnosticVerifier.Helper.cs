using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
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
        private class ReferenceAssemblies
        {
            private readonly        string                                   AssemblyPath;
            private readonly        Dictionary<string, MetadataReference>    Assemblies = new Dictionary<string, MetadataReference>();
            private static readonly Dictionary<Version, ReferenceAssemblies> Cache      = new Dictionary<Version, ReferenceAssemblies>();

            private ReferenceAssemblies(Version dotNetVersion)
            {
                AssemblyPath = BuildPath(dotNetVersion);
            }

            private string BuildPath(Version dotNetVersion)
            {
                var build   = dotNetVersion.Build != -1 ? $".{dotNetVersion.Build}" : "";
                var version = $"v{dotNetVersion.Major}.{dotNetVersion.Minor}{build}";
                var programFiles = Environment.Is64BitOperatingSystem
                                       ? Environment.SpecialFolder.ProgramFilesX86
                                       : Environment.SpecialFolder.ProgramFiles;

                return $@"{Environment.GetFolderPath(programFiles)}\Reference Assemblies\Microsoft\Framework\.NETFramework\{version}\";
            }

            public MetadataReference GetMetadata(string assemblyName)
            {
                MetadataReference ret;
                string            name = assemblyName.ToUpperInvariant();
                lock (Assemblies)
                {
                    if (Assemblies.TryGetValue(name, out ret))
                        return ret;

                    ret = MetadataReference.CreateFromFile($"{AssemblyPath}{name}");
                    Assemblies.Add(name, ret);
                }
                return ret;
            }

            public static ReferenceAssemblies GetCache(Version dotNetVersion)
            {
                ReferenceAssemblies ret;
                lock (Cache)
                {
                    if (Cache.TryGetValue(dotNetVersion, out ret))
                        return ret;

                    ret = new ReferenceAssemblies(dotNetVersion);
                    Cache.Add(dotNetVersion, ret);
                }
                return ret;
            }
        }

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

            var documents = GetDocuments(sources, dotNetVersion, language, references);
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
                var compilation              = await project.GetCompilationAsync(cancellationToken).ConfigureAwait(false);
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
        private static IEnumerable<Document> GetDocuments(string[]                       sources,
                                                          Version                        dotNetVersion,
                                                          string                         language,
                                                          IEnumerable<MetadataReference> references = null)
        {
            if (language != LanguageNames.CSharp && language != LanguageNames.VisualBasic)
            {
                throw new ArgumentException("Unsupported Language");
            }

            var project   = CreateProject(sources, dotNetVersion, language, references);
            return project.Documents;
        }

        /// <summary>
        /// Create a Document from a string through creating a project that contains it.
        /// </summary>
        /// <param name="source">Classes in the form of a string</param>
        /// <param name="language">The language the source code is in</param>
        /// <returns>A Document created from the source string</returns>
        protected static Document CreateDocument(string                         source,
                                                 Version                        dotNetVersion,
                                                 string                         language   = LanguageNames.CSharp,
                                                 IEnumerable<MetadataReference> references = null)
        {
            return CreateProject(new[] { source }, dotNetVersion, language, references).Documents.First();
        }

        /// <summary>
        /// Create a project using the inputted strings as sources.
        /// </summary>
        /// <param name="sources">Classes in the form of strings</param>
        /// <param name="language">The language the source code is in</param>
        /// <returns>A Project created out of the Documents created from the source strings</returns>
        private static Project CreateProject(string[]                           sources,
                                             Version                            dotNetVersion,
                                             string                             language        = LanguageNames.CSharp,
                                             IEnumerable<MetadataReference>     references      = null)
        {
            string fileNamePrefix = DefaultFilePathPrefix;
            string fileExt        = language == LanguageNames.CSharp ? CSharpDefaultFileExt : VisualBasicDefaultExt;

            var options = language == LanguageNames.CSharp ? CSharpDefaultOptions : VisualBasicDefaultOptions;

            var projectId = ProjectId.CreateNewId(debugName: TestProjectName);

            var refAssemblies = ReferenceAssemblies.GetCache(dotNetVersion ?? new Version(4, 5, 2));

            var solution = new AdhocWorkspace()
                           .CurrentSolution
                           .AddProject(projectId, TestProjectName, TestProjectName, language)
                           .AddMetadataReference(projectId, refAssemblies.GetMetadata("mscorlib.dll"))
                           .AddMetadataReference(projectId, refAssemblies.GetMetadata("System.Core.dll"))
                           .AddMetadataReference(projectId, refAssemblies.GetMetadata("System.dll"))
                           .AddMetadataReference(projectId, refAssemblies.GetMetadata("System.Xml.dll"))
                           .AddMetadataReference(projectId, refAssemblies.GetMetadata("System.Data.dll"))
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

            return solution.GetProject(projectId);
        }

        #endregion
    }
}
