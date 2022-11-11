using Microsoft.Build.Locator;
using Microsoft.CodeAnalysis.MSBuild;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis.Diagnostics;
using System.Collections.Immutable;
using System.Collections.Generic;
using SecurityCodeScan.Analyzers.Taint;
using System.Reflection;
using Microsoft.CodeAnalysis;
using System.Globalization;
using Mono.Options;
using SecurityCodeScan.Config;
using System.Text.RegularExpressions;
using System.Collections.Concurrent;
using Microsoft.CodeAnalysis.Text;
using System.Text;
using System.Threading.Tasks.Dataflow;
using System.Diagnostics;
using DotNet.Globbing;
using SecurityCodeScan.Analyzers.Locale;

namespace SecurityCodeScan.Tool
{
    internal abstract class Runner
    {
        protected int _analysis_warnings = 0;
        protected int _errors = 0;
        protected int _warnings = 0;

        private List<DiagnosticAnalyzer> _analyzers;
        protected Func<ImmutableArray<Diagnostic>, ParsedOptions, ConcurrentDictionary<string, DiagnosticDescriptor>, SarifV2ErrorLogger, (int, int, int)> _logDiagnostics;
        protected ParsedOptions _parsedOptions;
        protected ConcurrentDictionary<string, DiagnosticDescriptor> _descriptors;
        protected SarifV2ErrorLogger _logger;

        public Runner(
            List<DiagnosticAnalyzer> analyzers,
            Func<ImmutableArray<Diagnostic>, ParsedOptions, ConcurrentDictionary<string, DiagnosticDescriptor>, SarifV2ErrorLogger, (int, int, int)> logDiagnostics,
            ParsedOptions parsedOptions,
            ConcurrentDictionary<string, DiagnosticDescriptor> descriptors,
            SarifV2ErrorLogger logger)
        {
            _analyzers = analyzers;
            _logDiagnostics = logDiagnostics;
            _parsedOptions = parsedOptions;
            _descriptors = descriptors;
            _logger = logger;
        }

        public abstract Task Run(Project project);

        public virtual async Task<(int, int, int)> WaitForCompletion()
        {
            return await Task.FromResult((_analysis_warnings, _errors, _warnings)).ConfigureAwait(false);
        }

        protected async Task<ImmutableArray<Diagnostic>> GetDiagnostics(Project project)
        {
            var compilation = await project.GetCompilationAsync().ConfigureAwait(false);
            var compilationWithAnalyzers = compilation.WithAnalyzers(_analyzers.ToImmutableArray(), project.AnalyzerOptions);
            return await compilationWithAnalyzers.GetAllDiagnosticsAsync().ConfigureAwait(false);
        }
    }

    internal class SingleThreadRunner : Runner
    {
        private bool _verbose;

        public SingleThreadRunner(
            bool verbose,
            List<DiagnosticAnalyzer> analyzers,
            Func<ImmutableArray<Diagnostic>, ParsedOptions, ConcurrentDictionary<string, DiagnosticDescriptor>, SarifV2ErrorLogger, (int, int, int)> logDiagnostics,
            ParsedOptions parsedOptions,
            ConcurrentDictionary<string, DiagnosticDescriptor> descriptors,
            SarifV2ErrorLogger logger)
            : base(analyzers, logDiagnostics, parsedOptions, descriptors, logger)
        {
            _verbose = verbose;
        }

        public override async Task Run(Project project)
        {
            if (_verbose)
                Console.WriteLine($"Starting: {project.FilePath}");
            var diagnostics = await GetDiagnostics(project).ConfigureAwait(false);
            (var analysisWarnings, var errors, var warnings) = _logDiagnostics(diagnostics, _parsedOptions, _descriptors, _logger);
            _analysis_warnings += analysisWarnings;
            _errors += errors;
            _warnings += warnings;
        }
    }

    internal class MultiThreadRunner : Runner
    {
        private TransformBlock<Project, ImmutableArray<Diagnostic>> _scanBlock;
        private ActionBlock<ImmutableArray<Diagnostic>>             _resultsBlock;

        public MultiThreadRunner(
            bool verbose,
            List<DiagnosticAnalyzer> analyzers,
            Func<ImmutableArray<Diagnostic>, ParsedOptions, ConcurrentDictionary<string, DiagnosticDescriptor>, SarifV2ErrorLogger, (int, int, int)> logDiagnostics,
            ParsedOptions parsedOptions,
            ConcurrentDictionary<string, DiagnosticDescriptor> descriptors,
            SarifV2ErrorLogger logger,
            int threads)
            : base(analyzers, logDiagnostics, parsedOptions, descriptors, logger)
        {
            _scanBlock = new TransformBlock<Project, ImmutableArray<Diagnostic>>(async project =>
            {
                if (verbose)
                    Console.WriteLine($"Starting: {project.FilePath}");
                return await GetDiagnostics(project).ConfigureAwait(false);
            },
            new ExecutionDataflowBlockOptions
            {
                MaxDegreeOfParallelism = threads,
                EnsureOrdered = false,
                BoundedCapacity = 32
            });

            _resultsBlock = new ActionBlock<ImmutableArray<Diagnostic>>(diagnostics =>
            {
                (var analysisWarnings, var errors, var warnings) = logDiagnostics(diagnostics, _parsedOptions, descriptors, logger);
                _analysis_warnings += analysisWarnings;
                _errors += errors;
                _warnings += warnings;
            },
            new ExecutionDataflowBlockOptions
            {
                EnsureOrdered = false
            });

            _scanBlock.LinkTo(_resultsBlock, new DataflowLinkOptions { PropagateCompletion = true });
        }

        public override async Task Run(Project project)
        {
            if (!await _scanBlock.SendAsync(project).ConfigureAwait(false))
            {
                throw new Exception("Thread synchronization error.");
            }
        }

        public override async Task<(int, int, int)> WaitForCompletion()
        {
            _scanBlock.Complete();
            await _resultsBlock.Completion.ConfigureAwait(false);
            return await base.WaitForCompletion().ConfigureAwait(false);
        }
    }

    internal class ParsedOptions
    {
        public string solutionPath = null;
        public string sarifFile = null;
        public string config = null;
        public int? threads = null;
        public bool shouldShowHelp = false;
        public bool verbose = false;
        public bool ignoreMsBuildErrors = false;
        public bool ignoreCompilerErrors = false;
        public bool showBanner = true;
        public bool cwe = false;
        public bool failOnWarning = false;
        public HashSet<string> excludeWarnings = new HashSet<string>();
        public HashSet<string> includeWarnings = new HashSet<string>();
        public List<Glob> excludeProjects = new List<Glob>();
        public List<Glob> includeProjects = new List<Glob>();
        public string sdkPath = null;

        public OptionSet inputOptions = null;

        public void Parse(string[] args)
        {
            try
            {
                string includeWarningsList = null;
                string excludeWarningsList = null;
                string includeProjectsList = null;
                string excludeProjectsList = null;

                inputOptions = new OptionSet
                {
                    { "<>",             "(Required) solution or project path", r => { solutionPath = r; } },
                    { "w|excl-warn=",   "(Optional) semicolon delimited list of warnings to exclude", r => { excludeWarningsList = r; } },
                    { "incl-warn=",     "(Optional) semicolon delimited list of warnings to include", r => { includeWarningsList = r; } },
                    { "p|excl-proj=",   "(Optional) semicolon delimited list of glob project patterns to exclude", r => { excludeProjectsList = r; } },
                    { "incl-proj=",     "(Optional) semicolon delimited list of glob project patterns to include", r => { includeProjectsList = r; } },
                    { "x|export=",      "(Optional) SARIF file path", r => { sarifFile = r; } },
                    { "c|config=",      "(Optional) path to additional configuration file", r => { config = r; } },
                    { "cwe",            "(Optional) show CWE IDs", r => { cwe = r != null; } },
                    { "t|threads=",     "(Optional) run analysis in parallel (experimental)", (int r) => { threads = r; } },
                    { "sdk-path=",      "(Optional) Path to .NET SDK to use.",  r => { sdkPath = r; } },
                    { "ignore-msbuild-errors", "(Optional) Don't stop on MSBuild errors", r => { ignoreMsBuildErrors = r != null; } },
                    { "ignore-compiler-errors", "(Optional) Don't exit with non-zero code on compilation errors", r => { ignoreCompilerErrors = r != null; } },
                    { "f|fail-any-warn","(Optional) fail on security warnings with non-zero exit code", r => { failOnWarning = r != null; } },
                    { "n|no-banner",    "(Optional) don't show the banner", r => { showBanner = r == null; } },
                    { "v|verbose",      "(Optional) more diagnostic messages", r => { verbose = r != null; } },
                    { "h|?|help",       "show this message and exit", h => shouldShowHelp = h != null },
                };

                inputOptions.Parse(args);

                void SplitBy<T>(bool toUpper, char separator, ICollection<T> outContainer, string delimitedList, Func<string, T> factory)
                {
                    if (delimitedList == null)
                        return;

                    if (toUpper)
                        delimitedList = delimitedList.ToUpperInvariant();

                    foreach (var item in delimitedList.Split(separator))
                    {
                        outContainer.Add(factory(item.Trim()));
                    }
                }

                SplitBy(true, ';', excludeWarnings, excludeWarningsList, x => x);
                SplitBy(true, ';', includeWarnings, includeWarningsList, x => x);
                SplitBy(false, ';', excludeProjects, excludeProjectsList, x => Glob.Parse(x));
                SplitBy(false, ';', includeProjects, includeProjectsList, x => Glob.Parse(x));
            }
            catch
            {
                shouldShowHelp = true;
            }
        }
    }

    internal class Program
    {
        private static readonly Regex ProjRegex = new Regex(@"^.*'([^']+\.[a-z]+)'.*$", RegexOptions.Compiled);

        private static async Task<int> Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            var startTime = DateTime.Now;
            var versionString = FileVersionInfo.GetVersionInfo(Assembly.GetEntryAssembly().Location).FileVersion;

            var parsedOptions = new ParsedOptions();
            parsedOptions.Parse(args);

            if (parsedOptions.showBanner)
            {
                Console.WriteLine($@"
╔═╗┌─┐┌─┐┬ ┬┬─┐┬┌┬┐┬ ┬  ╔═╗┌─┐┌┬┐┌─┐  ╔═╗┌─┐┌─┐┌┐┌
╚═╗├┤ │  │ │├┬┘│ │ └┬┘  ║  │ │ ││├┤   ╚═╗│  ├─┤│││
╚═╝└─┘└─┘└─┘┴└─┴ ┴  ┴   ╚═╝└─┘─┴┘└─┘  ╚═╝└─┘┴ ┴┘└┘

.NET tool by Jaroslav Lobačevski v{versionString}");
                Console.WriteLine("\n");
            }

            if (parsedOptions.includeWarnings.Any() && parsedOptions.excludeWarnings.Any())
            {
                LogError(false, "\nOnly --excl-warn or --incl-warn should be specified.\n");
                parsedOptions.shouldShowHelp = true;
            }

            if (parsedOptions.excludeProjects.Any() && parsedOptions.includeProjects.Any())
            {
                LogError(false, "\nOnly --excl-proj or --incl-proj should be specified.\n");
                parsedOptions.shouldShowHelp = true;
            }

            if (parsedOptions.shouldShowHelp || parsedOptions.solutionPath == null)
            {
                var name = AppDomain.CurrentDomain.FriendlyName;
                Console.WriteLine("\nUsage:\n");
                parsedOptions.inputOptions.WriteOptionDescriptions(Console.Out);
                Console.WriteLine("\nExample:\n");
                Console.WriteLine($"  {name} my.sln/my.csproj --excl-proj=**/*Test*/** --export=out.sarif --excl-warn=SCS1234;SCS2345 --config=setting.yml");
                return 1;
            }

            var returnCode = 0;

            // Attempt to set the version of MSBuild.
            if (parsedOptions.sdkPath != null)
            {
                void ApplyDotNetSdkEnvironmentVariables(string dotNetSdkPath)
                {
                    const string MSBUILD_EXE_PATH = nameof(MSBUILD_EXE_PATH);
                    const string MSBuildExtensionsPath = nameof(MSBuildExtensionsPath);
                    const string MSBuildSDKsPath = nameof(MSBuildSDKsPath);

                    var variables = new Dictionary<string, string>
                    {
                        [MSBUILD_EXE_PATH] = Path.Combine(dotNetSdkPath, "MSBuild.dll"),
                        [MSBuildExtensionsPath] = dotNetSdkPath,
                        [MSBuildSDKsPath] = Path.Combine(dotNetSdkPath, "Sdks")
                    };

                    foreach (var kvp in variables)
                    {
                        Environment.SetEnvironmentVariable(kvp.Key, kvp.Value);
                    }
                }
                ApplyDotNetSdkEnvironmentVariables(parsedOptions.sdkPath);
                // Find and load NuGet assemblies if msbuildPath is in a VS installation
                string nugetPath = Path.GetFullPath(Path.Combine(parsedOptions.sdkPath, "..", "..", "..", "Common7", "IDE", "CommonExtensions", "Microsoft", "NuGet"));
                if (Directory.Exists(nugetPath))
                {
                    MSBuildLocator.RegisterMSBuildPath(new string[] { parsedOptions.sdkPath, nugetPath });
                }
                else
                {
                    MSBuildLocator.RegisterMSBuildPath(parsedOptions.sdkPath);
                }
            }
            else
            {
                var visualStudioInstances = MSBuildLocator.QueryVisualStudioInstances().ToArray();
                var instance = visualStudioInstances.OrderByDescending(x => x.Version).FirstOrDefault();
                if (instance != null)
                {
                    if (parsedOptions.verbose)
                        Console.WriteLine($"Using MSBuild at '{instance.MSBuildPath}' to load projects.");
                    MSBuildLocator.RegisterInstance(instance);
                }
                else
                {
                    Console.WriteLine($"Failed to find MSBuild path. Try specifying `sdk-path=` as a command line parameter.");
                    return 1;
                }
            }

            var properties = new Dictionary<string, string>() { { "AdditionalFileItemNames", "$(AdditionalFileItemNames);Content" } };

            var solutionDirectory = Path.GetDirectoryName(parsedOptions.solutionPath) + Path.DirectorySeparatorChar;

            using (var workspace = MSBuildWorkspace.Create(properties))
            {
                // Print message for WorkspaceFailed event to help diagnosing project load failures.
                workspace.WorkspaceFailed += (o, e) =>
                {
                    if (e.Diagnostic.Message.Contains(".shproj") || e.Diagnostic.Message.Contains(".sqlproj") || e.Diagnostic.Message.Contains(".fsproj"))
                    {
                        return;
                    }

                    var kind = e.Diagnostic.Kind;

                    if (kind == WorkspaceDiagnosticKind.Warning && !parsedOptions.verbose)
                        return;

                    var match = ProjRegex.Matches(e.Diagnostic.Message);
                    if (match.Count == 1)
                    {
                        var path = match[0].Groups[1].Value;
                        if (path.StartsWith(solutionDirectory))
                            path = match[0].Groups[1].Value.Remove(0, solutionDirectory.Length);

                        if ((parsedOptions.includeProjects.Any() && !parsedOptions.includeProjects.Any(x => x.IsMatch(path))) ||
                            parsedOptions.excludeProjects.Any(x => x.IsMatch(path)))
                        {
                            return;
                        }
                    }

                    LogError(kind == WorkspaceDiagnosticKind.Failure, e.Diagnostic.Message);

                    if (kind == WorkspaceDiagnosticKind.Failure && !parsedOptions.ignoreMsBuildErrors)
                        returnCode = 2;
                };

                List<Project> projects;
                if (parsedOptions.solutionPath.EndsWith(".sln"))
                {
                    Console.WriteLine($"Loading solution '{parsedOptions.solutionPath}'");
                    // Attach progress reporter so we print projects as they are loaded.
                    var solution = await workspace.OpenSolutionAsync(parsedOptions.solutionPath, new ConsoleProgressReporter(parsedOptions.verbose)).ConfigureAwait(false);
                    projects = new List<Project>(solution.Projects.Count());

                    foreach (var project in solution.Projects)
                    {
                        if (project.FilePath.EndsWith(".shproj") || project.FilePath.EndsWith(".sqlproj") || project.FilePath.EndsWith(".fsproj"))
                        {
                            Console.WriteLine($"Skipped: {project.FilePath} excluded from analysis");
                            continue;
                        }

                        var path = project.FilePath;
                        if (path.StartsWith(solutionDirectory))
                            path = path.Remove(0, solutionDirectory.Length);

                        if ((parsedOptions.includeProjects.Any() && !parsedOptions.includeProjects.Any(x => x.IsMatch(path))) ||
                            parsedOptions.excludeProjects.Any(x => x.IsMatch(path)))
                        {
                            Console.WriteLine($"Skipped: {project.FilePath} excluded from analysis");
                            continue;
                        }

                        projects.Add(project);
                    }
                }
                else
                {
                    // Attach progress reporter so we print projects as they are loaded.
                    projects = new List<Project>() { await workspace.OpenProjectAsync(parsedOptions.solutionPath, new ConsoleProgressReporter(parsedOptions.verbose)).ConfigureAwait(false) };
                }

                Console.WriteLine($"Finished loading solution '{parsedOptions.solutionPath}'");
                if (returnCode != 0)
                    return returnCode;

                var analyzers = new List<DiagnosticAnalyzer>();
                LoadAnalyzers(parsedOptions, analyzers);

                (var count, var errors, _) = await GetDiagnostics(parsedOptions, versionString, projects, analyzers).ConfigureAwait(false);

                var elapsed = DateTime.Now - startTime;
                if (parsedOptions.verbose)
                    Console.WriteLine($@"Completed in {elapsed:hh\:mm\:ss}");
                Console.WriteLine($@"Found {count} security issues.");

                if (errors > 0 && !parsedOptions.ignoreCompilerErrors)
                {
                    if (parsedOptions.verbose)
                        Console.WriteLine($@"Exiting with 2 due to compilation errors.");
                    return 2;
                }

                if (parsedOptions.failOnWarning && count > 0)
                {
                    if (parsedOptions.verbose)
                        Console.WriteLine($@"Exiting with 1 due to warnings.");
                    return 1;
                }

                return 0;
            }
        }

        private static void LogError(bool error, string msg)
        {
            if (error)
                Console.ForegroundColor = ConsoleColor.Red;
            else
                Console.ForegroundColor = ConsoleColor.Yellow;

            Console.Error.WriteLine(msg);
            Console.ForegroundColor = ConsoleColor.White;
        }

        private static async Task<(int, int, int)> GetDiagnostics(
            ParsedOptions parsedOptions,
            string versionString,
            IEnumerable<Project> projects,
            List<DiagnosticAnalyzer> analyzers)
        {
            Stream stream = null;
            SarifV2ErrorLogger logger = null;
            try
            {
                if (parsedOptions.sarifFile != null)
                {
                    if (File.Exists(parsedOptions.sarifFile))
                        File.Delete(parsedOptions.sarifFile);

                    stream = File.Open(parsedOptions.sarifFile, FileMode.CreateNew);
                }

                try
                {
                    if (stream != null)
                    {
                        var v = new Version(versionString);
                        logger = new SarifV2ErrorLogger(stream, "Security Code Scan", versionString, new Version($"{v.Major}.{v.Minor}.{v.Build}.0"), CultureInfo.CurrentCulture);
                    }

                    var descriptors = new ConcurrentDictionary<string, DiagnosticDescriptor>();

                    Runner runner;
                    if (parsedOptions.threads.HasValue)
                    {
                        runner = new MultiThreadRunner(parsedOptions.verbose, analyzers, LogDiagnostics, parsedOptions, descriptors, logger, Debugger.IsAttached ? 1 : parsedOptions.threads.Value);
                    }
                    else
                    {
                        runner = new SingleThreadRunner(parsedOptions.verbose, analyzers, LogDiagnostics, parsedOptions, descriptors, logger);
                    }

                    foreach (var project in projects)
                    {
                        await runner.Run(project).ConfigureAwait(false);
                    }

                    return await runner.WaitForCompletion().ConfigureAwait(false);
                }
                finally
                {
                    if (logger != null)
                        logger.Dispose();
                }
            }
            finally
            {
                if (stream != null)
                    stream.Close();
            }
        }

        private static void LoadAnalyzers(ParsedOptions parsedOptions, List<DiagnosticAnalyzer> analyzers)
        {
            var types = typeof(PathTraversalTaintAnalyzer).GetTypeInfo().Assembly.DefinedTypes;
            AdditionalConfiguration.Path = parsedOptions.config;

            foreach (var type in types)
            {
                if (type.IsAbstract)
                    continue;

                var secAttributes = type.GetCustomAttributes(typeof(DiagnosticAnalyzerAttribute), false)
                                            .Cast<DiagnosticAnalyzerAttribute>();
                foreach (var attribute in secAttributes)
                {
                    var analyzer = (DiagnosticAnalyzer)Activator.CreateInstance(type.AsType());

                    // First pass. Analyzers may support more than one diagnostic.
                    // If all supported diagnostics are excluded, don't load the analyzer - save CPU time.
                    if (parsedOptions.includeWarnings.Any() && !analyzer.SupportedDiagnostics.Any(x => parsedOptions.includeWarnings.Contains(x.Id)))
                        continue;
                    else if (analyzer.SupportedDiagnostics.All(x => parsedOptions.excludeWarnings.Contains(x.Id)))
                        continue;

                    analyzers.Add(analyzer);
                    break;
                }
            }
        }

        private static (int, int, int) LogDiagnostics(
            ImmutableArray<Diagnostic> diagnostics,
            ParsedOptions parsedOptions,
            ConcurrentDictionary<string, DiagnosticDescriptor> descriptors,
            SarifV2ErrorLogger logger)
        {
            var analysis_issues = 0;
            var errors = 0;
            var warnings = 0;

            foreach (var diag in diagnostics)
            {
                var d = diag;
                if (d.Severity == DiagnosticSeverity.Hidden || d.Severity == DiagnosticSeverity.Info)
                    continue;

                if (!d.Id.StartsWith("SCS"))
                {
                    LogError(d.Severity == DiagnosticSeverity.Error, d.ToString());
                    if (d.Severity == DiagnosticSeverity.Error)
                        ++errors;
                    else
                        ++warnings;

                    continue;
                }

                // Second pass. Analyzers may support more than one diagnostic.
                // Filter excluded diagnostics.
                if (parsedOptions.excludeWarnings.Contains(d.Id))
                    continue;
                else if (parsedOptions.includeWarnings.Any() && !parsedOptions.includeWarnings.Contains(d.Id))
                    continue;

                ++analysis_issues;

                // fix locations for diagnostics from additional files
                if (d.Location == Location.None)
                {
                    var match = WebConfigMessageRegex.Matches(d.GetMessage());
                    if (match.Count > 1)
                        throw new Exception("Unexpected");

                    if (match.Count != 0)
                    {
                        if (!descriptors.TryGetValue(d.Id, out var descr))
                        {
                            var msg = $"{match[0].Groups[1].Value}.";
                            descr = new DiagnosticDescriptor(d.Id, msg, msg, d.Descriptor.Category, d.Severity, d.Descriptor.IsEnabledByDefault);
                            descriptors.TryAdd(d.Id, descr);
                        }

                        var line = new LinePosition(int.Parse(match[0].Groups[3].Value) - 1, 0);
                        var capture = match[0].Groups[4].Value.TrimEnd('.');
                        d = Diagnostic.Create(descr, Location.Create(match[0].Groups[2].Value, new TextSpan(0, capture.Length), new LinePositionSpan(line, line)));
                    }
                }

                if (parsedOptions.cwe)
                {
                    var cwe = LocaleUtil.GetLocalString($"{d.Id}_cwe");
                    var msg = d.ToString();
                    if (!cwe.ToString().StartsWith("??")) // overall all IDs must have corresponding CWE, but some are special like SCS0000
                    {
                        msg = msg.Replace($"{d.Id}:", $"{d.Id}: CWE-{cwe}:");
                    }

                    Console.WriteLine(msg);
                }
                else
                {
                    Console.WriteLine(d.ToString());
                }

                if (logger != null)
                    logger.LogDiagnostic(d, null);
            }

            return (analysis_issues, errors, warnings);
        }

        private static readonly Regex WebConfigMessageRegex = new Regex(@"(.*) in (.*)\((\d+)\): (.*)", RegexOptions.Compiled);

        private class ConsoleProgressReporter : IProgress<ProjectLoadProgress>
        {
            private bool _verbose;

            public ConsoleProgressReporter(bool verbose)
            {
                _verbose = verbose;
            }

            public void Report(ProjectLoadProgress loadProgress)
            {
                if (!_verbose && loadProgress.Operation != ProjectLoadOperation.Resolve)
                    return;

                var projectDisplay = Path.GetFileName(loadProgress.FilePath);
                if (loadProgress.TargetFramework != null)
                {
                    projectDisplay += $" ({loadProgress.TargetFramework})";
                }

                Console.WriteLine($"{loadProgress.Operation,-15} {loadProgress.ElapsedTime,-15:m\\:ss\\.fffffff} {projectDisplay}");
            }
        }
    }
}
