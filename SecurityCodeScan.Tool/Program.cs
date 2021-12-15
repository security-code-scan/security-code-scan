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
        protected int _count;
        private List<DiagnosticAnalyzer> _analyzers;
        protected Func<ImmutableArray<Diagnostic>, ParsedOptions, ConcurrentDictionary<string, DiagnosticDescriptor>, SarifV2ErrorLogger, int> _logDiagnostics;
        protected ParsedOptions _parsedOptions;
        protected ConcurrentDictionary<string, DiagnosticDescriptor> _descriptors;
        protected SarifV2ErrorLogger _logger;

        public Runner(
            List<DiagnosticAnalyzer> analyzers,
            Func<ImmutableArray<Diagnostic>, ParsedOptions, ConcurrentDictionary<string, DiagnosticDescriptor>, SarifV2ErrorLogger, int> logDiagnostics,
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

        public virtual async Task<int> WaitForCompletion()
        {
            return await Task.FromResult(_count).ConfigureAwait(false);
        }

        protected async Task<ImmutableArray<Diagnostic>> GetDiagnostics(Project project)
        {
            var compilation = await project.GetCompilationAsync().ConfigureAwait(false);
            var compilationWithAnalyzers = compilation.WithAnalyzers(_analyzers.ToImmutableArray(), project.AnalyzerOptions);
            return await compilationWithAnalyzers.GetAnalyzerDiagnosticsAsync().ConfigureAwait(false);
        }
    }

    internal class SingleThreadRunner : Runner
    {
        private bool _verbose;

        public SingleThreadRunner(
            bool verbose,
            List<DiagnosticAnalyzer> analyzers,
            Func<ImmutableArray<Diagnostic>, ParsedOptions, ConcurrentDictionary<string, DiagnosticDescriptor>, SarifV2ErrorLogger, int> logDiagnostics,
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
            _count += _logDiagnostics(diagnostics, _parsedOptions, _descriptors, _logger);
        }
    }

    internal class MultiThreadRunner : Runner
    {
        private TransformBlock<Project, ImmutableArray<Diagnostic>> _scanBlock;
        private ActionBlock<ImmutableArray<Diagnostic>>             _resultsBlock;

        public MultiThreadRunner(
            bool verbose,
            List<DiagnosticAnalyzer> analyzers,
            Func<ImmutableArray<Diagnostic>, ParsedOptions, ConcurrentDictionary<string, DiagnosticDescriptor>, SarifV2ErrorLogger, int> logDiagnostics,
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
                _count += logDiagnostics(diagnostics, _parsedOptions, descriptors, logger);
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

        public override async Task<int> WaitForCompletion()
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
        public bool showBanner = true;
        public bool cwe = false;
        public HashSet<string> excludeWarnings = new HashSet<string>();
        public HashSet<string> includeWarnings = new HashSet<string>();
        public List<Glob> excludeProjects = new List<Glob>();
        public List<Glob> includeProjects = new List<Glob>();

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
                    { "<>",             "(Required) solution path", r => { solutionPath = r; } },
                    { "w|excl-warn=",   "(Optional) semicolon delimited list of warnings to exclude", r => { excludeWarningsList = r; } },
                    { "incl-warn=",     "(Optional) semicolon delimited list of warnings to include", r => { includeWarningsList = r; } },
                    { "p|excl-proj=",   "(Optional) semicolon delimited list of glob project patterns to exclude", r => { excludeProjectsList = r; } },
                    { "incl-proj=",     "(Optional) semicolon delimited list of glob project patterns to include", r => { includeProjectsList = r; } },
                    { "x|export=",      "(Optional) SARIF file path", r => { sarifFile = r; } },
                    { "c|config=",      "(Optional) path to additional configuration file", r => { config = r; } },
                    { "cwe",            "(Optional) show CWE IDs", r => { cwe = r != null; } },
                    { "t|threads=",     "(Optional) run analysis in parallel (experimental)", (int r) => { threads = r; } },
                    { "n|no-banner",    "(Optional) don't show the banner", r => { showBanner = r == null; } },
                    { "v|verbose",      "(Optional) more diagnostic messages", r => { verbose = r != null; } },
                    { "ignore-msbuild-errors", "(Optional) Don't stop on MSBuild errors", r => { ignoreMsBuildErrors = r != null; } },
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
                Console.WriteLine($"  {name} my.sln --excl-proj=**/*Test*/** --export=out.sarif --excl-warn=SCS1234;SCS2345 --config=setting.yml");
                return 1;
            }

            var returnCode = 0;

            // Attempt to set the version of MSBuild.
            var visualStudioInstances = MSBuildLocator.QueryVisualStudioInstances().ToArray();
            var instance = visualStudioInstances.OrderByDescending(x => x.Version).FirstOrDefault();
            if (instance != null)
            {
                if (parsedOptions.verbose)
                    Console.WriteLine($"Using MSBuild at '{instance.MSBuildPath}' to load projects.");
                MSBuildLocator.RegisterInstance(instance);
            }

            var properties = new Dictionary<string, string>() { { "AdditionalFileItemNames", "$(AdditionalFileItemNames);Content" } };

            using (var workspace = MSBuildWorkspace.Create(properties))
            {
                // Print message for WorkspaceFailed event to help diagnosing project load failures.
                workspace.WorkspaceFailed += (o, e) =>
                {
                    var kind = e.Diagnostic.Kind;

                    if (kind == WorkspaceDiagnosticKind.Warning && !parsedOptions.verbose)
                        return;

                    LogError(kind == WorkspaceDiagnosticKind.Failure, e.Diagnostic.Message);

                    if (kind == WorkspaceDiagnosticKind.Failure && !parsedOptions.ignoreMsBuildErrors)
                        returnCode = 2;
                };

                Console.WriteLine($"Loading solution '{parsedOptions.solutionPath}'");
                // Attach progress reporter so we print projects as they are loaded.
                var solution = await workspace.OpenSolutionAsync(parsedOptions.solutionPath, new ConsoleProgressReporter(parsedOptions.verbose)).ConfigureAwait(false);
                Console.WriteLine($"Finished loading solution '{parsedOptions.solutionPath}'");
                if (returnCode != 0)
                    return returnCode;

                var analyzers = new List<DiagnosticAnalyzer>();
                LoadAnalyzers(parsedOptions, analyzers);

                var count = await GetDiagnostics(parsedOptions, versionString, solution, analyzers).ConfigureAwait(false);

                var elapsed = DateTime.Now - startTime;
                Console.WriteLine($@"Completed in {elapsed:hh\:mm\:ss}");
                Console.WriteLine($@"{count} warnings");

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

        private static async Task<int> GetDiagnostics(
            ParsedOptions parsedOptions,
            string versionString,
            Solution solution,
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

                    var solutionPath = Path.GetDirectoryName(solution.FilePath) + Path.DirectorySeparatorChar;
                    foreach (var project in solution.Projects)
                    {
                        var projectPath = project.FilePath;
                        if (projectPath.StartsWith(solutionPath))
                            projectPath = projectPath.Remove(0, solutionPath.Length);



                        if ((parsedOptions.includeProjects.Any() && !parsedOptions.includeProjects.Any(x => x.IsMatch(projectPath))) ||
                            parsedOptions.excludeProjects.Any(x => x.IsMatch(projectPath)))
                        {
                            Console.WriteLine($"Skipped: {project.FilePath} excluded from analysis");
                            continue;
                        }

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

        private static int LogDiagnostics(
            ImmutableArray<Diagnostic> diagnostics,
            ParsedOptions parsedOptions,
            ConcurrentDictionary<string, DiagnosticDescriptor> descriptors,
            SarifV2ErrorLogger logger)
        {
            var count = 0;

            foreach (var diag in diagnostics)
            {
                var d = diag;
                // Second pass. Analyzers may support more than one diagnostic.
                // Filter excluded diagnostics.
                if (parsedOptions.excludeWarnings.Contains(d.Id))
                    continue;
                else if (parsedOptions.includeWarnings.Any() && !parsedOptions.includeWarnings.Contains(d.Id))
                    continue;

                ++count;

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

                    Console.WriteLine($"Found: {msg}");
                }
                else
                {
                    Console.WriteLine($"Found: {d}");
                }

                if (logger != null)
                    logger.LogDiagnostic(d, null);
            }

            return count;
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
