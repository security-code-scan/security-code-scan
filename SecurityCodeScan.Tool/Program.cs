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

namespace SecurityCodeScan.Tool
{
    internal abstract class Runner
    {
        protected int _count;
        private List<DiagnosticAnalyzer> _analyzers;
        protected Func<ImmutableArray<Diagnostic>, HashSet<string>, ConcurrentDictionary<string, DiagnosticDescriptor>, SarifV2ErrorLogger, int> _logDiagnostics;
        protected HashSet<string> _excludeWarningsMap;
        protected ConcurrentDictionary<string, DiagnosticDescriptor> _descriptors;
        protected SarifV2ErrorLogger _logger;

        public Runner(
            List<DiagnosticAnalyzer> analyzers,
            Func<ImmutableArray<Diagnostic>, HashSet<string>, ConcurrentDictionary<string, DiagnosticDescriptor>, SarifV2ErrorLogger, int> logDiagnostics,
            HashSet<string> excludeWarningsMap,
            ConcurrentDictionary<string, DiagnosticDescriptor> descriptors,
            SarifV2ErrorLogger logger)
        {
            _analyzers = analyzers;
            _logDiagnostics = logDiagnostics;
            _excludeWarningsMap = excludeWarningsMap;
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
        public SingleThreadRunner(
            List<DiagnosticAnalyzer> analyzers,
            Func<ImmutableArray<Diagnostic>, HashSet<string>, ConcurrentDictionary<string, DiagnosticDescriptor>, SarifV2ErrorLogger, int> logDiagnostics,
            HashSet<string> excludeWarningsMap,
            ConcurrentDictionary<string, DiagnosticDescriptor> descriptors,
            SarifV2ErrorLogger logger)
            : base(analyzers, logDiagnostics, excludeWarningsMap, descriptors, logger)
        {
        }

        public override async Task Run(Project project)
        {
            var diagnostics = await GetDiagnostics(project).ConfigureAwait(false);
            _count += _logDiagnostics(diagnostics, _excludeWarningsMap, _descriptors, _logger);
        }
    }

    internal class MultiThreadRunner : Runner
    {
        private TransformBlock<Project, ImmutableArray<Diagnostic>> _scanBlock;
        private ActionBlock<ImmutableArray<Diagnostic>>             _resultsBlock;

        public MultiThreadRunner(
            List<DiagnosticAnalyzer> analyzers,
            Func<ImmutableArray<Diagnostic>, HashSet<string>, ConcurrentDictionary<string, DiagnosticDescriptor>, SarifV2ErrorLogger, int> logDiagnostics,
            HashSet<string> excludeWarningsMap,
            ConcurrentDictionary<string, DiagnosticDescriptor> descriptors,
            SarifV2ErrorLogger logger,
            int threads)
            : base(analyzers, logDiagnostics, excludeWarningsMap, descriptors, logger)
        {
            _scanBlock = new TransformBlock<Project, ImmutableArray<Diagnostic>>(async project =>
            {
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
                _count += logDiagnostics(diagnostics, excludeWarningsMap, descriptors, logger);
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

    internal class Program
    {
        private static async Task<int> Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            var startTime = DateTime.Now;
            var versionString = FileVersionInfo.GetVersionInfo(Assembly.GetEntryAssembly().Location).FileVersion;

            string solutionPath = null;
            string sarifFile = null;
            string config = null;
            int? threads = null;
            var shouldShowHelp = false;
            var showBanner = true;
            var parsedArgCount = 0;
            var excludeWarningsMap = new HashSet<string>();
            var excludeProjectsMap = new List<Glob>();

            OptionSet options = null;
            try
            {
                string excludeWarningsList = null;
                string excludeProjectsList = null;

                options = new OptionSet {
                    { "<>",             "(Required) solution path", r => { solutionPath = r; ++parsedArgCount; } },
                    { "w|excl-warn=",   "(Optional) semicolon delimited list of warnings to exclude", r => { excludeWarningsList = r; ++parsedArgCount; } },
                    { "p|excl-proj=",   "(Optional) semicolon delimited list of glob project patterns to exclude", r => { excludeProjectsList = r; ++parsedArgCount; } },
                    { "x|export=",      "(Optional) SARIF file path", r => { sarifFile = r; ++parsedArgCount; } },
                    { "c|config=",      "(Optional) path to additional configuration file", r => { config = r; ++parsedArgCount; } },
                    { "t|threads=",     "(Optional) run analysis in parallel (experimental)", (int r) => { threads = r; ++parsedArgCount; } },
                    { "n|no-banner",    "(Optional) don't show the banner", r => { showBanner = r == null; ++parsedArgCount; } },
                    { "h|help",         "show this message and exit", h => shouldShowHelp = h != null },
                };

                options.Parse(args);
                if (excludeWarningsList != null)
                {
                    foreach (var exclusion in excludeWarningsList.Split(';'))
                    {
                        excludeWarningsMap.Add(exclusion.ToUpperInvariant().Trim());
                    }
                }

                if (excludeProjectsList != null)
                {
                    foreach (var exclusion in excludeProjectsList.Split(';'))
                    {
                        excludeProjectsMap.Add(Glob.Parse(exclusion.Trim()));
                    }
                }
            }
            catch
            {
                shouldShowHelp = true;
            }

            if (showBanner)
            {
                Console.WriteLine($@"
╔═╗┌─┐┌─┐┬ ┬┬─┐┬┌┬┐┬ ┬  ╔═╗┌─┐┌┬┐┌─┐  ╔═╗┌─┐┌─┐┌┐┌
╚═╗├┤ │  │ │├┬┘│ │ └┬┘  ║  │ │ ││├┤   ╚═╗│  ├─┤│││
╚═╝└─┘└─┘└─┘┴└─┴ ┴  ┴   ╚═╝└─┘─┴┘└─┘  ╚═╝└─┘┴ ┴┘└┘

.NET tool by Jaroslav Lobačevski v{versionString}");
                Console.WriteLine("\n");
            }

            if (shouldShowHelp || solutionPath == null || parsedArgCount != args.Length)
            {
                var name = AppDomain.CurrentDomain.FriendlyName;
                Console.WriteLine("\nUsage:\n");
                options.WriteOptionDescriptions(Console.Out);
                Console.WriteLine("\nExample:\n");
                Console.WriteLine($"  {name} my.sln --excl-proj=**/*Test*/** --export=out.sarif --exclude=SCS1234;SCS2345 --config=setting.yml");
                return 1;
            }

            var returnCode = 0;

            // Attempt to set the version of MSBuild.
            var visualStudioInstances = MSBuildLocator.QueryVisualStudioInstances().ToArray();
            var instance = visualStudioInstances.OrderByDescending(x => x.Version).First();

            Console.WriteLine($"Using MSBuild at '{instance.MSBuildPath}' to load projects.");
            MSBuildLocator.RegisterInstance(instance);

            var properties = new Dictionary<string, string>() { { "AdditionalFileItemNames", "$(AdditionalFileItemNames);Content" } };

            using (var workspace = MSBuildWorkspace.Create(properties))
            {
                // Print message for WorkspaceFailed event to help diagnosing project load failures.
                workspace.WorkspaceFailed += (o, e) =>
                {
                    if (e.Diagnostic.Kind == WorkspaceDiagnosticKind.Failure)
                        Console.ForegroundColor = ConsoleColor.Red;
                    else
                        Console.ForegroundColor = ConsoleColor.Yellow;

                    Console.Error.WriteLine(e.Diagnostic.Message);
                    Console.ForegroundColor = ConsoleColor.White;
                    returnCode = 2;
                };

                Console.WriteLine($"Loading solution '{solutionPath}'");

                // Attach progress reporter so we print projects as they are loaded.
                var solution = await workspace.OpenSolutionAsync(solutionPath, new ConsoleProgressReporter()).ConfigureAwait(false);
                Console.WriteLine($"Finished loading solution '{solutionPath}'");

                var analyzers = new List<DiagnosticAnalyzer>();
                LoadAnalyzers(config, excludeWarningsMap, analyzers);

                var count = await GetDiagnostics(versionString, sarifFile, threads, excludeWarningsMap, excludeProjectsMap, solution, analyzers).ConfigureAwait(false);

                var elapsed = DateTime.Now - startTime;
                Console.WriteLine($@"Completed in {elapsed:hh\:mm\:ss}");
                Console.WriteLine($@"{count} warnings");

                return returnCode;
            }
        }

        private static async Task<int> GetDiagnostics(
            string versionString,
            string sarifFile,
            int? threads,
            HashSet<string> excludeWarningsMap,
            List<Glob> excludeProjectsList,
            Solution solution,
            List<DiagnosticAnalyzer> analyzers)
        {
            Stream stream = null;
            SarifV2ErrorLogger logger = null;
            try
            {
                if (sarifFile != null)
                {
                    if (File.Exists(sarifFile))
                        File.Delete(sarifFile);

                    stream = File.Open(sarifFile, FileMode.CreateNew);
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
                    if (threads.HasValue)
                    {
                        runner = new MultiThreadRunner(analyzers, LogDiagnostics, excludeWarningsMap, descriptors, logger, Debugger.IsAttached ? 1 : threads.Value);
                    }
                    else
                    {
                        runner = new SingleThreadRunner(analyzers, LogDiagnostics, excludeWarningsMap, descriptors, logger);
                    }

                    foreach (var project in solution.Projects)
                    {
                        var solutionPath = Path.GetDirectoryName(solution.FilePath) + Path.DirectorySeparatorChar;
                        var projectPath = project.FilePath;
                        if (projectPath.StartsWith(solutionPath))
                            projectPath = projectPath.Remove(0, solutionPath.Length);

                        if (excludeProjectsList.Any(x => x.IsMatch(projectPath)))
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

        private static void LoadAnalyzers(string config, HashSet<string> excludeMap, List<DiagnosticAnalyzer> analyzers)
        {
            var types = typeof(PathTraversalTaintAnalyzer).GetTypeInfo().Assembly.DefinedTypes;
            AdditionalConfiguration.Path = config;

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
                    if (analyzer.SupportedDiagnostics.All(x => excludeMap.Contains(x.Id)))
                        continue;

                    analyzers.Add(analyzer);
                    break;
                }
            }
        }

        private static int LogDiagnostics(
            ImmutableArray<Diagnostic> diagnostics,
            HashSet<string> excludeMap,
            ConcurrentDictionary<string, DiagnosticDescriptor> descriptors,
            SarifV2ErrorLogger logger)
        {
            var count = 0;

            foreach (var diag in diagnostics)
            {
                var d = diag;
                // Second pass. Analyzers may support more than one diagnostic.
                // Filter excluded diagnostics.
                if (excludeMap.Contains(d.Id))
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

                Console.WriteLine($"Found: {d}");
                if (logger != null)
                    logger.LogDiagnostic(d, null);
            }

            return count;
        }

        private static readonly Regex WebConfigMessageRegex = new Regex(@"(.*) in (.*)\((\d+)\): (.*)", RegexOptions.Compiled);

        private class ConsoleProgressReporter : IProgress<ProjectLoadProgress>
        {
            public void Report(ProjectLoadProgress loadProgress)
            {
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
