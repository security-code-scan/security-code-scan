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

namespace SecurityCodeScan.Tool
{
    internal class Program
    {
        private static async Task<int> Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            var startTime = DateTime.Now;
            var versionString = System.Diagnostics.FileVersionInfo.GetVersionInfo(Assembly.GetEntryAssembly().Location).FileVersion;

            string solutionPath = null;
            string sarifFile = null;
            string excludeList = null;
            string config = null;
            int? threads = null;
            var shouldShowHelp = false;
            var showBanner = true;
            var parsedArgCount = 0;

            var options = new OptionSet {
                { "<>",             "(Required) solution path", r => { solutionPath = r; ++parsedArgCount; } },
                { "e|exclude=",     "(Optional) semicolon delimited list of warnings to exclude", r => { excludeList = r; ++parsedArgCount; } },
                { "x|export=",      "(Optional) SARIF file path", r => { sarifFile = r; ++parsedArgCount; } },
                { "c|config=",      "(Optional) path to additional configuration file", r => { config = r; ++parsedArgCount; } },
                { "p|threads=",     "(Optional) run analysis in parallel (experimental)", (int r) => { threads = r; ++parsedArgCount; } },
                { "n|no-banner",    "(Optional) don't show the banner", r => { showBanner = r == null; ++parsedArgCount; } },
                { "h|help",         "show this message and exit", h => shouldShowHelp = h != null },
            };

            var excludeMap = new HashSet<string>();
            try
            {
                options.Parse(args);
                if (excludeList != null)
                {
                    foreach (var exclusion in excludeList.Split(';'))
                    {
                        excludeMap.Add(exclusion.ToUpperInvariant().Trim());
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
                Console.WriteLine($"  {name} my.sln --export=out.sarif --exclude=SCS1234;SCS2345 --config=setting.yml");
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
                LoadAnalyzers(config, excludeMap, analyzers);

                var count = await GetDiagnostics(versionString, sarifFile, threads, excludeMap, solution, analyzers).ConfigureAwait(false);

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
            HashSet<string> excludeMap,
            Solution solution,
            List<DiagnosticAnalyzer> analyzers)
        {
            var count = 0;
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

                    if(threads.HasValue)
                    {
                        var scanBlock = new TransformBlock<Project, ImmutableArray<Diagnostic>>(async project =>
                        {
                            var compilation = await project.GetCompilationAsync().ConfigureAwait(false);
                            var compilationWithAnalyzers = compilation.WithAnalyzers(analyzers.ToImmutableArray(), project.AnalyzerOptions);
                            var diagnostics = await compilationWithAnalyzers.GetAnalyzerDiagnosticsAsync().ConfigureAwait(false);
                            return diagnostics;
                        },
                        new ExecutionDataflowBlockOptions
                        {
                            MaxDegreeOfParallelism = Debugger.IsAttached ? 1 : threads.Value,
                            EnsureOrdered = false,
                            BoundedCapacity = 32
                        });

                        var resultsBlock = new ActionBlock<ImmutableArray<Diagnostic>>(diagnostics =>
                        {
                            count += LogDiagnostics(diagnostics, excludeMap, descriptors, logger);
                        },
                        new ExecutionDataflowBlockOptions
                        {
                            EnsureOrdered = false
                        });

                        scanBlock.LinkTo(resultsBlock, new DataflowLinkOptions { PropagateCompletion = true });

                        foreach (var project in solution.Projects)
                        {
                            if (!await scanBlock.SendAsync(project).ConfigureAwait(false))
                            {
                                throw new Exception("Thread synchronization error.");
                            }
                        }

                        scanBlock.Complete();
                        await resultsBlock.Completion.ConfigureAwait(false);
                    }
                    else
                    {
                        foreach (var project in solution.Projects)
                        {
                            var compilation = await project.GetCompilationAsync().ConfigureAwait(false);
                            var compilationWithAnalyzers = compilation.WithAnalyzers(analyzers.ToImmutableArray(), project.AnalyzerOptions);
                            var diagnostics = await compilationWithAnalyzers.GetAnalyzerDiagnosticsAsync().ConfigureAwait(false);
                            count += LogDiagnostics(diagnostics, excludeMap, descriptors, logger);
                        }
                    }
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

            return count;
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
