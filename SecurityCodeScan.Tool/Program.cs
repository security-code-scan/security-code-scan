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
            var shouldShowHelp = false;
            var showBanner = true;
            var parsedArgCount = 0;

            var options = new OptionSet {
                { "<>", "solution path", r => { solutionPath = r; ++parsedArgCount; } },
                { "e|exclude=", "semicolon delimited list of SCS warnings to exclude", r => { excludeList = r; ++parsedArgCount; } },
                { "x|export=", "SARIF file path", r => { sarifFile = r; ++parsedArgCount; } },
                { "c|config=", "additional Security Code Scan configuration path", r => { config = r; ++parsedArgCount; } },
                { "n|no-banner", "don't show the banner", r => { showBanner = r == null; ++parsedArgCount; } },
                { "h|help", "show this message and exit", h => shouldShowHelp = h != null },
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
                Console.WriteLine($"  {name} my.sln [--export=out.sarif] [--exclude=SCS1234;SCS2345] [--config=setting.yml]");
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
                var solution = await workspace.OpenSolutionAsync(solutionPath, new ConsoleProgressReporter());
                Console.WriteLine($"Finished loading solution '{solutionPath}'");

                var analyzers = new List<DiagnosticAnalyzer>();
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

                        foreach (var project in solution.Projects)
                        {
                            var compilation = await project.GetCompilationAsync();
                            var compilationWithAnalyzers = compilation.WithAnalyzers(analyzers.ToImmutableArray(), project.AnalyzerOptions);
                            var diagnostics = await compilationWithAnalyzers.GetAnalyzerDiagnosticsAsync();
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

                                Console.WriteLine($"Security Code Scan: {d}");
                                if (logger != null)
                                    logger.LogDiagnostic(d, null);
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

                var elapsed = DateTime.Now - startTime;
                Console.WriteLine($@"Completed in {elapsed:hh\:mm\:ss}");
                Console.WriteLine($@"{count} warnings");

                return returnCode;
            }
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
