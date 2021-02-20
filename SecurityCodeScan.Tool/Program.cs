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

namespace SecurityCodeScan.Tool
{
    internal class Program
    {
        private static async Task<int> Main(string[] args)
        {
            var versionString = System.Diagnostics.FileVersionInfo.GetVersionInfo(Assembly.GetEntryAssembly().Location).FileVersion;

            string solutionPath = null;
            string sarifFile = null;
            var shouldShowHelp = false;
            var options = new OptionSet {
                { "<>", "solution path", n => solutionPath = n },
                { "e|export=", "SARIF file path", r => sarifFile = r },
                { "h|help", "show this message and exit", h => shouldShowHelp = h != null },
            };

            try
            {
                options.Parse(args);
            }
            catch
            {
                shouldShowHelp = true;
            }

            if (shouldShowHelp || solutionPath == null || args.Length > 2)
            {
                var name = AppDomain.CurrentDomain.FriendlyName;

                Console.WriteLine($@"
╔═╗┌─┐┌─┐┬ ┬┬─┐┬┌┬┐┬ ┬  ╔═╗┌─┐┌┬┐┌─┐  ╔═╗┌─┐┌─┐┌┐┌
╚═╗├┤ │  │ │├┬┘│ │ └┬┘  ║  │ │ ││├┤   ╚═╗│  ├─┤│││
╚═╝└─┘└─┘└─┘┴└─┴ ┴  ┴   ╚═╝└─┘─┴┘└─┘  ╚═╝└─┘┴ ┴┘└┘

.NET tool v{versionString}");
                Console.WriteLine("\nUsage:\n");
                options.WriteOptionDescriptions(Console.Out);
                Console.WriteLine("\nExample:\n");
                Console.WriteLine($"  {name} <solution path> [--export=<SARIF file path>]");
                return 1;
            }

            var returnCode = 0;

            // Attempt to set the version of MSBuild.
            var visualStudioInstances = MSBuildLocator.QueryVisualStudioInstances().ToArray();
            var instance = visualStudioInstances.OrderByDescending(x => x.Version).First();

            Console.WriteLine($"Using MSBuild at '{instance.MSBuildPath}' to load projects.");
            MSBuildLocator.RegisterInstance(instance);

            using (var workspace = MSBuildWorkspace.Create())
            {
                // Print message for WorkspaceFailed event to help diagnosing project load failures.
                workspace.WorkspaceFailed += (o, e) =>
                {
                    Console.ForegroundColor = ConsoleColor.Red;
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

                foreach (var type in types)
                {
                    if (type.IsAbstract)
                        continue;

                    var secAttributes = type.GetCustomAttributes(typeof(DiagnosticAnalyzerAttribute), false)
                                            .Cast<DiagnosticAnalyzerAttribute>();
                    foreach (var attribute in secAttributes)
                    {
                        analyzers.Add((DiagnosticAnalyzer)Activator.CreateInstance(type.AsType()));
                        break;
                    }
                }

                Stream stream = null;
                SarifV2ErrorLogger logger = null;
                try
                {
                    if (sarifFile != null)
                    {
                        stream = File.OpenWrite(sarifFile);
                        logger = new SarifV2ErrorLogger(stream, "Security Code Scan", versionString, new Version(versionString), CultureInfo.InvariantCulture);
                    }

                    if (stream != null)
                    {
                        logger = new SarifV2ErrorLogger(stream, "Security Code Scan", versionString, new Version(versionString), CultureInfo.InvariantCulture);
                    }

                    try
                    {
                        foreach (var project in solution.Projects)
                        {
                            var compilation = await project.GetCompilationAsync();
                            var compilationWithAnalyzers = compilation.WithAnalyzers(analyzers.ToImmutableArray());
                            var diagnostics = await compilationWithAnalyzers.GetAnalyzerDiagnosticsAsync();
                            foreach (var diag in diagnostics)
                            {
                                Console.WriteLine($"Security Code Scan: {diag}");
                                if (logger != null)
                                    logger.LogDiagnostic(diag, null);
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

                return returnCode;
            }
        }

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
