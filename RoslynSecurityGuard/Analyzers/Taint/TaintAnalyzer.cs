using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using RoslynSecurityGuard.Analyzers.Locale;
using RoslynSecurityGuard.Analyzers.Utils;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

namespace RoslynSecurityGuard.Analyzers.Taint
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class TaintAnalyzer : DiagnosticAnalyzer
    {
        private readonly List<DiagnosticDescriptor> Descriptors = new List<DiagnosticDescriptor>();
        
        private MethodBehaviorRepository behaviorRepo = new MethodBehaviorRepository();

        private static List<CSharpTaintAnalyzerExtension> extensions = new List<CSharpTaintAnalyzerExtension>();

        private CSharpCodeEvaluation csharpCodeEval = new CSharpCodeEvaluation();
        private VbCodeEvaluation vbCodeEval = new VbCodeEvaluation();

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics
        {
            get
            {
                //Feed the diagnostic descriptor from the configured sinks
                HashSet<DiagnosticDescriptor> all = new HashSet<DiagnosticDescriptor>(Descriptors);
                //Add the diagnostic that can be reported by taint analysis extension
                foreach (var extension in extensions)
                {
                    var analyzer = extension as DiagnosticAnalyzer;
                    foreach (DiagnosticDescriptor desc in analyzer.SupportedDiagnostics)
                    {
                        all.Add(desc);
                    }
                }
                return ImmutableArray.Create(all.ToArray());
            }
        }

        public TaintAnalyzer()
        {
            //Load injectable APIs
            behaviorRepo.LoadConfiguration("Sinks.yml");
            //Load password APIs
            behaviorRepo.LoadConfiguration("Passwords.yml");
            //
            behaviorRepo.LoadConfiguration("Behavior.yml");

            //Build the descriptor based on the locale fields of the Sinks.yml
            //This must be done in the constructor because, the array need be available before SupportedDiagnostics is first invoked.
            foreach (var desc in behaviorRepo.GetDescriptors())
            {
                Descriptors.Add(desc);
            }

            csharpCodeEval.behaviorRepo = behaviorRepo;
        }
        
        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitMethods, SyntaxKind.MethodDeclaration);
        }
        
        public static void RegisterExtension(CSharpTaintAnalyzerExtension extension)
        {
			// Must be executed in a synchronous way for testing purposes
			lock (extensions)
			{
				// Makes sure an extension of the same time isn't already registered before adding it to the list
				if (!extensions.Any(x => x.GetType().FullName.Equals((extension).GetType().FullName)))
				{
					extensions.Add(extension);
					CSharpCodeEvaluation.extensions = extensions;
				}
			}	
        }


        private void VisitMethods(SyntaxNodeAnalysisContext obj)
        {
            csharpCodeEval.VisitMethods(obj);
            //vbCodeEval.VisitMethods(obj);
        }
    }
}
