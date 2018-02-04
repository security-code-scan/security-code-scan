using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using VB = Microsoft.CodeAnalysis.VisualBasic;

namespace SecurityCodeScan.Analyzers.Taint
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class TaintAnalyzer : DiagnosticAnalyzer
    {
        private readonly List<DiagnosticDescriptor> Descriptors = new List<DiagnosticDescriptor>();

        private readonly MethodBehaviorRepository BehaviorRepo = new MethodBehaviorRepository();

        private static readonly List<TaintAnalyzerExtension> Extensions = new List<TaintAnalyzerExtension>();

        private readonly CSharpCodeEvaluation CsharpCodeEval = new CSharpCodeEvaluation();
        private readonly VbCodeEvaluation     VbCodeEval     = new VbCodeEvaluation();

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics
        {
            get
            {
                //Feed the diagnostic descriptor from the configured sinks
                var all = new HashSet<DiagnosticDescriptor>(Descriptors);

                //Add the diagnostic that can be reported by taint analysis extension
                lock (Extensions)
                {
                    foreach (var extension in Extensions)
                    {
                        foreach (DiagnosticDescriptor desc in extension.SupportedDiagnostics)
                        {
                            all.Add(desc);
                        }
                    }
                }

                return ImmutableArray.Create(all.ToArray());
            }
        }

        public TaintAnalyzer()
        {
            //Load injectable APIs
            BehaviorRepo.LoadConfiguration("Sinks.yml");

            //Load password APIs
            BehaviorRepo.LoadConfiguration("Passwords.yml");

            //
            BehaviorRepo.LoadConfiguration("Behavior.yml");

            //Build the descriptor based on the locale fields of the Sinks.yml
            //This must be done in the constructor because,
            //the array need be available before SupportedDiagnostics is first invoked.
            foreach (var desc in BehaviorRepo.GetDescriptors())
            {
                Descriptors.Add(desc);
            }

            VbCodeEval.BehaviorRepo     = BehaviorRepo;
            CsharpCodeEval.BehaviorRepo = BehaviorRepo;
        }

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(CsharpCodeEval.VisitMethods, CSharp.SyntaxKind.MethodDeclaration);
            context.RegisterSyntaxNodeAction(CsharpCodeEval.VisitMethods, CSharp.SyntaxKind.ConstructorDeclaration);
            context.RegisterSyntaxNodeAction(CsharpCodeEval.VisitMethods, CSharp.SyntaxKind.DestructorDeclaration);
            context.RegisterSyntaxNodeAction(CsharpCodeEval.VisitMethods, CSharp.SyntaxKind.PropertyDeclaration);
            context.RegisterSyntaxNodeAction(VbCodeEval.VisitMethods,     VB.SyntaxKind.SubBlock);
            context.RegisterSyntaxNodeAction(VbCodeEval.VisitMethods,     VB.SyntaxKind.FunctionBlock);
            context.RegisterSyntaxNodeAction(VbCodeEval.VisitMethods,     VB.SyntaxKind.ConstructorBlock);
            context.RegisterSyntaxNodeAction(VbCodeEval.VisitMethods,     VB.SyntaxKind.PropertyBlock);
        }

        public static void RegisterExtension(TaintAnalyzerExtension extension)
        {
            // Must be executed in a synchronous way for testing purposes
            lock (Extensions)
            {
                // Makes sure an extension of the same time isn't already registered before adding it to the list
                if (Extensions.Any(x => x.GetType().FullName.Equals(extension.GetType().FullName)))
                    return;

                Extensions.Add(extension);
                CSharpCodeEvaluation.Extensions = Extensions;
                VbCodeEvaluation.Extensions     = Extensions;
            }
        }
    }
}
