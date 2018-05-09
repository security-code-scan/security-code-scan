using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using VB = Microsoft.CodeAnalysis.VisualBasic;

namespace SecurityCodeScan.Analyzers.Taint
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class TaintAnalyzerCSharp : TaintAnalyzer
    {
        private readonly CSharpCodeEvaluation CodeEval = new CSharpCodeEvaluation();
        public override void Initialize(AnalysisContext context)
        {
            CodeEval.BehaviorRepo = BehaviorRepo;
            context.RegisterSyntaxNodeAction(CodeEval.VisitMethods, CSharp.SyntaxKind.MethodDeclaration);
            context.RegisterSyntaxNodeAction(CodeEval.VisitMethods, CSharp.SyntaxKind.ConstructorDeclaration);
            context.RegisterSyntaxNodeAction(CodeEval.VisitMethods, CSharp.SyntaxKind.DestructorDeclaration);
            context.RegisterSyntaxNodeAction(CodeEval.VisitMethods, CSharp.SyntaxKind.PropertyDeclaration);
        }
    }

    [DiagnosticAnalyzer(LanguageNames.VisualBasic)]
    public class TaintAnalyzerVisualBasic : TaintAnalyzer
    {
        private readonly VbCodeEvaluation CodeEval = new VbCodeEvaluation();
        public override void Initialize(AnalysisContext context)
        {
            CodeEval.BehaviorRepo = BehaviorRepo;
            context.RegisterSyntaxNodeAction(CodeEval.VisitMethods,     VB.SyntaxKind.SubBlock);
            context.RegisterSyntaxNodeAction(CodeEval.VisitMethods,     VB.SyntaxKind.FunctionBlock);
            context.RegisterSyntaxNodeAction(CodeEval.VisitMethods,     VB.SyntaxKind.ConstructorBlock);
            context.RegisterSyntaxNodeAction(CodeEval.VisitMethods,     VB.SyntaxKind.PropertyBlock);
        }
    }

    public abstract class TaintAnalyzer : DiagnosticAnalyzer
    {
        private readonly List<DiagnosticDescriptor> Descriptors = new List<DiagnosticDescriptor>();

        protected readonly MethodBehaviorRepository BehaviorRepo = new MethodBehaviorRepository();

        private static readonly List<TaintAnalyzerExtension> Extensions = new List<TaintAnalyzerExtension>();

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

        protected TaintAnalyzer()
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
