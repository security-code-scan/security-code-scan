using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using VB = Microsoft.CodeAnalysis.VisualBasic;

namespace SecurityCodeScan.Analyzers.Taint
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class TaintAnalyzerCSharp : DiagnosticAnalyzer
    {
        public override void Initialize(AnalysisContext analysisContext)
        {
            analysisContext.RegisterCompilationStartAction(
                context =>
                {
                    var taintAnalyzer = new CSharpCodeEvaluation(CSharpSyntaxNodeHelper.Default,
                                                                 ConfigurationManager.Instance
                                                                                     .GetUpdatedProjectConfiguration(context.Options.AdditionalFiles));
                    context.RegisterSyntaxNodeAction(taintAnalyzer.VisitMethods, CSharp.SyntaxKind.MethodDeclaration);
                    context.RegisterSyntaxNodeAction(taintAnalyzer.VisitMethods, CSharp.SyntaxKind.ConstructorDeclaration);
                    context.RegisterSyntaxNodeAction(taintAnalyzer.VisitMethods, CSharp.SyntaxKind.DestructorDeclaration);
                    context.RegisterSyntaxNodeAction(taintAnalyzer.VisitMethods, CSharp.SyntaxKind.PropertyDeclaration);
                });
        }

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics
        {
            get
            {
                //Feed the diagnostic descriptor from the configured sinks
                var all = new HashSet<DiagnosticDescriptor>(LocaleUtil.GetAllAvailableDescriptors());

                //Add the diagnostic that can be reported by taint analysis extension
                lock (CSharpCodeEvaluation.Extensions)
                {
                    foreach (var extension in CSharpCodeEvaluation.Extensions)
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

        public static void RegisterExtension(TaintAnalyzerExtensionCSharp extension)
        {
            // Must be executed in a synchronous way for testing purposes
            lock (CSharpCodeEvaluation.Extensions)
            {
                // Makes sure an extension of the same time isn't already registered before adding it to the list
                if (CSharpCodeEvaluation.Extensions.Any(x => x.GetType().FullName.Equals(extension.GetType().FullName)))
                    return;

                CSharpCodeEvaluation.Extensions.Add(extension);
            }
        }
    }

    [DiagnosticAnalyzer(LanguageNames.VisualBasic)]
    public class TaintAnalyzerVisualBasic : DiagnosticAnalyzer
    {
        public override void Initialize(AnalysisContext analysisContext)
        {
            analysisContext.RegisterCompilationStartAction(
                context =>
                {
                    var taintAnalyzer = new VbCodeEvaluation(VBSyntaxNodeHelper.Default,
                                                             ConfigurationManager.Instance
                                                                                 .GetUpdatedProjectConfiguration(context.Options.AdditionalFiles));
                    context.RegisterSyntaxNodeAction(taintAnalyzer.VisitMethods, VB.SyntaxKind.SubBlock);
                    context.RegisterSyntaxNodeAction(taintAnalyzer.VisitMethods, VB.SyntaxKind.FunctionBlock);
                    context.RegisterSyntaxNodeAction(taintAnalyzer.VisitMethods, VB.SyntaxKind.ConstructorBlock);
                    context.RegisterSyntaxNodeAction(taintAnalyzer.VisitMethods, VB.SyntaxKind.PropertyBlock);
                });
        }

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics
        {
            get
            {
                //Feed the diagnostic descriptor from the configured sinks
                var all = new HashSet<DiagnosticDescriptor>(LocaleUtil.GetAllAvailableDescriptors());

                //Add the diagnostic that can be reported by taint analysis extension
                lock (VbCodeEvaluation.Extensions)
                {
                    foreach (var extension in VbCodeEvaluation.Extensions)
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

        public static void RegisterExtension(TaintAnalyzerExtensionVisualBasic extension)
        {
            // Must be executed in a synchronous way for testing purposes
            lock (VbCodeEvaluation.Extensions)
            {
                // Makes sure an extension of the same time isn't already registered before adding it to the list
                if (VbCodeEvaluation.Extensions.Any(x => x.GetType().FullName.Equals(extension.GetType().FullName)))
                    return;

                VbCodeEvaluation.Extensions.Add(extension);
            }
        }
    }
}
