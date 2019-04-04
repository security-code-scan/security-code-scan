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
    internal abstract class TaintAnalyzer<T> : SecurityAnalyzer where T : TaintAnalyzerExtension
    {
        protected readonly IEnumerable<T> Extensions;

        protected TaintAnalyzer(IEnumerable<T> extensions)
        {
            Extensions = extensions;
        }

        protected TaintAnalyzer(T extension)
        {
            Extensions = new [] { extension };
        }

        protected TaintAnalyzer()
        {
        }

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics
        {
            get
            {
                //Feed the diagnostic descriptor from the configured sinks
                var all = new HashSet<DiagnosticDescriptor>(LocaleUtil.GetAllAvailableDescriptors());

                if (Extensions != null)
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
    }

    [SecurityAnalyzer(LanguageNames.CSharp)]
    internal class TaintAnalyzerCSharp : TaintAnalyzer<TaintAnalyzerExtensionCSharp>
    {
        public TaintAnalyzerCSharp(TaintAnalyzerExtensionCSharp extension) : base(extension)
        {
        }

        public TaintAnalyzerCSharp(params TaintAnalyzerExtensionCSharp[] extensions) : base(extensions)
        {
        }

        public TaintAnalyzerCSharp()
        {
        }

        public override void Initialize(ISecurityAnalysisContext context)
        {
            context.RegisterCompilationStartAction(OnCompilationStartAction);
        }

        private void OnCompilationStartAction(CompilationStartAnalysisContext context, Configuration config)
        {
            var taintAnalyzer = new CSharpCodeEvaluation(CSharpSyntaxNodeHelper.Default, config, Extensions);
            context.RegisterSyntaxNodeAction(taintAnalyzer.VisitMethods, CSharp.SyntaxKind.MethodDeclaration);
            context.RegisterSyntaxNodeAction(taintAnalyzer.VisitMethods, CSharp.SyntaxKind.ConstructorDeclaration);
            context.RegisterSyntaxNodeAction(taintAnalyzer.VisitMethods, CSharp.SyntaxKind.DestructorDeclaration);
            context.RegisterSyntaxNodeAction(taintAnalyzer.VisitMethods, CSharp.SyntaxKind.PropertyDeclaration);
        }
    }

    [SecurityAnalyzer(LanguageNames.VisualBasic)]
    internal class TaintAnalyzerVisualBasic : TaintAnalyzer<TaintAnalyzerExtensionVisualBasic>
    {
        public TaintAnalyzerVisualBasic(TaintAnalyzerExtensionVisualBasic extension) : base(extension)
        {
        }

        public TaintAnalyzerVisualBasic(params TaintAnalyzerExtensionVisualBasic[] extensions) : base(extensions)
        {
        }

        public TaintAnalyzerVisualBasic()
        {
        }

        public override void Initialize(ISecurityAnalysisContext context)
        {
            context.RegisterCompilationStartAction(OnCompilationStartAction);
        }

        private void OnCompilationStartAction(CompilationStartAnalysisContext context, Configuration config)
        {
            var taintAnalyzer = new VbCodeEvaluation(VBSyntaxNodeHelper.Default, config, Extensions);
            context.RegisterSyntaxNodeAction(taintAnalyzer.VisitMethods, VB.SyntaxKind.SubBlock);
            context.RegisterSyntaxNodeAction(taintAnalyzer.VisitMethods, VB.SyntaxKind.FunctionBlock);
            context.RegisterSyntaxNodeAction(taintAnalyzer.VisitMethods, VB.SyntaxKind.ConstructorBlock);
            context.RegisterSyntaxNodeAction(taintAnalyzer.VisitMethods, VB.SyntaxKind.PropertyBlock);
        }
    }
}
