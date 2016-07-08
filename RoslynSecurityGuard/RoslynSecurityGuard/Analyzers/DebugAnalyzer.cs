using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using System;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.CodeAnalysis.Internal.Log;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class DebugAnalyzer : DiagnosticAnalyzer
    {
        //static StreamWriter outfile;
        public static Action<String> handler { get; set; }


        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics
        {
            get
            { //Dummy descriptor
                DiagnosticDescriptor Rule = AnalyzerUtil.GetDescriptorFromResource(typeof(CommandInjectionAnalyzer), DiagnosticSeverity.Warning);
                return ImmutableArray.Create(Rule);
            }
        }

        public override void Initialize(AnalysisContext context)
        {
            //var allSyntaxKind = Enum.GetValues(typeof(SyntaxKind)).Cast<SyntaxKind>().ToArray();
            //context.RegisterSyntaxNodeAction(VisitAllNode, allSyntaxKind);
            context.RegisterSyntaxNodeAction(VisitMethods, SyntaxKind.MethodDeclaration);
        }


        private static void VisitAllNode(SyntaxNodeAnalysisContext ctx)
        {
            var node = ctx.Node;
            var symbol = ctx.SemanticModel.GetSymbolInfo(node).Symbol;

            if (handler != null)
            {
                handler("Node : " + node.GetType() + "");

                if (!(node is BlockSyntax || node is ClassDeclarationSyntax || node is CompilationUnitSyntax))
                {
                    handler("<<" + node.ToFullString() + ">>");
                }
            }
        }

        private static void VisitMethods(SyntaxNodeAnalysisContext ctx)
        {
            var node = ctx.Node as MethodDeclarationSyntax;
            var symbol = ctx.SemanticModel.GetSymbolInfo(node).Symbol;

            if (node != null)
            {
                visitNodeRecursively(node,0);
            }
        }

        private static void visitNodeRecursively(SyntaxNode node,int indent) {

            string code = node.GetText().Lines[0].Text.ToString().Trim() + (node.GetText().Lines.Count > 1 ? "[...]" : "");

            if (node.ChildNodes().Count() > 0)
            {
                code = "";
            }

            handler(new String(' ', indent * 4) + code + " (" +node.GetType().Name+")");

            foreach (var n in node.ChildNodes()) {
                visitNodeRecursively(n, indent+1);
            }
        }
    }
}
