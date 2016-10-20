using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using System;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using RoslynSecurityGuard.Analyzers.Utils;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class DebugAnalyzer : DiagnosticAnalyzer
    {
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics
        {
            get
            { //Dummy descriptor
                DiagnosticDescriptor Rule = AnalyzerUtil.GetDescriptorFromResource("Debug",typeof(CommandInjectionAnalyzer).Name, DiagnosticSeverity.Warning);
                return ImmutableArray.Create(Rule);
            }
        }

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitMethods, SyntaxKind.MethodDeclaration);
        }

        private static void VisitMethods(SyntaxNodeAnalysisContext ctx)
        {
            var node = ctx.Node as MethodDeclarationSyntax;

            if (node != null)
            {
                //This analyzer will trace the node only if it is in debug mode.
                if(SGLogging.IsConfigured()) { 
                    visitNodeRecursively(node,0, ctx);
                }
            }
        }

        private static void visitNodeRecursively(SyntaxNode node, int indent, SyntaxNodeAnalysisContext ctx) {

            string code = node.GetText().Lines[0].Text.ToString().Trim() + (node.GetText().Lines.Count > 1 ? "[...]" : "");

            if (node.ChildNodes().Count() > 0)
            {
                code = "";
            }

            if (node is InvocationExpressionSyntax)
            {
                var symbol = ctx.SemanticModel.GetSymbolInfo(node).Symbol;
                if (symbol != null)
                {
                    string typeName = symbol.ContainingType?.Name; //Class name
                    string name = symbol.Name; //Method
                    if (typeName != null && name != null)
                    {
                        code = typeName + "." + name;
                    }
                }
            }

            SGLogging.Log(new string(' ', indent * 4) + code + " <" +node.GetType().Name+">", false);

            foreach (var n in node.ChildNodes()) {
                visitNodeRecursively(n, indent+1, ctx);
            }
        }
    }
}
