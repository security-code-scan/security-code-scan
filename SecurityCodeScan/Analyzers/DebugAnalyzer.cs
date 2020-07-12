#nullable disable
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;

namespace SecurityCodeScan.Analyzers
{
    //[DiagnosticAnalyzer(LanguageNames.CSharp)]
#pragma warning disable RS1001 // Missing diagnostic analyzer attribute.
    internal class DebugAnalyzer : DiagnosticAnalyzer
#pragma warning restore RS1001 // Missing diagnostic analyzer attribute.
    {
        //Dummy descriptor, it will never be reported
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
            ImmutableArray.Create(LocaleUtil.GetDescriptor("Debug"));

        public override void Initialize(AnalysisContext context)
        {
            context.EnableConcurrentExecution();
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
            context.RegisterSyntaxNodeAction(VisitMethods, SyntaxKind.MethodDeclaration);
        }

        private static void VisitMethods(SyntaxNodeAnalysisContext ctx)
        {
            if (!(ctx.Node is MethodDeclarationSyntax node))
                return;

            //This analyzer will trace the node only if it is in debug mode.
            if (!Logger.IsConfigured())
                return;

            Logger.Log("== Method : " + node.Identifier.Text + " (BEGIN) ==", false);
            VisitNodeRecursively(node, 0, ctx);
            Logger.Log("== Method : " + node.Identifier.Text + " (END) ==", false);
        }

        private static void VisitNodeRecursively(SyntaxNode node, int indent, SyntaxNodeAnalysisContext ctx)
        {
            string code = node.GetText().Lines[0].Text.ToString().Trim() +
                          (node.GetText().Lines.Count > 1 ? "[...]" : "");

            if (node.ChildNodes().Any())
            {
                code = "";
            }

            if (node is InvocationExpressionSyntax)
            {
                var symbol = ctx.SemanticModel.GetSymbolInfo(node).Symbol;
                if (symbol != null)
                {
                    string typeName = symbol.ContainingType?.Name; //Class name
                    string name     = symbol.Name;                 //Method
                    if (typeName != null && name != null)
                    {
                        code = typeName + "." + name;
                    }
                }
            }

            Logger.Log(new string(' ', indent * 4) + code + " <" + node.GetType().Name + ">", false);

            foreach (var n in node.ChildNodes())
            {
                VisitNodeRecursively(n, indent + 1, ctx);
            }
        }
    }
}
