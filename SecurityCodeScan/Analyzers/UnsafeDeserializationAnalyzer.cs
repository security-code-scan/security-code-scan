using System;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using VB = Microsoft.CodeAnalysis.VisualBasic;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class UnsafeDeserializationAnalyzer : DiagnosticAnalyzer
    {
        private static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0028", "title_analyzer");

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(ctx => VisitMemberAccess  (ctx, CSharpSyntaxNodeHelper.Default),  CSharp.SyntaxKind.SimpleMemberAccessExpression);
            context.RegisterSyntaxNodeAction(ctx => VisitMemberAccess  (ctx, VBSyntaxNodeHelper.Default),      VB.SyntaxKind.SimpleMemberAccessExpression);
            context.RegisterSyntaxNodeAction(ctx => VisitObjectCreation(ctx, CSharpSyntaxNodeHelper.Default),  CSharp.SyntaxKind.ObjectCreationExpression);
            context.RegisterSyntaxNodeAction(ctx => VisitObjectCreation(ctx, VBSyntaxNodeHelper.Default),      VB.SyntaxKind.ObjectCreationExpression);
        }

        private void VisitObjectCreation(SyntaxNodeAnalysisContext ctx, SyntaxNodeHelper nodeHelper)
        {
            var objectCreation = nodeHelper.GetNameNode(ctx.Node);
            if(!objectCreation.ToString().Contains("JavaScriptSerializer"))
                return;

            var creationSymbols = ctx.SemanticModel.GetSymbolInfo(ctx.Node).Symbol;
            if (creationSymbols == null || creationSymbols.ContainingSymbol.ToString() != "System.Web.Script.Serialization.JavaScriptSerializer")
                return;

            var arguments = nodeHelper.GetObjectCreationArgumentExpressionNodes(ctx.Node);

            var firstArgument = arguments.FirstOrDefault();
            if (firstArgument == null)
                return;

            if(ctx.SemanticModel.GetSymbolInfo(firstArgument).Symbol != null)
                ctx.ReportDiagnostic(Diagnostic.Create(Rule, ctx.Node.GetLocation()));
        }

        private void VisitMemberAccess(SyntaxNodeAnalysisContext ctx, SyntaxNodeHelper nodeHelper)
        {
            var name = nodeHelper.GetMemberAccessExpressionNode(ctx.Node);
            if (name == null || !name.ToString().Contains("TypeNameHandling"))
                return;

            var nameSymbols = ctx.SemanticModel.GetSymbolInfo(ctx.Node).Symbol;
            if (nameSymbols == null || nameSymbols.ContainingSymbol.ToString() != "Newtonsoft.Json.TypeNameHandling")
                return;

            var expresion = nodeHelper.GetNameNode(ctx.Node);
            if (expresion != null && expresion.ToString() != "None")
                ctx.ReportDiagnostic(Diagnostic.Create(Rule, ctx.Node.GetLocation()));
        }
    }
}
