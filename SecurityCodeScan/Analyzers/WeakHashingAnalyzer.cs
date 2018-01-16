using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VB = Microsoft.CodeAnalysis.VisualBasic;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class WeakHashingAnalyzer : DiagnosticAnalyzer
    {
        private static readonly DiagnosticDescriptor Md5Rule  = LocaleUtil.GetDescriptor("SCS0006", new[] { "MD5" });
        private static readonly DiagnosticDescriptor Sha1Rule = LocaleUtil.GetDescriptor("SCS0006", new[] { "SHA1" });

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Md5Rule,
                                                                                                           Sha1Rule);

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitInvocationSyntaxNode, CSharp.SyntaxKind.InvocationExpression);
            context.RegisterSyntaxNodeAction(VisitInvocationSyntaxNode, VB.SyntaxKind.InvocationExpression);
            context.RegisterSyntaxNodeAction(VisitObjectCreationSyntaxNode, CSharp.SyntaxKind.ObjectCreationExpression);
            context.RegisterSyntaxNodeAction(VisitObjectCreationSyntaxNode, VB.SyntaxKind.ObjectCreationExpression);
        }

        private static void VisitObjectCreationSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            var symbol = ctx.SemanticModel.GetSymbolInfo(ctx.Node).Symbol;
            if (symbol == null)
                return;

            if (symbol.IsType("System.Security.Cryptography.SHA1") ||
                symbol.ContainingType.IsDerivedFrom("System.Security.Cryptography.SHA1"))
            {
                var diagnostic = Diagnostic.Create(Sha1Rule, ctx.Node.GetLocation());
                ctx.ReportDiagnostic(diagnostic);
            }

            if (symbol.IsType("System.Security.Cryptography.MD5") ||
                symbol.ContainingType.IsDerivedFrom("System.Security.Cryptography.MD5"))
            {
                var diagnostic = Diagnostic.Create(Md5Rule, ctx.Node.GetLocation());
                ctx.ReportDiagnostic(diagnostic);
            }
        }

        private static void VisitInvocationSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            SyntaxNode expression;
            if (ctx.Node.Language == LanguageNames.CSharp)
            {
                expression = ((CSharpSyntax.InvocationExpressionSyntax)ctx.Node).Expression;
            }
            else
            {
                expression = ((VBSyntax.InvocationExpressionSyntax)ctx.Node).Expression;
            }

            var symbol = ctx.SemanticModel.GetSymbolInfo(ctx.Node).Symbol;
            if (symbol == null)
                return;

            var symbolString = symbol.ToDisplayString(SymbolExtensions.SymbolDisplayFormat);
            switch (symbolString)
            {
                case "System.Security.Cryptography.MD5.Create":
                {
                    var diagnostic = Diagnostic.Create(Md5Rule, expression.GetLocation());
                    ctx.ReportDiagnostic(diagnostic);
                    break;
                }
                case "System.Security.Cryptography.SHA1.Create":
                {
                    var diagnostic = Diagnostic.Create(Sha1Rule, expression.GetLocation());
                    ctx.ReportDiagnostic(diagnostic);
                    break;
                }
                case "System.Security.Cryptography.CryptoConfig.CreateFromName":
                {
                    var methodSymbol = (IMethodSymbol)symbol;
                    DiagnosticDescriptor rule;
                    if (methodSymbol.Parameters.Length == 1 && (rule = CheckParameter(ctx)) != null)
                    {
                        var diagnostic = Diagnostic.Create(rule, expression.GetLocation());
                        ctx.ReportDiagnostic(diagnostic);
                    }

                    break;
                }
                case "System.Security.Cryptography.HashAlgorithm.Create":
                {
                    var methodSymbol = (IMethodSymbol)symbol;
                    DiagnosticDescriptor rule = Sha1Rule; // default if no parameters
                    if (methodSymbol.Parameters.Length == 0 ||
                        (methodSymbol.Parameters.Length == 1 && (rule = CheckParameter(ctx)) != null))
                    {
                        var diagnostic = Diagnostic.Create(rule, expression.GetLocation());
                        ctx.ReportDiagnostic(diagnostic);
                    }

                    break;
                }
            }
        }

        private static DiagnosticDescriptor CheckParameter(SyntaxNodeAnalysisContext ctx)
        {
            Optional<object> argValue;
            if (ctx.Node.Language == LanguageNames.CSharp)
            {
                argValue = ctx.SemanticModel
                              .GetConstantValue(((CSharpSyntax.InvocationExpressionSyntax)ctx.Node).ArgumentList
                                                                                                   .Arguments[0]
                                                                                                   .Expression);
            }
            else
            {
                argValue = ctx.SemanticModel
                              .GetConstantValue(((VBSyntax.InvocationExpressionSyntax)ctx.Node).ArgumentList
                                                                                               .Arguments[0]
                                                                                               .GetExpression());
            }

            if (!argValue.HasValue)
                return null;

            var value = (string)argValue.Value;
            if (value == "System.Security.Cryptography.SHA1" ||
                value == "SHA"                               ||
                value == "SHA1"                              ||
                value == "System.Security.Cryptography.HashAlgorithm")
            {
                return Sha1Rule;
            }

            if (value == "System.Security.Cryptography.MD5" ||
                value == "MD5")
            {
                return Md5Rule;
            }

            return null;
        }
    }
}
