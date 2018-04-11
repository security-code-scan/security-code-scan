using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
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
        public static readonly DiagnosticDescriptor Md5Rule  = LocaleUtil.GetDescriptor("SCS0006", args: new[] { "MD5" });
        public static readonly DiagnosticDescriptor Sha1Rule = LocaleUtil.GetDescriptor("SCS0006", args: new[] { "SHA1" });
        public const string Sha1TypeName = "System.Security.Cryptography.SHA1";
        public const string Md5TypeName = "System.Security.Cryptography.MD5";

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Md5Rule,
                                                                                                           Sha1Rule);

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterCompilationStartAction(ctx =>
                                                   {
                                                       var analyzer = new WeakHashingCompilationAnalyzer();
                                                       ctx.RegisterSyntaxNodeAction(analyzer.VisitInvocationSyntaxNode,
                                                                                    CSharp.SyntaxKind.InvocationExpression);

                                                       ctx.RegisterSyntaxNodeAction(analyzer.VisitInvocationSyntaxNode,
                                                                                    VB.SyntaxKind.InvocationExpression);

                                                       ctx.RegisterSyntaxNodeAction(analyzer.VisitMemberAccessSyntaxNode,
                                                                                    CSharp.SyntaxKind.SimpleMemberAccessExpression);

                                                       ctx.RegisterSyntaxNodeAction(analyzer.VisitMemberAccessSyntaxNode,
                                                                                    VB.SyntaxKind.SimpleMemberAccessExpression);

                                                       ctx.RegisterSyntaxNodeAction(analyzer.VisitObjectCreationSyntaxNode,
                                                                                    CSharp.SyntaxKind.ObjectCreationExpression);

                                                       ctx.RegisterSyntaxNodeAction(analyzer.VisitObjectCreationSyntaxNode,
                                                                                    VB.SyntaxKind.ObjectCreationExpression);
                                                   });
        }
    }

    internal class WeakHashingCompilationAnalyzer
    {
        private readonly List<Diagnostic> ReportedDiagnostics = new List<Diagnostic>();

        private void Report(Diagnostic diagnostic, SyntaxNodeAnalysisContext ctx)
        {
            var diagLineSpan = diagnostic.Location.GetLineSpan();

            lock (ReportedDiagnostics)
            {
                if (ReportedDiagnostics.FirstOrDefault(x =>
                                                        {
                                                            if (x.Id != diagnostic.Id)
                                                                return false;

                                                            var xLineSpan = x.Location.GetLineSpan();

                                                            if (xLineSpan.Path != diagLineSpan.Path)
                                                                return false;

                                                            return xLineSpan.StartLinePosition == diagLineSpan.StartLinePosition;
                                                        }) != null)
                {
                    return;
                }

                ReportedDiagnostics.Add(diagnostic);
            }

            ctx.ReportDiagnostic(diagnostic);
        }

        public void VisitObjectCreationSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            var symbol = ctx.SemanticModel.GetSymbolInfo(ctx.Node).Symbol;
            if (symbol == null)
                return;

            CheckType(WeakHashingAnalyzer.Sha1TypeName, WeakHashingAnalyzer.Sha1Rule, symbol.ContainingType, ctx);
            CheckType(WeakHashingAnalyzer.Md5TypeName,  WeakHashingAnalyzer.Md5Rule,  symbol.ContainingType, ctx);
        }

        private bool CheckType(string type, DiagnosticDescriptor diagnosticDescriptor, ITypeSymbol symbol, SyntaxNodeAnalysisContext ctx)
        {
            if (!symbol.IsTypeOrDerivedFrom(type))
                return false;

            var diagnostic = Diagnostic.Create(diagnosticDescriptor, ctx.Node.GetLocation());
            Report(diagnostic, ctx);
            return true;
        }

        public void VisitMemberAccessSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            var symbol = ctx.SemanticModel.GetSymbolInfo(ctx.Node).Symbol;
            switch (symbol)
            {
                case null:
                    return;
                case IMethodSymbol methodSymbol:
                    CheckType(WeakHashingAnalyzer.Sha1TypeName, WeakHashingAnalyzer.Sha1Rule, methodSymbol.ReturnType, ctx);
                    CheckType(WeakHashingAnalyzer.Md5TypeName,  WeakHashingAnalyzer.Md5Rule,  methodSymbol.ReturnType, ctx);
                    break;
            }
        }

        public void VisitInvocationSyntaxNode(SyntaxNodeAnalysisContext ctx)
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
            switch (symbol)
            {
                case null:
                    return;
                case IMethodSymbol method:
                    bool ret = CheckType(WeakHashingAnalyzer.Sha1TypeName, WeakHashingAnalyzer.Sha1Rule, method.ReturnType, ctx);
                    ret |= CheckType(WeakHashingAnalyzer.Md5TypeName, WeakHashingAnalyzer.Md5Rule, method.ReturnType, ctx);
                    if (ret)
                        return;

                    break;
            }

            var symbolString = symbol.GetTypeName();
            switch (symbolString)
            {
                case "System.Security.Cryptography.CryptoConfig.CreateFromName":
                {
                    var methodSymbol = (IMethodSymbol)symbol;
                    if (methodSymbol.Parameters.Length != 1)
                        break;

                    DiagnosticDescriptor rule;
                    if ((rule = CheckParameter(ctx)) != null)
                    {
                        var diagnostic = Diagnostic.Create(rule, expression.GetLocation());
                        Report(diagnostic, ctx);
                    }

                    break;
                }
                case "System.Security.Cryptography.HashAlgorithm.Create":
                {
                    var                  methodSymbol = (IMethodSymbol)symbol;
                    DiagnosticDescriptor rule         = WeakHashingAnalyzer.Sha1Rule; // default if no parameters
                    if (methodSymbol.Parameters.Length == 0 ||
                        (methodSymbol.Parameters.Length == 1 && (rule = CheckParameter(ctx)) != null))
                    {
                        var diagnostic = Diagnostic.Create(rule, expression.GetLocation());
                        Report(diagnostic, ctx);
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
            switch (value)
            {
                case WeakHashingAnalyzer.Sha1TypeName:
                case "SHA":
                case "SHA1":
                case "System.Security.Cryptography.HashAlgorithm":
                    return WeakHashingAnalyzer.Sha1Rule;
                case WeakHashingAnalyzer.Md5TypeName:
                case "MD5":
                    return WeakHashingAnalyzer.Md5Rule;
            }

            return null;
        }
    }
}
