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

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class WeakHashingAnalyzerCSharp : WeakHashingAnalyzer
    {
        public override void Initialize(AnalysisContext context)
        {
            context.RegisterCompilationStartAction(ctx =>
                                                   {
                                                       var analyzer = new WeakHashingCompilationAnalyzer();
                                                       ctx.RegisterSyntaxNodeAction(actionContext => analyzer.VisitInvocationSyntaxNode(actionContext, CSharpSyntaxNodeHelper.Default),
                                                                                    CSharp.SyntaxKind.InvocationExpression);

                                                       ctx.RegisterSyntaxNodeAction(analyzer.VisitMemberAccessSyntaxNode,
                                                                                    CSharp.SyntaxKind.SimpleMemberAccessExpression);

                                                       ctx.RegisterSyntaxNodeAction(analyzer.VisitObjectCreationSyntaxNode,
                                                                                    CSharp.SyntaxKind.ObjectCreationExpression);
                                                   });
        }
    }

    [DiagnosticAnalyzer(LanguageNames.VisualBasic)]
    public class WeakHashingAnalyzerVisualBasic: WeakHashingAnalyzer
    {
        public override void Initialize(AnalysisContext context)
        {
            context.RegisterCompilationStartAction(ctx =>
            {
                var analyzer = new WeakHashingCompilationAnalyzer();
                ctx.RegisterSyntaxNodeAction(actionContext => analyzer.VisitInvocationSyntaxNode(actionContext, VBSyntaxNodeHelper.Default),
                                             VB.SyntaxKind.InvocationExpression);

                ctx.RegisterSyntaxNodeAction(analyzer.VisitMemberAccessSyntaxNode,
                                             VB.SyntaxKind.SimpleMemberAccessExpression);

                ctx.RegisterSyntaxNodeAction(analyzer.VisitObjectCreationSyntaxNode,
                                             VB.SyntaxKind.ObjectCreationExpression);
            });
        }
    }

    public abstract class WeakHashingAnalyzer : DiagnosticAnalyzer
    {
        public static readonly DiagnosticDescriptor Md5Rule  = LocaleUtil.GetDescriptor("SCS0006", args: new[] { "MD5" });
        public static readonly DiagnosticDescriptor Sha1Rule = LocaleUtil.GetDescriptor("SCS0006", args: new[] { "SHA1" });
        public static readonly DiagnosticDescriptor UnknownHashRule = LocaleUtil.GetDescriptor("SCS0006", titleId:"title2", descriptionId: "description_unknown");
        public const string Sha1TypeName = "System.Security.Cryptography.SHA1";
        public const string Md5TypeName = "System.Security.Cryptography.MD5";

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(Md5Rule,
                                                                                                           Sha1Rule);
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
            if (!symbol.IsType(type) && !symbol.IsDerivedFrom(type))
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

        public void VisitInvocationSyntaxNode(SyntaxNodeAnalysisContext ctx, SyntaxNodeHelper nodeHelper)
        {
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
                    if ((rule = CheckParameter(ctx, nodeHelper)) != null)
                    {
                        SyntaxNode expression = nodeHelper.GetInvocationExpressionNode(ctx.Node);
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
                        (methodSymbol.Parameters.Length == 1 && (rule = CheckParameter(ctx, nodeHelper)) != null))
                    {
                        SyntaxNode expression = nodeHelper.GetInvocationExpressionNode(ctx.Node);
                        var diagnostic = Diagnostic.Create(rule, expression.GetLocation());
                        Report(diagnostic, ctx);
                    }

                    break;
                }
            }
        }

        private static DiagnosticDescriptor CheckParameter(SyntaxNodeAnalysisContext ctx, SyntaxNodeHelper nodeHelper)
        {
            Optional<object> argValue = ctx.SemanticModel.GetConstantValue(nodeHelper.GetCallArgumentExpressionNodes(ctx.Node).First());

            if (!argValue.HasValue)
            {
                if (ConfigurationManager.Instance.GetProjectConfiguration(ctx.Options.AdditionalFiles).AuditMode)
                    return WeakHashingAnalyzer.UnknownHashRule;

                return null;
            }

            if (!(argValue.Value is string value))
                return null;

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
