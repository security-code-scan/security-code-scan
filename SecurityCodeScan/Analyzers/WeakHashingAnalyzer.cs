#nullable disable
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
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
            if (!Debugger.IsAttached) // prefer single thread for debugging in development
                context.EnableConcurrentExecution();

            if (context.IsAuditMode())
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
            else
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);

            context.RegisterCompilationStartAction(OnCompilationStartAction);
        }

        private void OnCompilationStartAction(CompilationStartAnalysisContext ctx)
        {
            var analyzer = new WeakHashingCompilationAnalyzer(Configuration.GetOrCreate(ctx));
            ctx.RegisterSyntaxNodeAction(actionContext => analyzer.VisitInvocationSyntaxNode(actionContext, CSharpSyntaxNodeHelper.Default),
                                         CSharp.SyntaxKind.InvocationExpression);

            ctx.RegisterSyntaxNodeAction(analyzer.VisitMemberAccessSyntaxNode,
                                         CSharp.SyntaxKind.SimpleMemberAccessExpression);

            ctx.RegisterSyntaxNodeAction(analyzer.VisitObjectCreationSyntaxNode,
                                         CSharp.SyntaxKind.ObjectCreationExpression);
        }
    }

    [DiagnosticAnalyzer(LanguageNames.VisualBasic)]
    public class WeakHashingAnalyzerVisualBasic: WeakHashingAnalyzer
    {
        public override void Initialize(AnalysisContext context)
        {
            if (!Debugger.IsAttached) // prefer single thread for debugging in development
                context.EnableConcurrentExecution();

            if (context.IsAuditMode())
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
            else
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);

            context.RegisterCompilationStartAction(OnCompilationStartAction);
        }

        private void OnCompilationStartAction(CompilationStartAnalysisContext ctx)
        {
            var analyzer = new WeakHashingCompilationAnalyzer(Configuration.GetOrCreate(ctx));
            ctx.RegisterSyntaxNodeAction(actionContext => analyzer.VisitInvocationSyntaxNode(actionContext, VBSyntaxNodeHelper.Default),
                                         VB.SyntaxKind.InvocationExpression);

            ctx.RegisterSyntaxNodeAction(analyzer.VisitMemberAccessSyntaxNode,
                                         VB.SyntaxKind.SimpleMemberAccessExpression);

            ctx.RegisterSyntaxNodeAction(analyzer.VisitObjectCreationSyntaxNode,
                                         VB.SyntaxKind.ObjectCreationExpression);
        }
    }

    public abstract class WeakHashingAnalyzer : DiagnosticAnalyzer
    {
        public static readonly DiagnosticDescriptor Md5Rule  = LocaleUtil.GetDescriptor("SCS0006", args: new[] { "MD5" });
        public static readonly DiagnosticDescriptor Sha1Rule = LocaleUtil.GetDescriptor("SCS0006", args: new[] { "SHA1" });
        public static readonly DiagnosticDescriptor UnknownHashRule = LocaleUtil.GetDescriptor("SCS0006", titleId:"title2", descriptionId: "description_unknown");
        public const string Sha1TypeName = "System.Security.Cryptography.SHA1";
        public const string Md5TypeName  = "System.Security.Cryptography.MD5";

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(Md5Rule, Sha1Rule);

        public static readonly string[] TypeNames = new [] { Sha1TypeName, Md5TypeName };
        public static readonly Dictionary<string, DiagnosticDescriptor> Rules = new Dictionary<string, DiagnosticDescriptor>
        {
            { Sha1TypeName, Sha1Rule },
            { Md5TypeName,  Md5Rule }
        };
    }

    internal class WeakHashingDiagnosticGroup
    {
        public string TypeName { get; }
        public DiagnosticDescriptor Rule { get; }

        public WeakHashingDiagnosticGroup(string typeName, DiagnosticDescriptor rule)
        {
            TypeName = typeName;
            Rule = rule;
        }
    }

    internal class WeakHashingCompilationAnalyzer
    {
        private class DiagnosticComparer : IEqualityComparer<Diagnostic>
        {
            public bool Equals(Diagnostic x, Diagnostic y)
            {
                if (x.Id != y.Id)
                    return false;

                var xLineSpan = x.Location.GetLineSpan();
                var yLineSpan = y.Location.GetLineSpan();

                if (xLineSpan.Path != yLineSpan.Path)
                    return false;

                return xLineSpan.StartLinePosition == yLineSpan.StartLinePosition;
            }

            public int GetHashCode(Diagnostic x)
            {
                unchecked
                {
                    var hashCode = x.Id.GetHashCode();
                    var lineSpan = x.Location.GetLineSpan();
                    hashCode = (hashCode * 397) ^ lineSpan.Path.GetHashCode();
                    hashCode = (hashCode * 397) ^ lineSpan.StartLinePosition.GetHashCode();
                    return hashCode;
                }
            }
        }

        private readonly ConcurrentDictionary<Diagnostic, byte> Diagnostics = new ConcurrentDictionary<Diagnostic, byte>(new DiagnosticComparer());

        private readonly Configuration Config;

        public WeakHashingCompilationAnalyzer(Configuration config)
        {
            Config = config;
        }

        private void Report(Diagnostic diagnostic, SyntaxNodeAnalysisContext ctx)
        {
            if (Diagnostics.TryAdd(diagnostic, 0))
                ctx.ReportDiagnostic(diagnostic);
        }

        public void VisitObjectCreationSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            var symbol = ctx.SemanticModel.GetSymbolInfo(ctx.Node).Symbol;
            if (symbol == null)
                return;

            CheckSymbol(symbol.ContainingType, ctx);
        }

        private bool CheckSymbol(
            ITypeSymbol symbol,
            SyntaxNodeAnalysisContext ctx
        )
        {
            if (symbol.IsTypeOrDerivedFrom(WeakHashingAnalyzer.TypeNames, out var foundType))
            {
                var diagnostic = Diagnostic.Create(WeakHashingAnalyzer.Rules[foundType], ctx.Node.GetLocation());
                Report(diagnostic, ctx);
                return true;
            }

            return false;
        }

        public void VisitMemberAccessSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            var symbol = ctx.SemanticModel.GetSymbolInfo(ctx.Node).Symbol;
            switch (symbol)
            {
                case null:
                    return;
                case IMethodSymbol methodSymbol:
                    CheckSymbol(methodSymbol.ReturnType, ctx);
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
                    var ret = CheckSymbol(method.ReturnType, ctx);
                    if (ret)
                        return;

                    break;
            }

            var symbolTypeName = symbol.GetTypeName();

            switch (symbolTypeName)
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

        private DiagnosticDescriptor CheckParameter(SyntaxNodeAnalysisContext ctx, SyntaxNodeHelper nodeHelper)
        {
            Optional<object> argValue = ctx.SemanticModel.GetConstantValue(nodeHelper.GetCallArgumentExpressionNodes(ctx.Node).First());

            if (!argValue.HasValue)
            {
                if (Config.AuditMode)
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
