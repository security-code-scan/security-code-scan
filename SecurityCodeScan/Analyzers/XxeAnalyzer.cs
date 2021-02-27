#nullable disable
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Analyzers.Locale;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using VB = Microsoft.CodeAnalysis.VisualBasic;
using System.Diagnostics;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class XxeDiagnosticAnalyzerCSharp : XxeDiagnosticAnalyzer
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

        private void OnCompilationStartAction(CompilationStartAnalysisContext context)
        {
            Compilation compilation = context.Compilation;
            var         xmlTypes    = new XxeSecurityTypes(compilation);

            if (!xmlTypes.IsAnyTypeReferenced())
                return;

            (bool dotnetCore, Version version) = compilation.GetDotNetFrameworkVersion();
            if (!dotnetCore && version == null)
                return;

            context.RegisterCodeBlockStartAction<CSharp.SyntaxKind>(
                c =>
                {
                    var analyzer = new XxeAnalyzerCSharp(xmlTypes, dotnetCore || version >= new Version(4, 5, 2));
                    analyzer.RegisterSyntaxNodeAction(c);
                    c.RegisterCodeBlockEndAction(analyzer.AnalyzeCodeBlockEnd);
                });
        }
    }

    [DiagnosticAnalyzer(LanguageNames.VisualBasic)]
    public class XxeDiagnosticAnalyzerVisualBasic : XxeDiagnosticAnalyzer
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

        private void OnCompilationStartAction(CompilationStartAnalysisContext context)
        {
            Compilation compilation = context.Compilation;
            var         xmlTypes    = new XxeSecurityTypes(compilation);

            if (!xmlTypes.IsAnyTypeReferenced())
                return;

            (bool dotnetCore, Version version) = compilation.GetDotNetFrameworkVersion();
            if (!dotnetCore && version == null)
                return;

            context.RegisterCodeBlockStartAction<VB.SyntaxKind>(
                c =>
                {
                    var analyzer = new XxeAnalyzerVBasic(xmlTypes, dotnetCore || version >= new Version(4, 5, 2));
                    analyzer.RegisterSyntaxNodeAction(c);
                    c.RegisterCodeBlockEndAction(analyzer.AnalyzeCodeBlockEnd);
                });
        }
    }

    public abstract class XxeDiagnosticAnalyzer : DiagnosticAnalyzer
    {
        internal static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0007");

        private static readonly ImmutableArray<DiagnosticDescriptor> Rules = ImmutableArray.Create(Rule);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => Rules;
    }

    internal class XxeSecurityTypes
    {
        public INamedTypeSymbol XmlDocument              { get; }
        public INamedTypeSymbol XmlDataDocument          { get; }
        public INamedTypeSymbol ConfigXmlDocument        { get; }
        public INamedTypeSymbol XmlFileInfoDocument      { get; }
        public INamedTypeSymbol XmlTransformableDocument { get; }
        public INamedTypeSymbol XPathDocument            { get; }
        public INamedTypeSymbol XmlSchema                { get; }
        public INamedTypeSymbol XmlTextReader            { get; }
        public INamedTypeSymbol XmlReader                { get; }
        public INamedTypeSymbol XmlReaderSettings        { get; }
        public INamedTypeSymbol XmlSecureResolver        { get; }

        public XxeSecurityTypes(Compilation compilation)
        {
            XmlDocument              = compilation.GetTypeByMetadataName("System.Xml.XmlDocument");
            XmlDataDocument          = compilation.GetTypeByMetadataName("System.Xml.XmlDataDocument");
            ConfigXmlDocument        = compilation.GetTypeByMetadataName("System.Configuration.ConfigXmlDocument");
            XmlFileInfoDocument      = compilation.GetTypeByMetadataName("Microsoft.Web.XmlTransform.XmlFileInfoDocument");
            XmlTransformableDocument = compilation.GetTypeByMetadataName("Microsoft.Web.XmlTransform.XmlTransformableDocument");
            XPathDocument            = compilation.GetTypeByMetadataName("System.Xml.XPath.XPathDocument");
            XmlSchema                = compilation.GetTypeByMetadataName("System.Xml.Schema.XmlSchema");
            XmlTextReader            = compilation.GetTypeByMetadataName("System.Xml.XmlTextReader");
            XmlReader                = compilation.GetTypeByMetadataName("System.Xml.XmlReader");
            XmlReaderSettings        = compilation.GetTypeByMetadataName("System.Xml.XmlReaderSettings");
            XmlSecureResolver        = compilation.GetTypeByMetadataName("System.Xml.XmlSecureResolver");
        }

        public bool IsAnyTypeReferenced()
        {
            return XmlDocument              != null ||
                   XmlDataDocument          != null ||
                   ConfigXmlDocument        != null ||
                   XmlFileInfoDocument      != null ||
                   XmlTransformableDocument != null ||
                   XPathDocument            != null ||
                   XmlSchema                != null ||
                   XmlTextReader            != null ||
                   XmlReader                != null ||
                   XmlReaderSettings        != null ||
                   XmlSecureResolver        != null;
        }
    }

    internal class XxeAnalyzer
    {
        protected XxeAnalyzer(XxeSecurityTypes xmlTypes, SyntaxNodeHelper helper, bool areDefaultsSecure)
        {
            XmlTypes = xmlTypes;
            SyntaxNodeHelper = helper;
            AreDefaultsSecure = areDefaultsSecure;
        }

        private readonly XxeSecurityTypes XmlTypes;
        private readonly bool             AreDefaultsSecure;
        private readonly SyntaxNodeHelper SyntaxNodeHelper;

        private readonly HashSet<SyntaxNode> OjectCreationOperationsAnalyzed = new HashSet<SyntaxNode>();
        private readonly Dictionary<ISymbol, XmlDocumentEnvironment> XmlDocumentEnvironments = new Dictionary<ISymbol, XmlDocumentEnvironment>();
        private readonly Dictionary<SyntaxNode, XmlDocumentEnvironment> TempXmlDocumentEnvironments = new Dictionary<SyntaxNode, XmlDocumentEnvironment>();
        private readonly Dictionary<ISymbol, XmlTextReaderEnvironment> XmlTextReaderEnvironments = new Dictionary<ISymbol, XmlTextReaderEnvironment>();
        private readonly Dictionary<SyntaxNode, XmlTextReaderEnvironment> TempXmlTextReaderEnvironments = new Dictionary<SyntaxNode, XmlTextReaderEnvironment>();
        private readonly Dictionary<ISymbol, XmlReaderSettingsEnvironment> XmlReaderSettingsEnvironments = new Dictionary<ISymbol, XmlReaderSettingsEnvironment>();
        private readonly Dictionary<SyntaxNode, XmlReaderSettingsEnvironment> TempXmlReaderSettingsEnvironments = new Dictionary<SyntaxNode, XmlReaderSettingsEnvironment>();

        private class Environment
        {
            protected Environment(ISymbol type, SyntaxNode definition)
            {
                Type = type;
                Definition = definition;
            }

            public          SyntaxNode Definition;
            public          bool       IsSecureResolver;
            public readonly ISymbol    Type;
        }

        private class XmlDocumentEnvironment : Environment
        {
            public bool WasSafeFunctionCalled;
            public bool WasSomethingElseCalled;

            public XmlDocumentEnvironment(bool isTargetFrameworkSecure, ISymbol type, SyntaxNode definition) : base(type, definition)
            {
                // for .NET framework >= 4.5.2, the default value for XmlResolver property is null
                IsSecureResolver = isTargetFrameworkSecure;
            }
        }

        private class XmlTextReaderEnvironment : Environment
        {
            public bool       IsDtdProcessingDisabled;

            public XmlTextReaderEnvironment(bool isTargetFrameworkSecure, ISymbol type, SyntaxNode definition) : base(type, definition)
            {
                // for .NET framework >= 4.5.2, the default value for XmlResolver property is null
                IsSecureResolver = isTargetFrameworkSecure;
            }
        }

        private class XmlReaderSettingsEnvironment : Environment
        {
            public bool       IsDtdProcessingDisabled;
            public bool       IsMaxCharactersFromEntitiesLimited; // todo: stub to extend to check for xxe bombs

            public XmlReaderSettingsEnvironment(bool isTargetFrameworkSecure, ISymbol type, SyntaxNode definition) : base (type, definition)
            {
                IsDtdProcessingDisabled = true;
                // for .NET framework >= 4.5.2, the default value for XmlResolver property is null
                IsSecureResolver = isTargetFrameworkSecure;
                IsMaxCharactersFromEntitiesLimited = isTargetFrameworkSecure;
            }
        }

        public void AnalyzeCodeBlockEnd(CodeBlockAnalysisContext context)
        {
            foreach (var env in XmlDocumentEnvironments.Values)
            {
                if (env.IsSecureResolver)
                    continue;

                // Special case: Load is overridden and resolver is set to null in all versions, skip it if other functions were not called
                if (ReferenceEquals(env.Type, XmlTypes.ConfigXmlDocument) && env.WasSafeFunctionCalled && !env.WasSomethingElseCalled)
                    continue;

                if (ReferenceEquals(env.Type, XmlTypes.XmlDataDocument) && env.WasSafeFunctionCalled && !env.WasSomethingElseCalled)
                    continue;

                var diag = Diagnostic.Create(XxeDiagnosticAnalyzer.Rule, env.Definition.GetLocation());
                context.ReportDiagnostic(diag);
            }

            foreach (var env in TempXmlDocumentEnvironments.Values)
            {
                if (env.IsSecureResolver)
                    continue;

                // Special case: Load is overridden and resolver is set to null in all versions, skip it if other functions were not called
                if (ReferenceEquals(env.Type, XmlTypes.ConfigXmlDocument) && env.WasSafeFunctionCalled && !env.WasSomethingElseCalled)
                    continue;

                if (ReferenceEquals(env.Type, XmlTypes.XmlDataDocument) && env.WasSafeFunctionCalled && !env.WasSomethingElseCalled)
                    continue;

                var diag = Diagnostic.Create(XxeDiagnosticAnalyzer.Rule, env.Definition.GetLocation());
                context.ReportDiagnostic(diag);
            }

            foreach (var env in XmlTextReaderEnvironments.Values)
            {
                if (!env.IsSecureResolver && !env.IsDtdProcessingDisabled)
                {
                    var diag = Diagnostic.Create(XxeDiagnosticAnalyzer.Rule, env.Definition.GetLocation());
                    context.ReportDiagnostic(diag);
                }
            }

            foreach (var env in TempXmlTextReaderEnvironments.Values)
            {
                if (!env.IsSecureResolver && !env.IsDtdProcessingDisabled)
                {
                    var diag = Diagnostic.Create(XxeDiagnosticAnalyzer.Rule, env.Definition.GetLocation());
                    context.ReportDiagnostic(diag);
                }
            }

            foreach (var env in XmlReaderSettingsEnvironments.Values)
            {
                if (!env.IsSecureResolver && !env.IsDtdProcessingDisabled)
                {
                    var diag = Diagnostic.Create(XxeDiagnosticAnalyzer.Rule, env.Definition.GetLocation());
                    context.ReportDiagnostic(diag);
                }
            }

            foreach (var env in TempXmlReaderSettingsEnvironments.Values)
            {
                if (!env.IsSecureResolver && !env.IsDtdProcessingDisabled)
                {
                    var diag = Diagnostic.Create(XxeDiagnosticAnalyzer.Rule, env.Definition.GetLocation());
                    context.ReportDiagnostic(diag);
                }
            }
        }

        protected void AnalyzeAssignment(SyntaxNode node, SemanticModel model, Action<Diagnostic> reportDiagnostic)
        {
            SyntaxNode lhs = SyntaxNodeHelper.GetAssignmentLeftNode(node);
            SyntaxNode rhs = SyntaxNodeHelper.GetAssignmentRightNode(node);
            if (rhs == null || lhs == null)
                return;

            var variableSymbol = SyntaxNodeHelper.GetSymbol(lhs, model);
            switch (variableSymbol)
            {
                case IPropertySymbol propertySymbol:
                    var variable = SyntaxNodeHelper.GetMemberAccessExpressionNode(lhs);
                    if (variable == null)
                        break;
                    AnalyzePropertyAssignment(propertySymbol, variable, rhs, model);
                    break;
                //case ILocalSymbol localSymbol:
                //    AnalyzeObjectCreation(localSymbol, rhs, model, reportDiagnostic);
                //    break;
                default:
                    return;
            }
        }

        protected void AnalyzeVariableDeclaration(SyntaxNode node, SemanticModel model, Action<Diagnostic> reportDiagnostic)
        {
            SyntaxNode lhs = SyntaxNodeHelper.GetAssignmentLeftNode(node);
            SyntaxNode rhs = SyntaxNodeHelper.GetAssignmentRightNode(node);
            if (rhs == null || lhs == null)
                return;

            var variableSymbol = SyntaxNodeHelper.GetSymbol(lhs, model);
            if (variableSymbol == null)
                return;

            AnalyzeObjectCreation(variableSymbol, rhs, model, reportDiagnostic);
        }

        private T GetEnvironment<T>(ISymbol                   symbol,
                                    SyntaxNode                node,
                                    Dictionary<ISymbol, T>    permanentEnvironments,
                                    Dictionary<SyntaxNode, T> temporaryEnvironments)
        {
            if (permanentEnvironments.TryGetValue(symbol, out var env))
                return env;

            if (temporaryEnvironments.TryGetValue(node, out env))
                return env;

            // external symbol or class member, assume defaults
            env = (T)Activator.CreateInstance(typeof(T), AreDefaultsSecure, SecurityDiagnosticHelpers.GetTypeSymbol(symbol), node);
            permanentEnvironments[symbol] = env;

            return env;
        }

        private void AnalyzePropertyAssignment(IPropertySymbol symbol, SyntaxNode lhs, SyntaxNode rhs, SemanticModel model)
        {
            if (SecurityDiagnosticHelpers.IsXmlDocumentXmlResolverPropertyDerived(symbol, XmlTypes))
            {
                ISymbol lhsExpressionSymbol = SyntaxNodeHelper.GetSymbol(lhs, model);
                if (lhsExpressionSymbol == null)
                {
                    return;
                }

                var env = GetEnvironment(lhsExpressionSymbol, lhs, XmlDocumentEnvironments, TempXmlDocumentEnvironments);

                bool oldIsSecureResolver = env.IsSecureResolver;
                env.IsSecureResolver = SyntaxNodeHelper.NodeHasConstantValueNull(rhs, model) ||
                                       SecurityDiagnosticHelpers.IsXmlSecureResolverType(model.GetTypeInfo(rhs).Type, XmlTypes);

                if (oldIsSecureResolver && !env.IsSecureResolver)
                    env.Definition = rhs;
            }
            else if (SecurityDiagnosticHelpers.IsXmlTextReaderXmlResolverPropertyDerived(symbol, XmlTypes))
            {
                ISymbol lhsExpressionSymbol = SyntaxNodeHelper.GetSymbol(lhs, model);
                if (lhsExpressionSymbol == null)
                {
                    return;
                }

                var env = GetEnvironment(lhsExpressionSymbol, lhs, XmlTextReaderEnvironments, TempXmlTextReaderEnvironments);

                bool oldIsSecureResolver = env.IsSecureResolver;
                env.IsSecureResolver = SyntaxNodeHelper.NodeHasConstantValueNull(rhs, model) ||
                                       SecurityDiagnosticHelpers.IsXmlSecureResolverType(model.GetTypeInfo(rhs).Type, XmlTypes);

                if (oldIsSecureResolver && !env.IsSecureResolver)
                    env.Definition = rhs;
            }
            else if (SecurityDiagnosticHelpers.IsXmlTextReaderDtdProcessingPropertyDerived(symbol, XmlTypes))
            {
                ISymbol lhsExpressionSymbol = SyntaxNodeHelper.GetSymbol(lhs, model);
                if (lhsExpressionSymbol == null)
                {
                    return;
                }

                var env = GetEnvironment(lhsExpressionSymbol, lhs, XmlTextReaderEnvironments, TempXmlTextReaderEnvironments);

                bool oldIsDtdProcessingDisabled = env.IsDtdProcessingDisabled;
                env.IsDtdProcessingDisabled = !SyntaxNodeHelper.NodeHasConstantValue(rhs, model, 2 /*DtdProcessing.Parse*/);

                if (oldIsDtdProcessingDisabled && !env.IsDtdProcessingDisabled)
                    env.Definition = rhs;
            }
            else if (SecurityDiagnosticHelpers.IsXmlTextReaderProhibitDtdPropertyDerived(symbol, XmlTypes))
            {
                ISymbol lhsExpressionSymbol = SyntaxNodeHelper.GetSymbol(lhs, model);
                if (lhsExpressionSymbol == null)
                {
                    return;
                }

                var env = GetEnvironment(lhsExpressionSymbol, lhs, XmlTextReaderEnvironments, TempXmlTextReaderEnvironments);

                bool oldIsDtdProcessingDisabled = env.IsDtdProcessingDisabled;
                env.IsDtdProcessingDisabled = !SyntaxNodeHelper.NodeHasConstantValue(rhs, model, false);

                if (oldIsDtdProcessingDisabled && !env.IsDtdProcessingDisabled)
                    env.Definition = rhs;
            }
            else if (SecurityDiagnosticHelpers.IsXmlReaderSettingsDtdProcessingProperty(symbol, XmlTypes))
            {
                ISymbol lhsExpressionSymbol = SyntaxNodeHelper.GetSymbol(lhs, model);
                if (lhsExpressionSymbol == null)
                {
                    return;
                }

                var env = GetEnvironment(lhsExpressionSymbol, lhs, XmlReaderSettingsEnvironments, TempXmlReaderSettingsEnvironments);

                bool oldIsDtdProcessingDisabled = env.IsDtdProcessingDisabled;
                env.IsDtdProcessingDisabled = !SyntaxNodeHelper.NodeHasConstantValue(rhs, model, 2 /*DtdProcessing.Parse*/);

                if (oldIsDtdProcessingDisabled && !env.IsDtdProcessingDisabled)
                    env.Definition = rhs;
            }
            else if (SecurityDiagnosticHelpers.IsXmlReaderSettingsProhibitDtdProperty(symbol, XmlTypes))
            {
                var lhsExpressionSymbol = SyntaxNodeHelper.GetSymbol(lhs, model);
                if (lhsExpressionSymbol == null)
                {
                    return;
                }

                var env = GetEnvironment(lhsExpressionSymbol, lhs, XmlReaderSettingsEnvironments, TempXmlReaderSettingsEnvironments);

                bool oldIsDtdProcessingDisabled = env.IsDtdProcessingDisabled;
                env.IsDtdProcessingDisabled = !SyntaxNodeHelper.NodeHasConstantValue(rhs, model, false);

                if (oldIsDtdProcessingDisabled && !env.IsDtdProcessingDisabled)
                    env.Definition = rhs;
            }
            else if (SecurityDiagnosticHelpers.IsXmlReaderSettingsMaxCharactersFromEntitiesProperty(symbol, XmlTypes))
            {
                ISymbol lhsExpressionSymbol = SyntaxNodeHelper.GetSymbol(lhs, model);
                if (lhsExpressionSymbol == null)
                {
                    return;
                }

                var env = GetEnvironment(lhsExpressionSymbol, lhs, XmlReaderSettingsEnvironments, TempXmlReaderSettingsEnvironments);

                //bool oldIsMaxCharactersFromEntitiesLimited = env.IsMaxCharactersFromEntitiesLimited;
                env.IsMaxCharactersFromEntitiesLimited = !SyntaxNodeHelper.NodeHasConstantValue(rhs, model, 0);

                //if (!env.IsMaxCharactersFromEntitiesLimited)
                //    env.Definition = rhs;
            }
        }

        protected void AnalyzeObjectCreation(ISymbol            variableSymbol,
                                             SyntaxNode         objectCreationNode,
                                             SemanticModel      model,
                                             Action<Diagnostic> reportDiagnostic)
        {
            if (!(SyntaxNodeHelper.GetSymbol(objectCreationNode, model) is IMethodSymbol symbol))
                return;

            if (OjectCreationOperationsAnalyzed.Contains(objectCreationNode))
                return;

            OjectCreationOperationsAnalyzed.Add(objectCreationNode);

            if (SecurityDiagnosticHelpers.IsXmlDocumentCtorDerived(symbol, XmlTypes))
            {
                var env = AnalyzeObjectCreationForXmlDocument(symbol, objectCreationNode, model);
                if (variableSymbol != null)
                    XmlDocumentEnvironments[variableSymbol] = env;
                else
                    TempXmlDocumentEnvironments[objectCreationNode] = env;
            }
            else if (SecurityDiagnosticHelpers.IsXmlTextReaderCtorDerived(symbol, XmlTypes))
            {
                var env = AnalyzeObjectCreationForXmlTextReader(symbol, objectCreationNode, model);
                if (variableSymbol != null)
                    XmlTextReaderEnvironments[variableSymbol] = env;
                else
                    TempXmlTextReaderEnvironments[objectCreationNode] = env;
            }
            else if (SecurityDiagnosticHelpers.IsXmlReaderSettingsCtor(symbol, XmlTypes))
            {
                var env = AnalyzeObjectCreationForXmlReaderSettings(objectCreationNode, model);
                if (variableSymbol != null)
                    XmlReaderSettingsEnvironments[variableSymbol] = env;
                else
                    TempXmlReaderSettingsEnvironments[objectCreationNode] = env;
            }
            else if (symbol.MatchMethodByName(XmlTypes.XPathDocument, WellKnownMemberNames.InstanceConstructorName))
            {
                if (AreDefaultsSecure)
                    return;

                if (SecurityDiagnosticHelpers.GetSpecifiedParameterIndex(symbol,
                                                                         XmlTypes,
                                                                         SecurityDiagnosticHelpers.IsXmlReaderType) == 0)
                {
                    return;
                }

                var diag = Diagnostic.Create(XxeDiagnosticAnalyzer.Rule, objectCreationNode.GetLocation());
                reportDiagnostic(diag);
            }
        }

        private XmlDocumentEnvironment AnalyzeObjectCreationForXmlDocument(ISymbol symbol, SyntaxNode node, SemanticModel model)
        {
            var env = new XmlDocumentEnvironment(AreDefaultsSecure, symbol.ContainingType, node);

            if (!ReferenceEquals(symbol.ContainingType, XmlTypes.XmlDocument) &&
                !ReferenceEquals(symbol.ContainingType, XmlTypes.XmlDataDocument) &&
                !ReferenceEquals(symbol.ContainingType, XmlTypes.ConfigXmlDocument) &&
                !ReferenceEquals(symbol.ContainingType, XmlTypes.XmlFileInfoDocument) &&
                !ReferenceEquals(symbol.ContainingType, XmlTypes.XmlTransformableDocument))
            {
                // We assume the design of derived type is secure
                env.IsSecureResolver = true;
            }

            foreach (SyntaxNode arg in SyntaxNodeHelper.GetObjectInitializerExpressionNodes(node))
            {
                SyntaxNode argLhs = SyntaxNodeHelper.GetAssignmentLeftNode(arg);
                SyntaxNode argRhs = SyntaxNodeHelper.GetAssignmentRightNode(arg);

                if (!SecurityDiagnosticHelpers.IsXmlDocumentXmlResolverPropertyDerived(SyntaxNodeHelper.GetSymbol(argLhs, model), XmlTypes))
                    continue;

                env.IsSecureResolver = SyntaxNodeHelper.NodeHasConstantValueNull(argRhs, model) ||
                                       SecurityDiagnosticHelpers.IsXmlSecureResolverType(model.GetTypeInfo(argRhs).Type, XmlTypes);
                break;
            }

            return env;
        }

        private XmlReaderSettingsEnvironment AnalyzeObjectCreationForXmlReaderSettings(SyntaxNode node, SemanticModel model)
        {
            var env = new XmlReaderSettingsEnvironment(AreDefaultsSecure, XmlTypes.XmlReaderSettings, node);

            foreach (SyntaxNode arg in SyntaxNodeHelper.GetObjectInitializerExpressionNodes(node))
            {
                SyntaxNode argLhs = SyntaxNodeHelper.GetAssignmentLeftNode(arg);
                SyntaxNode argRhs = SyntaxNodeHelper.GetAssignmentRightNode(arg);
                ISymbol argLhsSymbol = SyntaxNodeHelper.GetSymbol(argLhs, model);

                if (SecurityDiagnosticHelpers.IsXmlReaderSettingsXmlResolverProperty(SyntaxNodeHelper.GetSymbol(argLhs, model), XmlTypes))
                {
                    env.IsSecureResolver = SyntaxNodeHelper.NodeHasConstantValueNull(argRhs, model) ||
                                           SecurityDiagnosticHelpers.IsXmlSecureResolverType(model.GetTypeInfo(argRhs).Type, XmlTypes);
                }
                else if (SecurityDiagnosticHelpers.IsXmlReaderSettingsDtdProcessingProperty(argLhsSymbol, XmlTypes))
                {
                    env.IsDtdProcessingDisabled = !SyntaxNodeHelper.NodeHasConstantValue(argRhs, model, 2/*DtdProcessing.Parse*/);
                }
                else if (SecurityDiagnosticHelpers.IsXmlReaderSettingsProhibitDtdProperty(argLhsSymbol, XmlTypes))
                {
                    env.IsDtdProcessingDisabled = !SyntaxNodeHelper.NodeHasConstantValue(argRhs, model, false);
                }
                else if (SecurityDiagnosticHelpers.IsXmlReaderSettingsMaxCharactersFromEntitiesProperty(argLhsSymbol, XmlTypes))
                {
                    env.IsMaxCharactersFromEntitiesLimited = !SyntaxNodeHelper.NodeHasConstantValue(argRhs, model, 0);
                }
            }

            return env;
        }

        private XmlTextReaderEnvironment AnalyzeObjectCreationForXmlTextReader(IMethodSymbol symbol, SyntaxNode node, SemanticModel model)
        {
            var env = new XmlTextReaderEnvironment(AreDefaultsSecure, symbol, node);

            if (!ReferenceEquals(symbol.ContainingType, XmlTypes.XmlTextReader))
            {
                // We assume the design of derived type is secure
                env.IsDtdProcessingDisabled = true;
                env.IsSecureResolver = true;
            }

            foreach (SyntaxNode arg in SyntaxNodeHelper.GetObjectInitializerExpressionNodes(node))
            {
                SyntaxNode argLhs = SyntaxNodeHelper.GetAssignmentLeftNode(arg);
                SyntaxNode argRhs = SyntaxNodeHelper.GetAssignmentRightNode(arg);
                ISymbol argLhsSymbol = SyntaxNodeHelper.GetSymbol(argLhs, model);

                if (SecurityDiagnosticHelpers.IsXmlTextReaderXmlResolverPropertyDerived(argLhsSymbol, XmlTypes))
                {
                    env.IsSecureResolver = SyntaxNodeHelper.NodeHasConstantValueNull(argRhs, model) ||
                                           SecurityDiagnosticHelpers.IsXmlSecureResolverType(model.GetTypeInfo(argRhs).Type, XmlTypes);
                }
                else if (SecurityDiagnosticHelpers.IsXmlTextReaderDtdProcessingPropertyDerived(argLhsSymbol, XmlTypes))
                {
                    env.IsDtdProcessingDisabled = !SyntaxNodeHelper.NodeHasConstantValue(argRhs, model, 2/*DtdProcessing.Parse*/);
                }
                else if (SecurityDiagnosticHelpers.IsXmlTextReaderProhibitDtdPropertyDerived(argLhsSymbol, XmlTypes))
                {
                    env.IsDtdProcessingDisabled = !SyntaxNodeHelper.NodeHasConstantValue(argRhs, model, false);
                }
            }

            return env;
        }

        protected void AnalyzeInvocation(SyntaxNode node, SemanticModel model, Action<Diagnostic> reportDiagnostic)
        {
            IMethodSymbol method = SyntaxNodeHelper.GetCalleeMethodSymbol(node, model);
            if (method == null)
            {
                return;
            }

            if (method.MatchMethodByName(XmlTypes.XmlSchema, "Read"))
            {
                if (!AreDefaultsSecure &&
                    SecurityDiagnosticHelpers.GetSpecifiedParameterIndex(method,
                                                                         XmlTypes,
                                                                         SecurityDiagnosticHelpers.IsXmlReaderType) < 0)
                {
                    var diag = Diagnostic.Create(XxeDiagnosticAnalyzer.Rule, node.GetLocation());
                    reportDiagnostic(diag);
                }
            }
            else if (method.MatchMethodDerivedByName(XmlTypes.XmlReader, "Create"))
            {
                int xmlReaderSettingsIndex = SecurityDiagnosticHelpers.GetXmlReaderSettingsParameterIndex(method, XmlTypes);

                if (xmlReaderSettingsIndex < 0)
                    return;

                SyntaxNode settingsNode = SyntaxNodeHelper.GetInvocationArgumentExpressionNodes(node).ElementAt(xmlReaderSettingsIndex);
                XmlReaderSettingsEnvironment env;
                if (SyntaxNodeHelper.IsObjectConstructionForTemporaryObject(settingsNode))
                {
                    OjectCreationOperationsAnalyzed.Add(settingsNode);
                    env                                             = AnalyzeObjectCreationForXmlReaderSettings(settingsNode, model);
                    TempXmlReaderSettingsEnvironments[settingsNode] = env;
                }
                else
                {
                    ISymbol settingsSymbol = SyntaxNodeHelper.GetSymbol(settingsNode, model);
                    XmlReaderSettingsEnvironments.TryGetValue(settingsSymbol, out env);
                }

                if (env == null)
                {
                    // symbol for settings is not found => passed in without any change => assume defaults
                    if (!AreDefaultsSecure)
                        reportDiagnostic(Diagnostic.Create(XxeDiagnosticAnalyzer.Rule, node.GetLocation()));
                }
            }
            else if (ReferenceEquals(method.ContainingType, XmlTypes.ConfigXmlDocument))
            {
                var variableNode = SyntaxNodeHelper.GetMemberAccessExpressionNode(SyntaxNodeHelper.GetInvocationExpressionNode(node));
                if (variableNode == null)
                    throw new ArgumentException(nameof(variableNode));

                var variableSymbol = SyntaxNodeHelper.GetSymbol(variableNode, model);
                if (variableSymbol == null)
                    return;

                XmlDocumentEnvironment env;
                if (SyntaxNodeHelper.IsObjectConstructionForTemporaryObject(variableNode))
                {
                    OjectCreationOperationsAnalyzed.Add(variableNode);
                    env = AnalyzeObjectCreationForXmlDocument(variableSymbol, variableNode, model);
                    TempXmlDocumentEnvironments[variableNode] = env;
                }
                else
                {
                    XmlDocumentEnvironments.TryGetValue(variableSymbol, out env);
                }

                if (method.MatchMethodDerivedByName(XmlTypes.ConfigXmlDocument, "Load"))
                {
                    if (env != null)
                        env.WasSafeFunctionCalled = true;
                }
                else
                {
                    if (env == null)
                    {
                        // symbol not found => passed in without any change => assume defaults
                        if (!AreDefaultsSecure)
                            reportDiagnostic(Diagnostic.Create(XxeDiagnosticAnalyzer.Rule, node.GetLocation()));
                    }
                    else
                    {
                        env.WasSomethingElseCalled = true;
                    }
                }
            }
            else if (ReferenceEquals(method.ContainingType, XmlTypes.XmlDocument))
            {
                var variableNode = SyntaxNodeHelper.GetMemberAccessExpressionNode(SyntaxNodeHelper.GetInvocationExpressionNode(node));
                if (variableNode == null)
                    throw new ArgumentException(nameof(variableNode));

                var variableSymbol = SyntaxNodeHelper.GetSymbol(variableNode, model);
                if (variableSymbol == null)
                    return;

                XmlDocumentEnvironment env;
                if (SyntaxNodeHelper.IsObjectConstructionForTemporaryObject(variableNode))
                {
                    OjectCreationOperationsAnalyzed.Add(variableNode);
                    env                                       = AnalyzeObjectCreationForXmlDocument(variableSymbol, variableNode, model);
                    TempXmlDocumentEnvironments[variableNode] = env;
                }
                else
                {
                    XmlDocumentEnvironments.TryGetValue(variableSymbol, out env);
                }

                // Special case XmlDataDocument.LoadXml throws NotSupportedException
                if (env == null || !ReferenceEquals(env.Type, XmlTypes.XmlDataDocument))
                    return;

                // LoadXml is not overridden in XmlDataDocument, thus XmlTypes.XmlDocument
                if (method.MatchMethodDerivedByName(XmlTypes.XmlDocument, "LoadXml"))
                {
                    env.WasSafeFunctionCalled = true;
                }
                else
                {
                    env.WasSomethingElseCalled = true;
                }

            }
        }

        private static class SecurityDiagnosticHelpers
        {
            public static ITypeSymbol GetTypeSymbol(ISymbol symbol)
            {
                switch (symbol)
                {
                    case IFieldSymbol fieldSymbol:
                        return fieldSymbol.Type;
                    case ILocalSymbol localSymbol:
                        return localSymbol.Type;
                    case IParameterSymbol parameterSymbol:
                        return parameterSymbol.Type;
                    case IPropertySymbol propertySymbol:
                        return propertySymbol.Type;
                    default:
                        throw new ArgumentException(nameof(symbol));
                }
            }

            public static bool IsXmlDocumentCtorDerived(IMethodSymbol method, XxeSecurityTypes xmlTypes)
            {
                return method != null &&
                       method.MatchMethodDerivedByName(xmlTypes.XmlDocument, WellKnownMemberNames.InstanceConstructorName);
            }

            public static bool IsXmlDocumentXmlResolverPropertyDerived(ISymbol symbol, XxeSecurityTypes xmlTypes)
            {
                return IsSpecifiedPropertyDerived(symbol, xmlTypes.XmlDocument, "XmlResolver");
            }

            public static bool IsXmlTextReaderCtorDerived(IMethodSymbol method, XxeSecurityTypes xmlTypes)
            {
                return method != null
                       && method.MatchMethodDerivedByName(xmlTypes.XmlTextReader, WellKnownMemberNames.InstanceConstructorName);
            }

            public static bool IsXmlTextReaderXmlResolverPropertyDerived(ISymbol symbol, XxeSecurityTypes xmlTypes)
            {
                return IsSpecifiedPropertyDerived(symbol, xmlTypes.XmlTextReader, "XmlResolver");
            }

            public static bool IsXmlTextReaderDtdProcessingPropertyDerived(ISymbol symbol, XxeSecurityTypes xmlTypes)
            {
                return IsSpecifiedPropertyDerived(symbol, xmlTypes.XmlTextReader, "DtdProcessing");
            }

            public static bool IsXmlTextReaderProhibitDtdPropertyDerived(ISymbol symbol, XxeSecurityTypes xmlTypes)
            {
                return IsSpecifiedPropertyDerived(symbol, xmlTypes.XmlTextReader, "ProhibitDtd");
            }

            public static bool IsXmlReaderSettingsCtor(IMethodSymbol method, XxeSecurityTypes xmlTypes)
            {
                return method != null
                       && method.MatchMethodByName(xmlTypes.XmlReaderSettings, WellKnownMemberNames.InstanceConstructorName);
            }

            public static bool IsXmlReaderSettingsXmlResolverProperty(ISymbol symbol, XxeSecurityTypes xmlTypes)
            {
                return IsSpecifiedProperty(symbol, xmlTypes.XmlReaderSettings, "XmlResolver");
            }

            public static bool IsXmlReaderSettingsDtdProcessingProperty(ISymbol symbol, XxeSecurityTypes xmlTypes)
            {
                return IsSpecifiedProperty(symbol, xmlTypes.XmlReaderSettings, "DtdProcessing");
            }

            public static bool IsXmlReaderSettingsProhibitDtdProperty(ISymbol symbol, XxeSecurityTypes xmlTypes)
            {
                return IsSpecifiedProperty(symbol, xmlTypes.XmlReaderSettings, "ProhibitDtd");
            }

            public static bool IsXmlReaderSettingsMaxCharactersFromEntitiesProperty(ISymbol symbol, XxeSecurityTypes xmlTypes)
            {
                return IsSpecifiedProperty(symbol, xmlTypes.XmlReaderSettings, "MaxCharactersFromEntities");
            }

            public static bool IsXmlSecureResolverType(ITypeSymbol symbol, XxeSecurityTypes xmlTypes)
            {
                return symbol != null && symbol.DerivesFrom(xmlTypes.XmlSecureResolver, baseTypesOnly: true);
            }

            public static bool IsXmlReaderSettingsType(ITypeSymbol symbol, XxeSecurityTypes xmlTypes)
            {
                return ReferenceEquals(symbol, xmlTypes.XmlReaderSettings);
            }

            public static bool IsXmlReaderType(ITypeSymbol symbol, XxeSecurityTypes xmlTypes)
            {
                return ReferenceEquals(symbol, xmlTypes.XmlReader);
            }

            public static int GetXmlReaderSettingsParameterIndex(IMethodSymbol method, XxeSecurityTypes xmlTypes)
            {
                return GetSpecifiedParameterIndex(method, xmlTypes, IsXmlReaderSettingsType);
            }

            private static bool IsSpecifiedProperty(ISymbol symbol, INamedTypeSymbol namedType, string propertyName)
            {
                if (symbol == null || symbol.Kind != SymbolKind.Property)
                    return false;

                var property = (IPropertySymbol)symbol;
                return property.MatchPropertyByName(namedType, propertyName);
            }

            private static bool IsSpecifiedPropertyDerived(ISymbol symbol, INamedTypeSymbol namedType, string propertyName)
            {
                if (symbol == null || symbol.Kind != SymbolKind.Property)
                    return false;

                var property = (IPropertySymbol)symbol;
                return property.MatchPropertyDerivedByName(namedType, propertyName);
            }

            public static int GetSpecifiedParameterIndex(IMethodSymbol                             method,
                                                         XxeSecurityTypes                          xmlTypes,
                                                         Func<ITypeSymbol, XxeSecurityTypes, bool> func)
            {
                int index = -1;
                if (method == null)
                {
                    return index;
                }
                for (int i = 0; i < method.Parameters.Length; i++)
                {
                    ITypeSymbol parameter = method.Parameters[i].Type;
                    if (!func(parameter, xmlTypes))
                        continue;

                    index = i;
                    break;
                }
                return index;
            }
        }
    }
}
