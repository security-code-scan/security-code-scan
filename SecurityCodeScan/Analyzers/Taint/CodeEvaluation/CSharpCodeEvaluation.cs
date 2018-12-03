using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Reflection;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;

namespace SecurityCodeScan.Analyzers.Taint
{
    /// <summary>
    /// Symbolic execution of C# code
    /// </summary>
    internal class CSharpCodeEvaluation
    {
        public static List<TaintAnalyzerExtensionCSharp> Extensions { get; set; } = new List<TaintAnalyzerExtensionCSharp>();

        private Configuration ProjectConfiguration;

        private SyntaxNodeHelper SyntaxNodeHelper;

        public CSharpCodeEvaluation(SyntaxNodeHelper syntaxHelper, Configuration projectConfiguration)
        {
            SyntaxNodeHelper     = syntaxHelper;
            ProjectConfiguration = projectConfiguration;
        }

        public void VisitMethods(SyntaxNodeAnalysisContext ctx)
        {
            try
            {
                var state = new ExecutionState(ctx);

                foreach (var ext in Extensions)
                {
                    ext.VisitBegin(ctx.Node, state);
                }

                VisitNode(ctx.Node, state);

                foreach (var ext in Extensions)
                {
                    ext.VisitEnd(ctx.Node, state);
                }
            }
            catch (Exception e)
            {
                //Intercept the exception for logging. Otherwise, the analyzer fails silently.
                string errorMsg = $"Unhandled exception while visiting method {ctx.Node}\n{e.Message}";
                Logger.Log(errorMsg);
                if (e.InnerException != null)
                    Logger.Log($"{e.InnerException.Message}");
                Logger.Log($"\n{e.StackTrace}", false);
                throw;
            }
        }

        private VariableState VisitBlock(BlockSyntax node, ExecutionState state)
        {
            var lastState = new VariableState(node, VariableTaint.Unknown);
            return VisitStatements(node.Statements, state, lastState);
        }

        private VariableState VisitStatements(SyntaxList<StatementSyntax> statements, ExecutionState state, VariableState lastState)
        {
            foreach (StatementSyntax statement in statements)
            {
                var statementState = VisitNode(statement, state);
                lastState = statementState;

                foreach (var ext in Extensions)
                {
                    ext.VisitStatement(statement, state);
                }
            }

            return lastState;
        }

        private void TaintParameters(BaseMethodDeclarationSyntax node, ExecutionState state)
        {
            foreach (ParameterSyntax parameter in node.ParameterList.Parameters)
            {
                state.AddNewValue(ResolveIdentifier(parameter.Identifier),
                                  new VariableState(parameter, VariableTaint.Tainted));
            }
        }

        /// <summary>
        /// Entry point that visits the method statements.
        /// </summary>
        private VariableState VisitMethodDeclaration(BaseMethodDeclarationSyntax node, ExecutionState state)
        {
            if (ProjectConfiguration.AuditMode)
            {
                TaintParameters(node, state);
            }
            else
            {
                var symbol = state.AnalysisContext.SemanticModel.GetDeclaredSymbol(node);
                if (symbol != null)
                {
                    if (symbol.IsTaintEntryPoint(ProjectConfiguration.TaintEntryPoints))
                        TaintParameters(node, state);
                }
            }

            if (node.Body == null)
                return new VariableState(node, VariableTaint.Unknown);

            return VisitBlock(node.Body, state);
        }

        private VariableState VisitForEach(ForEachStatementSyntax node, ExecutionState state)
        {
            state.AddNewValue(ResolveIdentifier(node.Identifier), VisitExpression(node.Expression, state));
            return VisitNode(node.Statement, state);
        }

        /// <summary>
        /// Statement are all segment separate by semi-colon.
        /// </summary>
        /// <param name="node"></param>
        /// <param name="state"></param>
        private VariableState VisitNode(SyntaxNode node, ExecutionState state)
        {
            switch (node)
            {
                case PrefixUnaryExpressionSyntax prefixUnaryExpression:
                    return VisitNode(prefixUnaryExpression.Operand, state);
                case LocalDeclarationStatementSyntax declarationStatementSyntax:
                    return VisitLocalDeclaration(declarationStatementSyntax, state);
                case VariableDeclarationSyntax variableDeclarationSyntax:
                    return VisitVariableDeclaration(variableDeclarationSyntax, state);
                case ExpressionStatementSyntax expressionStatementSyntax:
                    return VisitExpressionStatement(expressionStatementSyntax, state);
                case ExpressionSyntax expressionSyntax:
                    return VisitExpression(expressionSyntax, state);
                case MethodDeclarationSyntax methodDeclarationSyntax:
                    return VisitMethodDeclaration(methodDeclarationSyntax, state);
                case ConstructorDeclarationSyntax constructorDeclarationSyntax:
                    return VisitMethodDeclaration(constructorDeclarationSyntax, state);
                case DestructorDeclarationSyntax destructorDeclarationSyntax:
                    return VisitMethodDeclaration(destructorDeclarationSyntax, state);
                case PropertyDeclarationSyntax propertyDeclarationSyntax:
                    return VisitPropertyDeclaration(propertyDeclarationSyntax, state);
                case ReturnStatementSyntax returnStatementSyntax:
                    if (returnStatementSyntax.Expression == null)
                        return new VariableState(node, VariableTaint.Unknown);

                    return VisitExpression(returnStatementSyntax.Expression, state);
                case ForEachStatementSyntax forEachSyntax:
                    return VisitForEach(forEachSyntax, state);
                case BlockSyntax blockSyntax:
                    return VisitBlock(blockSyntax, state);
                case FromClauseSyntax fromClauseSyntax:
                    return VisitFromClause(fromClauseSyntax, state);
                case WhereClauseSyntax whereClauseSyntax:
                    return VisitExpression(whereClauseSyntax.Condition, state);
                case IfStatementSyntax ifStatementSyntax:
                    return VisitIf(ifStatementSyntax, state);
                case ElseClauseSyntax elseClauseSyntax:
                    return VisitNode(elseClauseSyntax.Statement, state);
                case SwitchStatementSyntax switchStatementSyntax:
                    return VisitSwitch(switchStatementSyntax, state);
                case SwitchSectionSyntax switchSectionSyntax:
                    return VisitStatements(switchSectionSyntax.Statements, state, new VariableState(node, VariableTaint.Unset));
            }

            foreach (var n in node.ChildNodes())
            {
                VisitNode(n, state);
            }

            var isBlockStatement = node is ForStatementSyntax ||
                                   node is UsingStatementSyntax;

            if (!isBlockStatement)
            {
#if DEBUG
                //throw new Exception("Unsupported statement " + node.GetType() + " (" + node + ")");
                Logger.Log("Unsupported statement " + node.GetType() + " (" + node + ")");
#endif
            }

            return new VariableState(node, VariableTaint.Unknown);
        }

        private VariableState VisitPropertyDeclaration(PropertyDeclarationSyntax propertyDeclarationSyntax, ExecutionState state)
        {
            if (propertyDeclarationSyntax.ExpressionBody != null)
                return VisitNode(propertyDeclarationSyntax.ExpressionBody, state);

            foreach (var accessor in propertyDeclarationSyntax.AccessorList.Accessors)
            {
                if (accessor.Body != null)
                    VisitBlock(accessor.Body, state);
            }

            return new VariableState(propertyDeclarationSyntax, VariableTaint.Unknown);
        }

        private VariableState VisitFromClause(FromClauseSyntax fromClauseSyntax, ExecutionState state)
        {
            var fromClauseState = VisitExpression(fromClauseSyntax.Expression, state);
            var fromSymbol      = SyntaxNodeHelper.GetSymbol(fromClauseSyntax.Expression, state.AnalysisContext.SemanticModel);
            if (fromSymbol != null)
            {
                switch (fromSymbol)
                {
                    case IPropertySymbol propertyFromSymbol when propertyFromSymbol.Type.IsTaintType(ProjectConfiguration.Behavior):
                    case IFieldSymbol fieldFromSymbol when fieldFromSymbol.Type.IsTaintType(ProjectConfiguration.Behavior):
                        return new VariableState(fromClauseSyntax, VariableTaint.Tainted);
                }
            }

            return fromClauseState;
        }

        private VariableState VisitSwitch(SwitchStatementSyntax switchStatementSyntax, ExecutionState state)
        {
            var exprVarState = VisitExpression(switchStatementSyntax.Expression, state);
            if (switchStatementSyntax.Sections.Count <= 0)
                return exprVarState;

            var firstCaseState  = new ExecutionState(state);
            var sectionVarState = VisitNode(switchStatementSyntax.Sections[0], firstCaseState);
            exprVarState.MergeTaint(sectionVarState.Taint);

            for (var i = 1; i < switchStatementSyntax.Sections.Count; i++)
            {
                var section   = switchStatementSyntax.Sections[i];
                var caseState = new ExecutionState(state);
                sectionVarState = VisitNode(section, caseState);
                exprVarState.MergeTaint(sectionVarState.Taint);
                firstCaseState.Merge(caseState);
            }

            if (switchStatementSyntax.Sections.Any(section => section.Labels.Any(label => label.Kind() == SyntaxKind.DefaultSwitchLabel)))
                state.Replace(firstCaseState);
            else
                state.Merge(firstCaseState);

            return exprVarState;
        }

        private VariableState VisitIf(IfStatementSyntax ifStatementSyntax, ExecutionState state)
        {
            var condition = VisitExpression(ifStatementSyntax.Condition, state);

            var ifState     = new ExecutionState(state);
            var ifStatement = VisitNode(ifStatementSyntax.Statement, ifState);
            condition.MergeTaint(ifStatement.Taint);

            if (ifStatementSyntax.Else != null)
            {
                var elseState     = new ExecutionState(state);
                var elseStatement = VisitNode(ifStatementSyntax.Else, elseState);
                condition.MergeTaint(elseStatement.Taint);

                var @else = ifStatementSyntax.Else;
                while (@else?.Statement != null && @else.Statement is IfStatementSyntax elseIf)
                {
                    @else = elseIf.Else;
                }

                if (@else != null)
                {
                    ifState.Merge(elseState);
                    state.Replace(ifState);
                    return condition;
                }
                else
                {
                    state.Merge(elseState);
                }
            }

            state.Merge(ifState);
            return condition;
        }

        /// <summary>
        /// Unwrap
        /// </summary>
        /// <param name="declaration"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitLocalDeclaration(LocalDeclarationStatementSyntax declaration, ExecutionState state)
        {
            return VisitVariableDeclaration(declaration.Declaration, state);
        }

        /// <summary>
        /// Evaluate expression that contains a list of assignment.
        /// </summary>
        /// <param name="declaration"></param>
        /// <param name="state"></param>
        private VariableState VisitVariableDeclaration(VariableDeclarationSyntax declaration, ExecutionState state)
        {
            var lastState = new VariableState(declaration, VariableTaint.Unknown);

            foreach (var variable in declaration.Variables)
            {
                VariableState varState;
                if (variable.Initializer != null)
                {
                    varState = VisitExpression(variable.Initializer.Value, state);
                    var type = state.AnalysisContext.SemanticModel.GetTypeInfo(variable.Initializer.Value);

                    if (type.ConvertedType != null && (type.ConvertedType.IsType("System.String") || type.ConvertedType.IsValueType))
                    {
                        var copy = new VariableState(varState.Node, varState.Taint, varState.Value);
                        foreach (var property in varState.PropertyStates)
                        {
                            copy.AddProperty(property.Key, property.Value);
                        }

                        varState = copy;
                    }
                }
                else
                {
                    varState = new VariableState(variable, VariableTaint.Constant);
                }

                state.AddNewValue(ResolveIdentifier(variable.Identifier), varState);
                lastState = varState;
            }

            return lastState;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="syntaxToken"></param>
        /// <returns></returns>
        private string ResolveIdentifier(SyntaxToken syntaxToken)
        {
            return syntaxToken.Text;
        }

        private VariableState VisitExpression(ExpressionSyntax expression, ExecutionState state)
        {
            switch (expression)
            {
                case ParenthesizedExpressionSyntax parenthesizedExpressionSyntax:
                    return VisitExpression(parenthesizedExpressionSyntax.Expression, state);
                case InvocationExpressionSyntax invocationExpressionSyntax:
                    return VisitMethodInvocation(invocationExpressionSyntax, state);
                case ObjectCreationExpressionSyntax objectCreationExpressionSyntax:
                    return VisitObjectCreation(objectCreationExpressionSyntax, state);
                case LiteralExpressionSyntax literalExpressionSyntax:
                    return new VariableState(literalExpressionSyntax, VariableTaint.Constant, literalExpressionSyntax.Token.Value);
                case IdentifierNameSyntax identifierNameSyntax:
                    return VisitIdentifierName(identifierNameSyntax, state);
                case BinaryExpressionSyntax binaryExpressionSyntax:
                {
                    switch (binaryExpressionSyntax.Kind())
                    {
                        case SyntaxKind.AsExpression:
                        case SyntaxKind.IsExpression:
                            return VisitNode(binaryExpressionSyntax.Left, state);
                    }

                    return VisitBinaryExpression(binaryExpressionSyntax, binaryExpressionSyntax.Left, binaryExpressionSyntax.Right, state);
                }
                case AssignmentExpressionSyntax assignmentExpressionSyntax:
                    if (assignmentExpressionSyntax.Kind() != SyntaxKind.SimpleAssignmentExpression)
                    {
                        var left = VisitExpression(assignmentExpressionSyntax.Left, state);
                        var assignmentState = VisitAssignment(assignmentExpressionSyntax, state);
                        left.MergeTaint(assignmentState.Taint);
                        return left;
                    }
                    else
                    {
                        var assignmentState = VisitAssignment(assignmentExpressionSyntax, state);
                        return MergeVariableState(assignmentExpressionSyntax.Left, assignmentState, state);
                    }

                case MemberAccessExpressionSyntax memberAccessExpressionSyntax:
                    return VisitMemberAccessExpression(memberAccessExpressionSyntax, state);
                case ElementAccessExpressionSyntax elementAccessExpressionSyntax:
                    return VisitElementAccess(elementAccessExpressionSyntax, elementAccessExpressionSyntax.ArgumentList, state);
                case ArrayCreationExpressionSyntax arrayCreationExpressionSyntax:
                    return VisitArrayCreation(arrayCreationExpressionSyntax, arrayCreationExpressionSyntax.Initializer, state);
                case ImplicitArrayCreationExpressionSyntax implicitArrayCreationExpressionSyntax:
                    return VisitArrayCreation(implicitArrayCreationExpressionSyntax, implicitArrayCreationExpressionSyntax.Initializer, state);
                case TypeOfExpressionSyntax typeOfExpressionSyntax:
                    return new VariableState(typeOfExpressionSyntax, VariableTaint.Safe);
                case ConditionalExpressionSyntax conditionalExpressionSyntax:
                {
                    VisitExpression(conditionalExpressionSyntax.Condition, state);
                    var finalState = new VariableState(conditionalExpressionSyntax, VariableTaint.Unset);

                    var whenTrueState = VisitExpression(conditionalExpressionSyntax.WhenTrue, state);
                    finalState.MergeTaint(whenTrueState.Taint);
                    var whenFalseState = VisitExpression(conditionalExpressionSyntax.WhenFalse, state);
                    finalState.MergeTaint(whenFalseState.Taint);

                    return finalState;
                }
                case CheckedExpressionSyntax checkedExpressionSyntax:
                    return VisitExpression(checkedExpressionSyntax.Expression, state);
                case QueryExpressionSyntax queryExpressionSyntax:
                {
                    var finalState = new VariableState(queryExpressionSyntax, VariableTaint.Unset);
                    var fromState = VisitNode(queryExpressionSyntax.FromClause, state);
                    finalState.MergeTaint(fromState.Taint);
                    var bodyState = VisitNode(queryExpressionSyntax.Body, state);
                    finalState.MergeTaint(bodyState.Taint);
                    return finalState;
                }
                case InterpolatedStringExpressionSyntax interpolatedStringExpressionSyntax:
                    return VisitInterpolatedString(interpolatedStringExpressionSyntax, state);
                case CastExpressionSyntax castExpressionSyntax:
                    return VisitExpression(castExpressionSyntax.Expression, state);
                case DefaultExpressionSyntax defaultExpressionSyntax:
                    var value = state.AnalysisContext.SemanticModel.GetConstantValue(defaultExpressionSyntax);
                    return new VariableState(defaultExpressionSyntax, VariableTaint.Constant, value.HasValue ? value.Value : null);
                case PrefixUnaryExpressionSyntax prefixUnaryExpressionSyntax:
                    return VisitExpression(prefixUnaryExpressionSyntax.Operand, state);
            }
#if DEBUG
            Logger.Log("Unsupported expression " + expression.GetType() + " (" + expression + ")");
#endif
            return new VariableState(expression, VariableTaint.Unknown);
        }

        private VariableState VisitInterpolatedString(InterpolatedStringExpressionSyntax interpolatedString,
                                                      ExecutionState                     state)
        {
            var varState = new VariableState(interpolatedString, VariableTaint.Constant);

            foreach (var content in interpolatedString.Contents)
            {
                if (content is InterpolatedStringTextSyntax)
                {
                    varState.MergeTaint(VariableTaint.Constant);
                }

                if (!(content is InterpolationSyntax interpolation))
                    continue;

                var expressionState = VisitExpression(interpolation.Expression, state);
                varState.MergeTaint(expressionState.Taint);
            }

            return varState;
        }

        private VariableState VisitElementAccess(ElementAccessExpressionSyntax elementAccess,
                                                 BracketedArgumentListSyntax   argumentList,
                                                 ExecutionState                state)
        {
            var finalState = new VariableState(elementAccess, VariableTaint.Unset);

            foreach (var argument in argumentList.Arguments)
            {
                finalState.MergeTaint(VisitExpression(argument.Expression, state).Taint);
            }

            finalState.MergeTaint(VisitExpression(elementAccess.Expression, state).Taint);

            var taintSourceState = CheckIfTaintSource(elementAccess, state);
            if (taintSourceState != null)
                finalState.MergeTaint(taintSourceState.Taint);

            return finalState;
        }

        private VariableState VisitExpressionStatement(ExpressionStatementSyntax node, ExecutionState state)
        {
            return VisitExpression(node.Expression, state); //Simply unwrap the expression
        }

        private VariableState VisitMethodInvocation(InvocationExpressionSyntax node, ExecutionState state)
        {
            VariableState memberVariableState = null;
            if (node.Expression is MemberAccessExpressionSyntax memberAccessExpression)
            {
                memberVariableState = VisitExpression(memberAccessExpression.Expression, state);
            }

            return VisitInvocationAndCreation(node, node.ArgumentList, state, memberVariableState?.Taint, memberVariableState);
        }

        private VariableState VisitObjectCreation(ObjectCreationExpressionSyntax node, ExecutionState state)
        {
            VariableState finalState = VisitInvocationAndCreation(node, node.ArgumentList, state);
            foreach (SyntaxNode child in node.DescendantNodes())
            {
                if (child is AssignmentExpressionSyntax assignmentExpressionSyntax)
                {
                    var assignmentState = VisitAssignment(assignmentExpressionSyntax, state);
                    MergeVariableState(assignmentExpressionSyntax.Left, assignmentState, state, finalState);
                }
                else
                {
#if DEBUG
                    Logger.Log(child.GetText().ToString().Trim() + " -> " + finalState);
#endif
                }
            }

            return finalState;
        }

        private VariableState VisitArrayCreation(SyntaxNode node, InitializerExpressionSyntax arrayInit, ExecutionState state)
        {
            var finalState = new VariableState(node, VariableTaint.Safe);
            if (arrayInit == null)
                return finalState;

            foreach (var ex in arrayInit.Expressions)
            {
                var exprState = VisitExpression(ex, state);
                finalState.MergeTaint(exprState.Taint);
            }

            return finalState;
        }

        private string GetMethodName(ExpressionSyntax node)
        {
            string methodName;
            switch (node)
            {
                case ObjectCreationExpressionSyntax objectCreationExpressionSyntax:
                    methodName = $"{objectCreationExpressionSyntax.NewKeyword} {objectCreationExpressionSyntax.Type}";
                    break;
                case InvocationExpressionSyntax invocationExpressionSyntax:
                    methodName = invocationExpressionSyntax.Expression.ToString();
                    break;
                default:
                    methodName = node.ToString();
                    break;
            }

            return methodName;
        }

        private IReadOnlyDictionary<int, PostCondition> GetPostConditions(MethodBehavior behavior, bool isExtensionMethod, ArgumentListSyntax argList, ExecutionState state)
        {
            if (behavior.Conditions == null)
                return behavior.PostConditions;

            foreach (var condition in behavior.Conditions)
            {
                if (CheckPrecondition(condition.If, isExtensionMethod, argList, state))
                    return condition.Then;
            }

            return behavior.PostConditions;
        }

        private bool CheckPrecondition(IReadOnlyDictionary<int, object> condition, bool isExtensionMethod, ArgumentListSyntax argList, ExecutionState state)
        {
            for (var i = 0; i < argList?.Arguments.Count; i++)
            {
                var argument            = argList.Arguments[i];
                var adjustedArgumentIdx = isExtensionMethod ? i + 1 : i;

                if (!condition.TryGetValue(adjustedArgumentIdx, out var preconditionArgumentValue))
                {
                    continue;
                }

                var calculatedArgumentValue = state.AnalysisContext.SemanticModel.GetConstantValue(argument.Expression);
                if (calculatedArgumentValue.HasValue && calculatedArgumentValue.Value.Equals(preconditionArgumentValue))
                {
                    continue;
                }

                return false;
            }

            return true;
        }

        /// <summary>
        /// Logic for each method invocation (including constructor)
        /// The argument list is required because <code>InvocationExpressionSyntax</code> and 
        /// <code>ObjectCreationExpressionSyntax</code> do not share a common interface.
        /// </summary>
        private VariableState VisitInvocationAndCreation(ExpressionSyntax   node,
                                                         ArgumentListSyntax argList,
                                                         ExecutionState     state,
                                                         VariableTaint?     initialTaint = null,
                                                         VariableState      memberVariableState = null)
        {
            var symbol = state.GetSymbol(node);
            if (symbol == null)
                return new VariableState(node, initialTaint ?? VariableTaint.Unknown);

            var  methodSymbol      = symbol as IMethodSymbol;
            bool isExtensionMethod = methodSymbol?.ReducedFrom != null;
            var  behavior          = symbol.GetMethodBehavior(ProjectConfiguration.Behavior);
            IReadOnlyDictionary<int, PostCondition> postConditions = null;
            if (behavior != null)
                postConditions = GetPostConditions(behavior, isExtensionMethod, argList, state);

            PostCondition returnPostCondition = null;
            postConditions?.TryGetValue(-1, out returnPostCondition);

            VariableState returnState = initialTaint != null && !symbol.IsStatic
                                            ? new VariableState(node, initialTaint.Value)
                                            : new VariableState(node, argList?.Arguments.Count > 0 && behavior != null
                                                                          ? VariableTaint.Unset
                                                                          : VariableTaint.Unknown);

            var argCount       = argList?.Arguments.Count;
            var argumentStates = argCount.HasValue &&
                                 argCount.Value > 0 &&
                                 (postConditions?.Any(c => c.Key != -1 && (c.Value.Taint != 0ul || c.Value.TaintFromArguments.Any())) == true ||
                                  methodSymbol != null && methodSymbol.Parameters.Any(x => x.RefKind != RefKind.None))
                                     ? new VariableState[argCount.Value]
                                     : null;

            for (var i = 0; i < argList?.Arguments.Count; i++)
            {
                var argument      = argList.Arguments[i];
                var argumentState = VisitExpression(argument.Expression, state);
                if (argumentStates != null)
                    argumentStates[i] = argumentState;

#if DEBUG
                Logger.Log(symbol.ContainingType + "." + symbol.Name + " -> " + argumentState);
#endif

                var adjustedArgumentIdx = isExtensionMethod ? i + 1 : i;

                if (behavior != null)
                {
                    if ((argumentState.Taint & (ProjectConfiguration.AuditMode
                                                    ? VariableTaint.Tainted | VariableTaint.Unknown
                                                    : VariableTaint.Tainted)) != 0)
                    {
                        //If the current parameter can be injected.
                        if (behavior.InjectableArguments.TryGetValue(adjustedArgumentIdx, out var injectableArgument) &&
                            (injectableArgument.RequiredTaintBits & (ulong)argumentState.Taint) != injectableArgument.RequiredTaintBits)
                        {
                            var newRule    = LocaleUtil.GetDescriptor(injectableArgument.Locale);
                            var diagnostic = Diagnostic.Create(newRule, argument.Expression.GetLocation(), GetMethodName(node), (i + 1).ToNthString());
                            state.AnalysisContext.ReportDiagnostic(diagnostic);
                        }
                    }
                    else if (argumentState.Taint == VariableTaint.Constant)
                    {
                        if (behavior.InjectableArguments.TryGetValue(adjustedArgumentIdx, out var injectableArgument) &&
                            injectableArgument.Not && (injectableArgument.RequiredTaintBits & (ulong)argumentState.Taint) != 0ul)
                        {
                            var newRule    = LocaleUtil.GetDescriptor(injectableArgument.Locale);
                            var diagnostic = Diagnostic.Create(newRule, argument.Expression.GetLocation(), GetMethodName(node), (i + 1).ToNthString());
                            state.AnalysisContext.ReportDiagnostic(diagnostic);
                        }
                    }
                }

                var argumentToSearch = adjustedArgumentIdx;
                if (methodSymbol != null                           &&
                    i            >= methodSymbol.Parameters.Length &&
                    methodSymbol.Parameters[methodSymbol.Parameters.Length - 1].IsParams)
                {
                    argumentToSearch = isExtensionMethod ? methodSymbol.Parameters.Length : methodSymbol.Parameters.Length - 1;
                }

                if (returnPostCondition == null ||
                    returnPostCondition.TaintFromArguments.Contains(argumentToSearch))
                {
                    returnState.MergeTaint(argumentState.Taint);
                }

                //TODO: taint all objects passed as arguments
                //if (argument.Expression is IdentifierNameSyntax identifierNameSyntax)
                //{
                //    var argumentType = state.AnalysisContext.SemanticModel.GetTypeInfo(argument.Expression).Type;
                //    if (argumentType.IsReferenceType &&
                //        argumentType.IsType("System.String")) // string is immutable
                //    {
                //        state.MergeValue(ResolveIdentifier(identifierNameSyntax.Identifier),
                //                         argumentState.Merge(new VariableState(argument, VariableTaint.Unknown)));
                //    }
                //}
            }

            if (returnPostCondition != null)
            {
                returnState.ApplyTaint(returnPostCondition.Taint);
            }

            if (argumentStates != null)
            {
                for (var i = 0; i < argList.Arguments.Count; i++)
                {
                    var adjustedPostConditionIdx = isExtensionMethod ? i + 1 : i;

                    if (postConditions != null && postConditions.TryGetValue(adjustedPostConditionIdx, out var postCondition) )
                    {
                        foreach (var argIdx in postCondition.TaintFromArguments)
                        {
                            var adjustedArgumentIdx = isExtensionMethod ? argIdx + 1 : argIdx;
                            argumentStates[adjustedPostConditionIdx].MergeTaint(argumentStates[adjustedArgumentIdx].Taint);
                        }

                        argumentStates[adjustedPostConditionIdx].ApplyTaint(postCondition.Taint);
                    }
                    else if (methodSymbol != null)
                    {
                        if (i >= methodSymbol.Parameters.Length)
                        {
                            if (!methodSymbol.Parameters[methodSymbol.Parameters.Length - 1].IsParams)
                                throw new IndexOutOfRangeException();
                        }
                        else if (methodSymbol.Parameters[i].RefKind != RefKind.None)
                        {
                            argumentStates[i].MergeTaint(returnState.Taint);
                        }
                    }
                }
            }

            if (memberVariableState != null &&
                methodSymbol != null &&
                methodSymbol.ReturnsVoid &&
                !methodSymbol.IsStatic &&
                methodSymbol.Parameters.All(x => x.RefKind == RefKind.None))
            {
                memberVariableState.MergeTaint(returnState.Taint);
            }

            //Additional analysis by extension
            foreach (var ext in Extensions)
            {
                ext.VisitInvocationAndCreation(node, argList, state);
            }

            return returnState;
        }

        private VariableState VisitAssignment(AssignmentExpressionSyntax node, ExecutionState state)
        {
            var            leftSymbol = state.GetSymbol(node.Left);
            MethodBehavior behavior   = null;
            if (leftSymbol != null)
                behavior = leftSymbol.GetMethodBehavior(ProjectConfiguration.Behavior);

            var variableState = VisitExpression(node.Right, state);

            //Additional analysis by extension
            foreach (var ext in Extensions)
            {
                ext.VisitAssignment(node, state, behavior, leftSymbol, variableState);
            }

            //if (leftSymbol != null)
            //{
            //    var rightTypeSymbol = state.AnalysisContext.SemanticModel.GetTypeInfo(node.Right).Type;
            //    if (rightTypeSymbol == null)
            //        return new VariableState(node.Right, VariableTaint.Unknown);

            //    var leftTypeSymbol = state.AnalysisContext.SemanticModel.GetTypeInfo(node.Left).Type;
            //    if (!state.AnalysisContext.SemanticModel.Compilation.ClassifyConversion(rightTypeSymbol, leftTypeSymbol).IsImplicit)
            //        return new VariableState(node.Right, VariableTaint.Unknown);
            //}

            if (variableState.Taint != VariableTaint.Constant &&
                behavior != null &&
                // compare if all required sanitization bits are set
                ((ulong)(variableState.Taint & VariableTaint.Safe) & behavior.InjectableField.RequiredTaintBits) != behavior.InjectableField.RequiredTaintBits &&
                (variableState.Taint & (ProjectConfiguration.AuditMode ? VariableTaint.Tainted | VariableTaint.Unknown : VariableTaint.Tainted)) != 0)
            {
                var newRule    = LocaleUtil.GetDescriptor(behavior.InjectableField.Locale, "title_assignment");
                var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                state.AnalysisContext.ReportDiagnostic(diagnostic);
            }

            //TODO: taint the variable being assigned.

            return variableState;
        }

        private VariableState GetVariableState(ExpressionSyntax expression, ExecutionState state)
        {
            if (!(expression is MemberAccessExpressionSyntax memberAccessExpressionSyntax))
            {
                VariableState result;
                if (!(expression is IdentifierNameSyntax identifierNameSyntax))
                {
                    //TODO: How to correctly handle "this" case
                    if (expression is ThisExpressionSyntax && state.VariableStates.TryGetValue("this", out result))
                        return result;

                    return null;
                }

                var identifier = ResolveIdentifier(identifierNameSyntax.Identifier);
                if (state.VariableStates.TryGetValue(identifier, out result))
                    return result;

                return null;
            }

            var variableState = GetVariableState(memberAccessExpressionSyntax.Expression, state);
            if (variableState == null)
                return null;

            var stateIdentifier = ResolveIdentifier(memberAccessExpressionSyntax.Name.Identifier);
            //make sure this identifier exists
            if (variableState.PropertyStates.TryGetValue(stateIdentifier, out var propertyState))
                return propertyState;

            return null;
        }

        private VariableState MergeVariableState(ExpressionSyntax expression,
                                                 VariableState    newVariableState,
                                                 ExecutionState   state,
                                                 VariableState    currentScope = null)
        {
            var variableStateToMerge = newVariableState ?? new VariableState(expression, VariableTaint.Unset);
            if (!(expression is MemberAccessExpressionSyntax memberAccessExpressionSyntax))
            {
                var identifier = "";
                if (expression is IdentifierNameSyntax identifierNameSyntax)
                    identifier = ResolveIdentifier(identifierNameSyntax.Identifier);
                else if (expression is ThisExpressionSyntax)
                    identifier = "this";

                if (currentScope != null)
                {
                    currentScope.AddOrMergeProperty(identifier, variableStateToMerge);
                    return currentScope.PropertyStates[identifier];
                }

                state.AddOrUpdateValue(identifier, variableStateToMerge);
                return state.VariableStates[identifier];
            }

            var variableState = MergeVariableState(memberAccessExpressionSyntax.Expression, null, state, currentScope);

            var stateIdentifier = ResolveIdentifier(memberAccessExpressionSyntax.Name.Identifier);
            variableState.AddOrMergeProperty(stateIdentifier, variableStateToMerge);
            return variableState.PropertyStates[stateIdentifier];
        }

        private VariableState VisitIdentifierName(ExpressionSyntax expression, ExecutionState state)
        {
            var varState = GetVariableState(expression, state);
            if (varState != null)
                return varState;

            var taintSourceState = CheckIfTaintSource(expression, state);
            if (taintSourceState != null)
                return taintSourceState;

            return ResolveVariableState(expression, state);
        }

        private VariableState VisitMemberAccessExpression(MemberAccessExpressionSyntax expression, ExecutionState state)
        {
            var varState = VisitIdentifierName(expression, state);

            if (varState.Taint == VariableTaint.Constant || expression.Expression == null)
            {
                return varState;
            }

            var expressionState = VisitExpression(expression.Expression, state);
            varState.MergeTaint(expressionState.Taint);

            return varState;
        }

        private VariableState CheckIfTaintSource(ExpressionSyntax expression, ExecutionState state)
        {
            var symbol   = state.GetSymbol(expression);
            var behavior = symbol?.GetMethodBehavior(ProjectConfiguration.Behavior);
            if (behavior != null && behavior.PostConditions.TryGetValue(-1, out var taint))
            {
                return new VariableState(expression, (VariableTaint)taint.Taint);
            }

            return null;
        }

        private VariableState ResolveVariableState(ExpressionSyntax expression,
                                                   ExecutionState state,
                                                   SemanticModel semanticModel = null,
                                                   HashSet<ExpressionSyntax> visited = null)
        {
            semanticModel = semanticModel ?? state.AnalysisContext.SemanticModel;
            var symbol    = semanticModel.GetSymbolInfo(expression).Symbol;
            switch (symbol)
            {
                case null:
                    return new VariableState(expression, VariableTaint.Unknown);
                case IFieldSymbol field:
                    if (field.IsConst)
                        return new VariableState(expression, VariableTaint.Constant);

                    if (!field.IsReadOnly)
                        return new VariableState(expression, VariableTaint.Unknown);

                    if (ProjectConfiguration.ConstantFields.Contains(field.GetTypeName()))
                    {
                        return new VariableState(expression, VariableTaint.Constant);
                    }

                    return new VariableState(expression, VariableTaint.Unknown);
                case IPropertySymbol prop:
                    if (prop.IsVirtual || prop.IsOverride || prop.IsAbstract)
                        return new VariableState(expression, VariableTaint.Unknown);

                    // TODO: Use public API
                    var syntaxNodeProperty = prop.GetMethod.GetType().GetTypeInfo().BaseType.GetTypeInfo().GetDeclaredProperty("BodySyntax");
                    if (syntaxNodeProperty == null)
                        return new VariableState(expression, VariableTaint.Unknown);

                    var syntaxNode = (CSharpSyntaxNode)syntaxNodeProperty.GetValue(prop.GetMethod);
                    if (syntaxNode == null)
                        return new VariableState(expression, VariableTaint.Unknown);

                    var possiblyOtherSemanticModel = semanticModel.Compilation.GetSemanticModel(syntaxNode.SyntaxTree);
                    if (syntaxNode is ArrowExpressionClauseSyntax arrowExpressionClauseSyntax)
                    {
                        if (possiblyOtherSemanticModel.GetConstantValue(arrowExpressionClauseSyntax.Expression).HasValue)
                            return new VariableState(expression, VariableTaint.Constant);

                        if (visited == null)
                            visited = new HashSet<ExpressionSyntax>();
                        else if (!visited.Add(arrowExpressionClauseSyntax.Expression))
                            return new VariableState(expression, VariableTaint.Unknown);

                        return ResolveVariableState(arrowExpressionClauseSyntax.Expression,
                                                    null,
                                                    possiblyOtherSemanticModel,
                                                    visited);
                    }

                    if (!(syntaxNode is StatementSyntax statementSyntax))
                        return new VariableState(expression, VariableTaint.Unknown);

                    var flow = possiblyOtherSemanticModel.AnalyzeControlFlow(statementSyntax);

                    if (flow.Succeeded && AllReturnConstant(flow.ExitPoints, possiblyOtherSemanticModel, visited))
                    {
                        return new VariableState(expression, VariableTaint.Constant);
                    }

                    return new VariableState(expression, VariableTaint.Unknown);
            }

            return new VariableState(expression, VariableTaint.Unknown);
        }

        private bool AllReturnConstant(ImmutableArray<SyntaxNode> exitPoints, SemanticModel semanticModel, HashSet<ExpressionSyntax> visited)
        {
            foreach (var exitPoint in exitPoints)
            {
                if (!(exitPoint is ReturnStatementSyntax returnStatementSyntax))
                    return false;

                if (semanticModel.GetConstantValue(returnStatementSyntax.Expression).HasValue)
                {
                    continue;
                }

                if (visited == null)
                    visited = new HashSet<ExpressionSyntax>();
                else if (!visited.Add(returnStatementSyntax.Expression))
                    return false;

                if (ResolveVariableState(returnStatementSyntax.Expression, null, semanticModel, visited).Taint != VariableTaint.Constant)
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Combine the state of the two operands. Binary expression include concatenation.
        /// </summary>
        /// <param name="expression"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitBinaryExpression(ExpressionSyntax expression,
                                                    ExpressionSyntax leftExpression,
                                                    ExpressionSyntax rightExpression,
                                                    ExecutionState state)
        {
            var result = new VariableState(expression, VariableTaint.Unset);
            var left = VisitExpression(leftExpression, state);
            result.MergeTaint(left.Taint);
            var right = VisitExpression(rightExpression, state);
            result.MergeTaint(right.Taint);
            return result;
        }
    }
}
